#!/usr/bin/env bash
#
# lib/hcl.sh — HCLA blob parsing and freshness-binding helpers for solpbc.
#
# This is the custom logic that lives beyond snpguest: it parses the Azure
# HCLA (HCL attestation) blob read from the vTPM, verifies that the embedded
# AMD SEV-SNP report commits to the HCL runtime data, proves that the live
# vTPM Attestation Key is the one bound by that AMD report, and builds the
# qualifying-data hash that ties a fresh TPM quote to a nonce + guest key.
#
# Trust pivot (see docs/azure-sev-snp-attestation-brief.pdf, pp. 2-3):
#   AMD report.report_data == H(HCL runtime data)
#   HCL runtime data carries HCLAkPub (the vTPM AK public key)
#   => the AK is trusted because it is inside AMD-bound runtime data,
#      NOT because Azure issued a cert for it.
#
# HCLA blob layout (AMD SEV-SNP):
#   offset 0     : 32-byte Azure HCLA header  (sig "HCLA", version, ...)
#   offset 32    : 1184-byte AMD SEV-SNP hardware report
#   offset 1216+ : HCL runtime data — JSON claims (incl. HCLAkPub JWK)
#
# SNP report field offsets used here:
#   offset 80    : report_data (64 bytes); for the SHA-256 hash type the
#                  first 32 bytes are H(runtime data) and the rest are zero.
#
# Pure-shell deps only (all in the runtime container): openssl, jq, xxd,
# base64, dd, grep, awk. No python, no extra crates.

set -euo pipefail

# HCLA constants
HCL_SIG="HCLA"            # 0x414c4348, little-endian -> ASCII "HCLA"
HCL_REPORT_OFFSET=32      # AMD report starts here
HCL_REPORT_SIZE=1184      # AMD SEV-SNP report length
HCL_RUNTIME_OFFSET=1216   # 32 + 1184; JSON runtime data at/after here
SNP_REPORT_DATA_OFFSET=80 # report_data within the AMD report
SNP_REPORT_DATA_SIZE=64

# Default key-id of the vTPM AK inside the HCL runtime claims.
HCL_AKPUB_KID="${HCL_AKPUB_KID:-HCLAkPub}"

# --- low-level helpers -------------------------------------------------------

# Read a little-endian uint32 from FILE at byte OFFSET, print as decimal.
_le32() {
  local file="$1" off="$2" b
  b=$(dd if="$file" bs=1 skip="$off" count=4 status=none | xxd -p)
  # bytes are b0 b1 b2 b3 (LE); reassemble as b3 b2 b1 b0
  printf '%d' "0x${b:6:2}${b:4:2}${b:2:2}${b:0:2}"
}

# base64url -> raw bytes (stdout). Handles missing padding and -_ alphabet.
_b64url_decode() {
  local s="$1"
  s=${s//-/+}
  s=${s//_//}
  local pad=$(( (4 - ${#s} % 4) % 4 )) i
  for ((i = 0; i < pad; i++)); do s+="="; done
  printf '%s' "$s" | base64 -d
}

# Normalize a hex modulus: uppercase, strip leading "00" sign bytes if present.
_norm_modulus() {
  local h
  h=$(printf '%s' "$1" | tr 'a-f' 'A-F' | tr -d '\n[:space:]')
  while [[ "$h" == 00* && ${#h} -gt 2 ]]; do h=${h:2}; done
  printf '%s' "$h"
}

# --- HCLA parsing ------------------------------------------------------------

# Verify the 32-byte HCLA header. Echoes a one-line summary; returns non-zero
# if the signature / version / request_type are not the expected AMD-SNP shape.
hcl_verify_header() {
  local blob="$1" sig version req_type
  sig=$(dd if="$blob" bs=1 count=4 status=none)
  version=$(_le32 "$blob" 4)
  req_type=$(_le32 "$blob" 12)
  if [[ "$sig" != "$HCL_SIG" ]]; then
    echo "HCLA signature mismatch: got '${sig}', expected '${HCL_SIG}'" >&2
    return 1
  fi
  # Observed on a live DCasv5 CVM: header version is 1 (the research brief said
  # 2). Accept the known versions and key on the request_type, which is the
  # field that actually distinguishes an AMD-SNP report request.
  if { [[ "$version" -ne 1 && "$version" -ne 2 ]]; } || [[ "$req_type" -ne 2 ]]; then
    echo "HCLA header unexpected: version=${version} request_type=${req_type} (expected version 1 or 2, request_type 2)" >&2
    return 1
  fi
  echo "sig=${sig} version=${version} request_type=${req_type}"
}

# Print the embedded AMD report (1184 bytes) from the HCLA blob to stdout.
hcl_amd_report() {
  dd if="$1" bs=1 skip="$HCL_REPORT_OFFSET" count="$HCL_REPORT_SIZE" status=none
}

# Extract the HCL runtime-data JSON from the HCLA blob to stdout.
#
# JSON text contains no NUL bytes, and Azure NUL-pads the NV region, so the
# claims run from the first `{"` at/after the runtime offset up to the first
# NUL (or EOF). The caller validates the result by checking that its SHA-256
# equals the AMD report's report_data, which confirms the byte range exactly.
hcl_runtime_json() {
  local blob="$1" start nul_rel len total
  start=$(LC_ALL=C grep -aboP '\{"' "$blob" \
            | awk -F: -v min="$HCL_RUNTIME_OFFSET" '$1>=min{print $1; exit}')
  if [[ -z "$start" ]]; then
    echo "no JSON object found at/after offset ${HCL_RUNTIME_OFFSET}" >&2
    return 1
  fi
  nul_rel=$(dd if="$blob" bs=1 skip="$start" status=none \
              | LC_ALL=C grep -aboP '\x00' | awk -F: 'NR==1{print $1; exit}')
  if [[ -n "$nul_rel" ]]; then
    len="$nul_rel"
  else
    total=$(wc -c < "$blob")
    len=$(( total - start ))
  fi
  dd if="$blob" bs=1 skip="$start" count="$len" status=none
}

# --- binding verification ----------------------------------------------------

# Print the AMD report's report_data as hex (128 hex chars). Arg: AMD report file.
snp_report_data_hex() {
  dd if="$1" bs=1 skip="$SNP_REPORT_DATA_OFFSET" count="$SNP_REPORT_DATA_SIZE" \
    status=none | xxd -p -c"$SNP_REPORT_DATA_SIZE" | tr -d '\n'
}

# Verify report_data == H(runtime data). Args: AMD report file, runtime JSON file.
# Returns 0 and prints the matched hash on success.
hcl_verify_runtime_binding() {
  local report="$1" json="$2" rd rd_lo rd_hi jh
  rd=$(snp_report_data_hex "$report")
  rd_lo=${rd:0:64}    # first 32 bytes
  rd_hi=${rd:64:64}   # trailing 32 bytes (must be zero for SHA-256 hash type)
  jh=$(openssl dgst -sha256 -binary < "$json" | xxd -p -c32 | tr -d '\n')
  if [[ "$rd_lo" != "$jh" ]]; then
    echo "runtime-data binding FAILED: H(runtime)=${jh} != report_data[0..32]=${rd_lo}" >&2
    return 1
  fi
  if [[ "$rd_hi" != "0000000000000000000000000000000000000000000000000000000000000000" ]]; then
    echo "warning: report_data[32..64] not zero (hash type may not be SHA-256): ${rd_hi}" >&2
  fi
  echo "$jh"
}

# Print the RSA modulus of HCLAkPub from the runtime JSON (normalized hex).
# Arg: runtime JSON file.
hcl_akpub_modulus_hex() {
  local json="$1" n
  n=$(jq -r --arg kid "$HCL_AKPUB_KID" \
        '.keys[]? | select(.kid==$kid) | .n // empty' "$json")
  if [[ -z "$n" ]]; then
    echo "HCLAkPub (kid=${HCL_AKPUB_KID}) not found in runtime claims" >&2
    return 1
  fi
  _norm_modulus "$(_b64url_decode "$n" | xxd -p -c4096)"
}

# Print the RSA modulus of an AK public key PEM (normalized hex). Arg: PEM file.
tpm_akpub_modulus_hex() {
  local pem="$1" m
  m=$(openssl rsa -pubin -in "$pem" -modulus -noout 2>/dev/null | sed 's/^Modulus=//')
  if [[ -z "$m" ]]; then
    echo "could not read RSA modulus from ${pem}" >&2
    return 1
  fi
  _norm_modulus "$m"
}

# Confirm the live vTPM AK is the AMD-bound HCLAkPub by matching RSA moduli.
# Args: runtime JSON file, AK public PEM file.
hcl_verify_ak_binding() {
  local json="$1" pem="$2" a b
  a=$(hcl_akpub_modulus_hex "$json")
  b=$(tpm_akpub_modulus_hex "$pem")
  if [[ "$a" != "$b" ]]; then
    echo "AK binding FAILED: vTPM AK modulus does not match AMD-bound HCLAkPub" >&2
    return 1
  fi
  echo "matched (${#a} hex chars)"
}

# --- freshness binding -------------------------------------------------------

# Compute the quote qualifying-data hash that binds a fresh quote to a nonce
# and the guest's ephemeral public key:
#   H( DOMAIN || nonce_bytes || guest_pubkey_der [|| ctx] )
# Args: domain string, nonce (hex), guest pubkey DER file, [optional ctx file].
# Prints the hash as hex (64 chars).
hcl_binding_hash() {
  local domain="$1" nonce_hex="$2" pub_der="$3" ctx_file="${4:-}"
  {
    printf '%s' "$domain"
    printf '%s' "$nonce_hex" | xxd -r -p
    cat "$pub_der"
    if [[ -n "$ctx_file" && -f "$ctx_file" ]]; then cat "$ctx_file"; fi
  } | openssl dgst -sha256 -binary | xxd -p -c32 | tr -d '\n'
}
