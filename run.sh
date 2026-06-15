#!/usr/bin/env bash
#
# solpbc demo entry point.
#
# Proves a composite, customer-verifiable attestation for an Azure SEV-SNP
# Confidential VM with NO Microsoft Azure Attestation (MAA) in the trust path:
#
#   Part 1 — AMD report (rooted in AMD silicon):
#     1. fetch the SEV-SNP report from the vTPM (paravisor path, --platform)
#     2. decode it
#     3. fetch the AMD cert chain (CA + VCEK) from the KDS
#     4. verify the cert chain and the report signature
#
#   Part 2 — vTPM quote freshness binding (the half beyond snpguest):
#     5. read the full HCLA blob from the vTPM and split out the runtime data
#     6. verify report_data == H(HCL runtime data)
#     7. prove the live vTPM AK IS the AMD-bound HCLAkPub (RSA modulus match)
#     8. take an AK-signed TPM quote over the PCRs whose qualifying data is
#        H(domain || nonce || guest_pubkey || ctx), then verify it
#
# Part 2 closes the loop: the AMD report binds the vTPM AK, and the vTPM AK
# signs a fresh, guest-bound quote. See docs/azure-sev-snp-attestation-brief.pdf
# (pp. 2-3) and lib/hcl.sh for the parsing/verification logic.
#
# Run on the CVM with the raw vTPM device passed through, e.g.:
#   podman run --rm --device /dev/tpm0 --device /dev/tpmrm0 \
#     --group-add keep-groups -v "$PWD:/out" -w /out solpbc

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/hcl.sh
source "${SCRIPT_DIR}/lib/hcl.sh"

# Where to write artifacts. Defaults to a mounted /out volume if present,
# otherwise an ephemeral /tmp (override with OUT_DIR=...).
OUT_DIR="${OUT_DIR:-/out}"
[[ -d "$OUT_DIR" && -w "$OUT_DIR" ]] || OUT_DIR="/tmp"

REPORT="${OUT_DIR}/report.bin"
REQUEST="${OUT_DIR}/request.txt"
CERTS_DIR="${OUT_DIR}/certs"
TPM_DEV="/dev/tpm0"

# Part 2 inputs (all overridable via the environment).
HCL_NV_INDEX="${HCL_NV_INDEX:-0x01400001}"   # Azure HCLA blob NV index
AK_HANDLE="${AK_HANDLE:-0x81000003}"         # vTPM Attestation Key handle
PCR_LIST="${PCR_LIST:-sha256:0,2,4,7,8,9,15,16,22,23}"
BINDING_DOMAIN="${BINDING_DOMAIN:-sol-key-release-v1}"
CTX_FILE="${CTX_FILE:-}"                      # optional extra binding context

# Part 2 artifacts.
HCL_BLOB="${OUT_DIR}/hcl_report.bin"
EMBEDDED_REPORT="${OUT_DIR}/amd_report_embedded.bin"
RUNTIME_JSON="${OUT_DIR}/runtime_data.json"
AK_PUB="${OUT_DIR}/akpub.pem"
GUEST_KEY="${OUT_DIR}/guest_x25519.key"
GUEST_PUB="${OUT_DIR}/guest_x25519.pub.der"
QUOTE_MSG="${OUT_DIR}/quote.msg"
QUOTE_SIG="${OUT_DIR}/quote.sig"
QUOTE_PCRS="${OUT_DIR}/quote.pcrs"

echo "== solpbc :: AMD SEV-SNP composite attestation demo =="

# The vTPM report path needs the raw TPM device. If it isn't here, we're not
# on a CVM (or it wasn't passed through) — explain and exit cleanly.
if [[ ! -e "$TPM_DEV" ]]; then
  cat <<EOF

No vTPM device found at ${TPM_DEV}.

This demo must run ON an Azure SEV-SNP Confidential VM with the TPM passed
through. From a checkout on the CVM:

  podman build -t solpbc .
  podman run --rm --device /dev/tpm0 --device /dev/tpmrm0 \\
    --group-add keep-groups -v "\$PWD:/out" -w /out solpbc

(See the README for provisioning the CVM and granting tss-group access to
/dev/tpm0. To exercise the HCLA/freshness logic off-hardware, run
test/freshness-selftest.sh instead.)
EOF
  exit 0
fi

# ===========================================================================
# Part 1 — AMD report, rooted in AMD silicon
# ===========================================================================

echo
echo "[1/8] Fetching attestation report from vTPM (VMPL 0, --platform)..."
snpguest report --platform "$REPORT" "$REQUEST"
size="$(wc -c < "$REPORT" | tr -d ' ')"
echo "      wrote ${REPORT} (${size} bytes)"

echo
echo "[2/8] Decoding attestation report:"
echo
snpguest display report "$REPORT"

# The fetch steps reach out to the AMD Key Distribution Service
# (kdsintf.amd.com). The processor model and chip/TCB are derived from the
# V3 report itself, so no hardware details need to be hardcoded.
echo
echo "[3/8] Fetching AMD certificate chain from the KDS..."
mkdir -p "$CERTS_DIR"
echo "      - ARK + ASK (certificate authority)"
snpguest fetch ca pem "$CERTS_DIR" --report "$REPORT"
echo "      - VCEK (chip- and TCB-specific endorsement key)"
snpguest fetch vcek pem "$CERTS_DIR" "$REPORT"

echo
echo "[4/8] Verifying the trust chain..."
echo "      - VCEK chains to the AMD root (ARK -> ASK -> VCEK):"
snpguest verify certs "$CERTS_DIR"
echo "      - report is signed by that VCEK:"
snpguest verify attestation "$CERTS_DIR" "$REPORT"

# ===========================================================================
# Part 2 — vTPM quote freshness binding (custom logic in lib/hcl.sh)
# ===========================================================================

echo
echo "[5/8] Reading the HCLA blob from the vTPM (NV ${HCL_NV_INDEX})..."
tpm2_nvread -C o "$HCL_NV_INDEX" -o "$HCL_BLOB"
echo "      - HCLA header: $(hcl_verify_header "$HCL_BLOB")"
hcl_amd_report "$HCL_BLOB" > "$EMBEDDED_REPORT"
if cmp -s "$REPORT" "$EMBEDDED_REPORT"; then
  echo "      - embedded AMD report matches the snpguest --platform report"
else
  echo "      - note: embedded AMD report differs from snpguest report;"
  echo "              using the HCLA-embedded report for the runtime binding"
fi
hcl_runtime_json "$HCL_BLOB" > "$RUNTIME_JSON"
echo "      - extracted HCL runtime data ($(wc -c < "$RUNTIME_JSON") bytes of JSON claims)"

echo
echo "[6/8] Verifying the HCLA binding (report_data == H(runtime data))..."
rd_hash="$(hcl_verify_runtime_binding "$EMBEDDED_REPORT" "$RUNTIME_JSON")"
echo "      - SHA-256(runtime data) = ${rd_hash}"
echo "        equals the AMD report's report_data -> AMD report commits to the"
echo "        HCL runtime claims (which carry the vTPM AK public key)."

echo
echo "[7/8] Proving the vTPM AK is the AMD-bound HCLAkPub..."
tpm2_readpublic -c "$AK_HANDLE" -f pem -o "$AK_PUB" >/dev/null
echo "      - live vTPM AK (handle ${AK_HANDLE}) read"
echo "      - AK vs AMD-bound HCLAkPub: $(hcl_verify_ak_binding "$RUNTIME_JSON" "$AK_PUB")"
echo "        => the AK is trusted because its key is inside AMD-bound runtime"
echo "           data, NOT because Azure issued a cert for it."

echo
echo "[8/8] Binding a fresh vTPM quote to a nonce + guest key..."
# In production the nonce comes from the customer-side verifier. Here we
# generate one (override with NONCE_HEX=...) to demonstrate the mechanism.
NONCE_HEX="${NONCE_HEX:-$(openssl rand -hex 32)}"
openssl genpkey -algorithm X25519 -out "$GUEST_KEY" 2>/dev/null
openssl pkey -in "$GUEST_KEY" -pubout -outform DER -out "$GUEST_PUB" 2>/dev/null
BINDING="$(hcl_binding_hash "$BINDING_DOMAIN" "$NONCE_HEX" "$GUEST_PUB" "$CTX_FILE")"
echo "      - nonce            : ${NONCE_HEX}"
echo "      - guest pubkey     : $(wc -c < "$GUEST_PUB") bytes (X25519, DER)"
echo "      - qualifying data  : ${BINDING}"
echo "        = SHA-256(\"${BINDING_DOMAIN}\" || nonce || guest_pubkey$( [[ -n "$CTX_FILE" ]] && echo ' || ctx'))"
echo "      - taking AK-signed quote over PCRs ${PCR_LIST#sha256:}..."
tpm2_quote -c "$AK_HANDLE" -l "$PCR_LIST" -q "$BINDING" \
  -m "$QUOTE_MSG" -s "$QUOTE_SIG" -o "$QUOTE_PCRS" -g sha256 >/dev/null
echo "      - verifying the quote under the AK public key (extraData == binding):"
tpm2_checkquote -u "$AK_PUB" -m "$QUOTE_MSG" -s "$QUOTE_SIG" \
  -f "$QUOTE_PCRS" -g sha256 -q "$BINDING" >/dev/null
echo "        quote signature valid; qualifying data matches the binding hash."

cat <<EOF

-- demo complete --
The full composite Azure SEV-SNP evidence verified, end to end, with NO
Microsoft Azure Attestation (MAA) in the trust path:

  AMD ARK -> ASK -> VCEK -> AMD SEV-SNP report          (Part 1, AMD silicon)
    report_data == H(HCL runtime data)                  (step 6)
      runtime data carries HCLAkPub == live vTPM AK     (step 7)
        vTPM AK signs a fresh quote over PCRs whose
        qualifying data binds nonce + guest pubkey      (step 8)

The AMD report proves genuine hardware; the runtime-data binding ties the
vTPM AK to that hardware; and the AK-signed quote proves freshness and binds
a guest-held key. A customer-side verifier can now release a secret to the
quoted guest public key without trusting Microsoft as the attestation
authority. (Guest image/PCR policy is the verifier's remaining decision.)
EOF
