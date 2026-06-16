#!/usr/bin/env bash
#
# test/freshness-selftest.sh — off-hardware tests for lib/hcl.sh.
#
# There is no TPM here, so the tpm2_quote / tpm2_checkquote step in run.sh
# cannot be exercised without a CVM. Everything *around* it can: this test
# fabricates a synthetic HCLA blob (header + AMD report whose report_data is
# H(runtime data) + runtime JSON carrying an RSA HCLAkPub + NUL padding) and
# drives the lib functions end to end, including negative cases.
#
# Run anywhere with bash + openssl + jq + xxd + base64 (no hardware needed):
#   ./test/freshness-selftest.sh

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=../lib/hcl.sh
source "$ROOT/lib/hcl.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

pass=0; fail=0
ok()  { echo "  ok   - $1"; pass=$((pass+1)); }
bad() { echo "  FAIL - $1"; fail=$((fail+1)); }

# emit a little-endian uint32 (decimal arg) as raw bytes
le32() {
  local v="$1"
  printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' \
    $((v & 0xff)) $(((v>>8)&0xff)) $(((v>>16)&0xff)) $(((v>>24)&0xff)))"
}

echo "== building synthetic fixture =="

# 1. A stand-in vTPM AK (RSA-2048) and its public PEM.
openssl genrsa -out ak.key 2048 >/dev/null 2>&1
openssl rsa -in ak.key -pubout -out akpub.pem >/dev/null 2>&1

# 2. The AK modulus as base64url, to embed as the HCLAkPub JWK "n".
mod_hex=$(openssl rsa -in ak.key -modulus -noout | sed 's/^Modulus=//')
b64url() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
n_b64url=$(printf '%s' "$mod_hex" | xxd -r -p | b64url)

# 3. The HCL runtime-data JSON (claims), with HCLAkPub carrying that modulus.
cat > runtime.json <<JSON
{"keys":[{"kid":"HCLAkPub","key_ops":["sign"],"kty":"RSA","e":"AQAB","n":"${n_b64url}"}],"vm-configuration":{"console-enabled":true,"secure-boot":true,"tpm-enabled":true,"vmUniqueId":"00000000-0000-0000-0000-000000000000"}}
JSON
# strip the trailing newline so the on-disk bytes are exactly the claims
printf '%s' "$(cat runtime.json)" > runtime.json.tmp && mv runtime.json.tmp runtime.json

# 4. AMD report (1184 bytes) whose report_data[0..32] = SHA-256(runtime data).
json_hash_bin=$(openssl dgst -sha256 -binary < runtime.json | xxd -p -c32)
report_data_hex="${json_hash_bin}$(printf '00%.0s' {1..32})"   # 32-byte hash + 32 zero bytes
: > amd_report.bin
head -c "$SNP_REPORT_DATA_OFFSET" /dev/zero >> amd_report.bin           # bytes 0..79
printf '%s' "$report_data_hex" | xxd -r -p >> amd_report.bin            # report_data @80 (64B)
tail_len=$(( HCL_REPORT_SIZE - SNP_REPORT_DATA_OFFSET - SNP_REPORT_DATA_SIZE ))
head -c "$tail_len" /dev/zero >> amd_report.bin                         # pad to 1184
[[ "$(wc -c < amd_report.bin)" -eq "$HCL_REPORT_SIZE" ]] || { echo "fixture: bad report size"; exit 1; }

# 5. Assemble the HCLA blob: 32B header + report + 20B binary metadata + JSON + NUL pad.
#    The 20B metadata mimics the IgvmRequestData struct and verifies that the
#    JSON extractor anchors on `{"` rather than a fixed offset.
{
  printf 'HCLA'                 # signature
  le32 1                        # version (observed on a live DCasv5 CVM)
  le32 "$HCL_REPORT_SIZE"       # report_size
  le32 2                        # request_type
  le32 0                        # status
  le32 0; le32 0; le32 0        # reserved (32 bytes total so far)
  cat amd_report.bin            # AMD report @32
  # 20-byte metadata (data_size, version, report_type, hash_type, var_size)
  jlen=$(wc -c < runtime.json)
  le32 20; le32 2; le32 2; le32 1; le32 "$jlen"
  cat runtime.json              # JSON claims
  head -c 200 /dev/zero         # NUL padding (as Azure pads the NV region)
} > hcl_report.bin
echo "  built hcl_report.bin ($(wc -c < hcl_report.bin) bytes)"

echo
echo "== positive cases =="

# header
if hcl_verify_header hcl_report.bin >/dev/null; then ok "HCLA header verifies"; else bad "HCLA header"; fi

# embedded AMD report is byte-identical
hcl_amd_report hcl_report.bin > extracted_report.bin
if cmp -s amd_report.bin extracted_report.bin; then ok "embedded AMD report extracted byte-exact"; else bad "AMD report extraction"; fi

# runtime JSON extraction is byte-exact and valid JSON
hcl_runtime_json hcl_report.bin > extracted.json
if cmp -s runtime.json extracted.json; then ok "runtime JSON extracted byte-exact"; else bad "runtime JSON extraction"; fi
if jq -e . extracted.json >/dev/null 2>&1; then ok "extracted runtime data parses as JSON"; else bad "extracted JSON parse"; fi

# report_data == H(runtime data)
if hcl_verify_runtime_binding amd_report.bin extracted.json >/dev/null; then ok "report_data == H(runtime data)"; else bad "runtime-data binding"; fi

# live AK modulus == AMD-bound HCLAkPub modulus
if hcl_verify_ak_binding extracted.json akpub.pem >/dev/null; then ok "vTPM AK matches AMD-bound HCLAkPub"; else bad "AK binding"; fi

# binding hash is deterministic and matches an independent computation
echo -n "abc123" > /dev/null
nonce_hex=$(openssl rand -hex 32)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out g.key 2>/dev/null
openssl pkey -in g.key -pubout -outform DER -out guest_pub.der 2>/dev/null
b1=$(hcl_binding_hash "sol-key-release-v1" "$nonce_hex" guest_pub.der)
ref=$( { printf '%s' "sol-key-release-v1"; printf '%s' "$nonce_hex" | xxd -r -p; cat guest_pub.der; } \
        | openssl dgst -sha256 -binary | xxd -p -c32 | tr -d '\n')
if [[ "$b1" == "$ref" && ${#b1} -eq 64 ]]; then ok "binding hash matches reference (${b1:0:16}...)"; else bad "binding hash"; fi

echo
echo "== negative cases =="

# tampered report_data must break the runtime-data binding
cp amd_report.bin tampered_report.bin
printf '\xff' | dd of=tampered_report.bin bs=1 seek="$SNP_REPORT_DATA_OFFSET" count=1 conv=notrunc status=none
if hcl_verify_runtime_binding tampered_report.bin extracted.json >/dev/null 2>&1; then bad "tampered report_data should fail"; else ok "tampered report_data rejected"; fi

# a different AK must fail the AK binding
openssl genrsa -out other.key 2048 >/dev/null 2>&1
openssl rsa -in other.key -pubout -out otherpub.pem >/dev/null 2>&1
if hcl_verify_ak_binding extracted.json otherpub.pem >/dev/null 2>&1; then bad "wrong AK should fail"; else ok "wrong AK rejected"; fi

# wrong HCLA signature must fail the header check
cp hcl_report.bin badsig.bin
printf 'XXXX' | dd of=badsig.bin bs=1 seek=0 count=4 conv=notrunc status=none
if hcl_verify_header badsig.bin >/dev/null 2>&1; then bad "bad HCLA sig should fail"; else ok "bad HCLA signature rejected"; fi

echo
echo "== summary: ${pass} passed, ${fail} failed =="
[[ "$fail" -eq 0 ]]
