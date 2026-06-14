#!/usr/bin/env bash
#
# solpbc demo entry point.
#
# Fetches the AMD SEV-SNP attestation report from the Azure Confidential VM's
# vTPM and decodes it. On Azure the paravisor pre-fetches the report at VMPL 0
# and stores it in the vTPM, so snpguest reads it via `--platform` (the hyperv
# build feature) rather than the absent /dev/sev-guest interface.
#
# Verifying the report against the AMD cert chain (ARK -> ASK -> VCEK) is the
# next milestone and is intentionally NOT done here yet.
#
# Run on the CVM with the raw vTPM device passed through, e.g.:
#   podman run --rm --device /dev/tpm0 --device /dev/tpmrm0 \
#     --group-add keep-groups -v "$PWD:/out" -w /out solpbc

set -euo pipefail

# Where to write artifacts. Defaults to a mounted /out volume if present,
# otherwise an ephemeral /tmp (override with OUT_DIR=...).
OUT_DIR="${OUT_DIR:-/out}"
[[ -d "$OUT_DIR" && -w "$OUT_DIR" ]] || OUT_DIR="/tmp"

REPORT="${OUT_DIR}/report.bin"
REQUEST="${OUT_DIR}/request.txt"
CERTS_DIR="${OUT_DIR}/certs"
TPM_DEV="/dev/tpm0"

echo "== solpbc :: AMD SEV-SNP attestation demo =="

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
/dev/tpm0.)
EOF
  exit 0
fi

echo
echo "[1/4] Fetching attestation report from vTPM (VMPL 0, --platform)..."
snpguest report --platform "$REPORT" "$REQUEST"
size="$(wc -c < "$REPORT" | tr -d ' ')"
echo "      wrote ${REPORT} (${size} bytes)"

echo
echo "[2/4] Decoding attestation report:"
echo
snpguest display report "$REPORT"

# The fetch steps reach out to the AMD Key Distribution Service
# (kdsintf.amd.com). The processor model and chip/TCB are derived from the
# V3 report itself, so no hardware details need to be hardcoded.
echo
echo "[3/4] Fetching AMD certificate chain from the KDS..."
mkdir -p "$CERTS_DIR"
echo "      - ARK + ASK (certificate authority)"
snpguest fetch ca pem "$CERTS_DIR" --report "$REPORT"
echo "      - VCEK (chip- and TCB-specific endorsement key)"
snpguest fetch vcek pem "$CERTS_DIR" "$REPORT"

echo
echo "[4/4] Verifying the trust chain..."
echo "      - VCEK chains to the AMD root (ARK -> ASK -> VCEK):"
snpguest verify certs "$CERTS_DIR"
echo "      - report is signed by that VCEK:"
snpguest verify attestation "$CERTS_DIR" "$REPORT"

cat <<'EOF'

-- demo complete --
The SEV-SNP report was fetched from the vTPM and verified all the way to the
AMD root certificate -- genuine AMD-hardware-signed evidence, with no Microsoft
Azure Attestation (MAA) in the trust path. That is the core thesis of solpbc.

Next milestone: bind the vTPM quote for freshness. The report's report_data
commits to the HCL runtime data, which carries the vTPM AK public key; verifying
the AK-signed quote over (nonce || guest_pubkey || ctx) closes the loop. This is
custom logic beyond snpguest and is not yet implemented here.
EOF
