#!/usr/bin/env bash
#
# demo.sh — the whole solpbc story in a single container run.
#
# Orchestrates the three roles end to end:
#   STAGE 1  [verifier] issues a fresh challenge nonce
#   STAGE 2  [attester] binds that nonce and produces the evidence bundle
#            (run.sh: AMD report -> cert chain -> runtime-data binding ->
#             AK binding -> fresh AK-signed quote)
#   STAGE 3  [verifier] independently appraises the bundle and, on success,
#            releases a (toy) key to the guest's public key
#
# This is the default container entrypoint, so on an Azure SEV-SNP CVM:
#   podman run --rm --device /dev/tpm0 --device /dev/tpmrm0 \
#     --group-add keep-groups -v "$PWD:/out" solpbc
#
# The individual roles are still runnable on their own:
#   podman run ... --entrypoint /app/run.sh    solpbc   # attester only
#   podman run ... --entrypoint /app/verify.sh solpbc appraise /out
#
# NOTE: the verifier here runs in the same container as the attester purely so
# the demo is self-contained; a real verifier runs on separate, customer-
# controlled hardware. See journal/2026-06-16-verifier-plan.md.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OUT_DIR="${OUT_DIR:-/out}"
[[ -d "$OUT_DIR" && -w "$OUT_DIR" ]] || OUT_DIR="/tmp"
export OUT_DIR

TPM_DEV="/dev/tpm0"

cat <<'BANNER'
#####################################################################
#  solpbc — end-to-end Azure SEV-SNP attestation demo
#
#    [verifier] issue nonce
#        -> [attester] bind nonce + produce AMD-rooted evidence
#            -> [verifier] appraise evidence + release key to guest
#
#  AMD silicon is the only root of trust. No Microsoft Azure
#  Attestation (MAA) anywhere in the path.
#####################################################################
BANNER

if [[ ! -e "$TPM_DEV" ]]; then
  cat <<EOF

No vTPM device at ${TPM_DEV}. This demo must run ON an Azure SEV-SNP Confidential
VM with the TPM passed through:

  podman run --rm --device /dev/tpm0 --device /dev/tpmrm0 \\
    --group-add keep-groups -v "\$PWD:/out" solpbc

To exercise the parsing/verifier logic off-hardware (no CVM needed), run the
self-tests instead:

  ./test/freshness-selftest.sh
  ./test/verifier-selftest.sh
EOF
  exit 0
fi

echo
echo "============================================================"
echo " STAGE 1/3 — [verifier] issue a fresh challenge nonce"
echo "============================================================"
DEMO=1 "${SCRIPT_DIR}/verify.sh" challenge "$OUT_DIR"

echo
echo "============================================================"
echo " STAGE 2/3 — [attester] bind the nonce and produce evidence"
echo "============================================================"
NONCE_HEX="$(tr -d '[:space:]' < "${OUT_DIR}/nonce.hex")" "${SCRIPT_DIR}/run.sh"

echo
echo "============================================================"
echo " STAGE 3/3 — [verifier] appraise the evidence and release key"
echo "============================================================"
"${SCRIPT_DIR}/verify.sh" appraise "$OUT_DIR"

echo
echo "#####################################################################"
echo "#  demo complete: AMD-rooted report + fresh guest-bound quote +"
echo "#  key release, verified independently, with no MAA in the path."
echo "#####################################################################"
