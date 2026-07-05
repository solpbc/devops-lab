#!/usr/bin/env bash
#
# demo-aci.sh — the solpbc story on ACI Confidential Containers.
#
# Same three roles as demo.sh, but with the verifier where it belongs — on
# YOUR machine, outside the TEE. Unlike the CVM demo (which runs everything
# in one container for self-containment), the trust boundary here is real:
#   STAGE 1  [verifier, this machine] issues a fresh challenge nonce
#   STAGE 2  [attester, ACI TEE] container binds the nonce at startup and
#            emits the raw SNP report via container logs
#   STAGE 3  [verifier, this machine] fetches the VCEK from AMD and
#            appraises: chain -> signature -> freshness -> CCE policy hash
#
# Usage:
#   ./demo-aci.sh setup     one-time: RG + ACR + build/push image + CCE policy
#   ./demo-aci.sh           the demo: deploy w/ fresh nonce -> logs -> appraise
#   ./demo-aci.sh clean     delete the resource group + local scratch
#
# Requires: az (logged in), podman, python3 (>=3.9) with -r requirements.txt.
# State (resource names) persists in .demo-aci.env; scratch files template.json
# and params.json hold the injected policy and ACR password (all gitignored).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

STATE_FILE=".demo-aci.env"
[[ -f "$STATE_FILE" ]] && source "$STATE_FILE"

RG="${RG:-solpbc-aci-rg}"
LOC="${LOC:-eastus}"
ACR="${ACR:-}"
IMAGE="${IMAGE:-}"
OUT_DIR="${OUT_DIR:-aci-demo-out}"

need() { command -v "$1" >/dev/null || { echo "missing dependency: $1" >&2; exit 1; }; }

usage() { sed -n '3,21p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

save_state() {
  printf 'RG=%q\nLOC=%q\nACR=%q\nIMAGE=%q\n' "$RG" "$LOC" "$ACR" "$IMAGE" > "$STATE_FILE"
}

policy_hash_from_template() {
  python3 - <<'EOF'
import base64, hashlib, json
t = json.load(open("template.json"))
p = t["resources"][0]["properties"]["confidentialComputeProperties"]["ccePolicy"]
print(hashlib.sha256(base64.b64decode(p)).hexdigest())
EOF
}

extract_policy_b64() {
  python3 - <<'EOF'
import json
t = json.load(open("template.json"))
print(t["resources"][0]["properties"]["confidentialComputeProperties"]["ccePolicy"])
EOF
}

setup() {
  need az; need podman; need python3
  ACR="${ACR:-solpbcacr$RANDOM}"
  IMAGE="$ACR.azurecr.io/solpbc-aci:latest"
  save_state
  echo "== setup: RG=$RG LOC=$LOC ACR=$ACR =="

  echo "-- build (amd64) --"
  podman build --platform linux/amd64 -f Containerfile.aci -t solpbc-aci .

  echo "-- resource group + registry --"
  az provider register --namespace Microsoft.ContainerRegistry --wait
  az group create -n "$RG" -l "$LOC" --output none
  az acr create -g "$RG" -n "$ACR" --sku Basic --admin-enabled true --output none

  echo "-- push (token login; retries around fresh-registry DNS lag) --"
  for attempt in 1 2 3; do
    TOKEN=$(az acr login -n "$ACR" --expose-token --query accessToken -o tsv) && break
    echo "   registry not resolvable yet (attempt $attempt); waiting 30s"; sleep 30
  done
  podman login "$ACR.azurecr.io" -u 00000000-0000-0000-0000-000000000000 -p "$TOKEN"
  podman tag solpbc-aci "$IMAGE"
  podman push "$IMAGE"

  echo "-- params + template --"
  ACR_USER=$(az acr credential show -n "$ACR" --query username -o tsv)
  ACR_PASS=$(az acr credential show -n "$ACR" --query 'passwords[0].value' -o tsv)
  python3 - "$IMAGE" "$ACR_USER" "$ACR_PASS" <<'EOF'
import json, sys
image, user, password = sys.argv[1:4]
params = {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "image": {"value": image},
        "registryUsername": {"value": user},
        "registryPassword": {"value": password},
    },
}
json.dump(params, open("params.json", "w"), indent=2)
EOF
  cp templates/aci-solpbc.json template.json

  echo "-- CCE policy (debug policy: exec/logs enabled; demo only) --"
  if [[ "$(uname)" == "Darwin" ]]; then
    podman save -o /private/tmp/solpbc-policy-img.tar "$IMAGE"
    printf '{"%s": "/work/img.tar"}' "$IMAGE" > /private/tmp/solpbc-tarmap.json
    podman run --rm \
      -v "$PWD/template.json":/work/template.json \
      -v "$PWD/params.json":/work/params.json \
      -v /private/tmp/solpbc-policy-img.tar:/work/img.tar \
      -v /private/tmp/solpbc-tarmap.json:/work/tarmap.json \
      mcr.microsoft.com/azure-cli \
      bash -c 'az extension add --name confcom -y >/dev/null 2>&1 && az confcom acipolicygen -a /work/template.json -p /work/params.json --debug-mode --approve-wildcards --tar /work/tarmap.json'
  else
    az extension add --upgrade --name confcom >/dev/null 2>&1
    az confcom acipolicygen -a template.json -p params.json --debug-mode --approve-wildcards
  fi

  echo
  echo "setup complete. expected HOST_DATA: $(policy_hash_from_template)"
  echo "run the demo: ./demo-aci.sh"
}

attest_and_appraise() {
  need az; need python3
  [[ -f template.json && -f params.json ]] || { echo "no template.json/params.json — run: ./demo-aci.sh setup" >&2; exit 1; }
  python3 -c 'import cryptography' 2>/dev/null \
    || { echo "python3 lacks 'cryptography' — run: python3 -m pip install --user -r requirements.txt" >&2; exit 1; }

  cat <<'BANNER'
#####################################################################
#  solpbc — end-to-end ACI Confidential Containers attestation demo
#
#    [verifier, HERE] issue nonce
#        -> [attester, ACI TEE] bind nonce + emit raw SNP report
#            -> [verifier, HERE] AMD chain + freshness + policy hash
#
#  AMD silicon is the only root of trust. No MAA, no vTPM, no HCL.
#####################################################################
BANNER

  echo
  echo "============================================================"
  echo " STAGE 1/3 — [verifier] issue a fresh challenge nonce"
  echo "============================================================"
  NONCE=$(openssl rand -hex 32)
  echo "nonce: $NONCE"

  echo
  echo "============================================================"
  echo " STAGE 2/3 — [attester] deploy TEE, bind nonce, emit report"
  echo "============================================================"
  echo "-- replacing any previous container group (nonce is fixed per deployment) --"
  az container delete -g "$RG" -n solpbc --yes --output none 2>/dev/null || true
  az deployment group create -g "$RG" --template-file template.json \
    --parameters @params.json --parameters nonceHex="$NONCE" --output none
  echo "-- waiting for the report in container logs --"
  REPORT_B64=""
  for _ in $(seq 1 30); do
    REPORT_B64=$(az container logs -g "$RG" -n solpbc 2>/dev/null \
      | grep -E '^[A-Za-z0-9+/=]{200,}$' | tail -1 || true)
    [[ -n "$REPORT_B64" ]] && break
    sleep 5
  done
  [[ -n "$REPORT_B64" ]] || { echo "no report in logs after 150s" >&2; exit 1; }
  mkdir -p "$OUT_DIR"
  printf '%s' "$REPORT_B64" | base64 -d > "$OUT_DIR/report.bin"
  extract_policy_b64 > "$OUT_DIR/policy.b64"
  echo "report: $OUT_DIR/report.bin ($(wc -c < "$OUT_DIR/report.bin" | tr -d ' ') bytes)"

  echo
  echo "============================================================"
  echo " STAGE 3/3 — [verifier] fetch VCEK + appraise the evidence"
  echo "============================================================"
  python3 verifier.py fetch-vcek "$OUT_DIR"
  python3 verifier.py appraise-raw "$OUT_DIR" --roots roots/amd \
    --cce-policy-file "$OUT_DIR/policy.b64" --nonce-hex "$NONCE"

  echo
  echo "#####################################################################"
  echo "#  demo complete: raw SNP report, nonce-fresh, CCE-policy-bound,"
  echo "#  verified against pinned AMD roots, with no MAA in the path."
  echo "#####################################################################"
  echo "reminder: the container group keeps billing — ./demo-aci.sh clean"
}

clean() {
  need az
  az group delete -n "$RG" --yes --no-wait || true
  rm -f params.json template.json "$STATE_FILE"
  rm -rf "$OUT_DIR"
  echo "resource group deletion requested; local scratch removed."
}

case "${1:-demo}" in
  setup)        setup ;;
  demo|attest)  attest_and_appraise ;;
  clean)        clean ;;
  -h|--help)    usage 0 ;;
  *)            echo "unknown command: $1" >&2; usage 1 ;;
esac
