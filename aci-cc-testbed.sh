#!/usr/bin/env bash
# aci-cc-testbed.sh — Layer-1 attestation-shape probe on ACI Confidential
# Containers (GA), replacing the sunset AKS kata-cc path (see journal/2026-07-04).
#
# Question under test: can a tenant verify a policy-bound SEV-SNP child report
# AMD-rooted, with no MAA in the loop? Checks: raw /dev/sev(-guest) vs HCL/vTPM
# mediation, HOST_DATA == CCE policy hash, CHIP_ID real vs zeroed, THIM vs AMD KDS
# for the VCEK chain, then verifier.py appraisal.
#
# Run sections interactively; don't blind-execute.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE_SRC="$DIR/templates/aci-snp-probe.json"

RG=solpbc-acicc-rg
LOC=eastus            # confidential ACI is GA in most major regions

# ---------------------------------------------------------------- 0. setup
az extension add --upgrade --name confcom

# work on a copy: acipolicygen writes the policy into the template in place,
# and the policy is CLI-generated only (manual policies unsupported):
TEMPLATE=/tmp/aci-snp-probe.deploy.json
cp "$TEMPLATE_SRC" "$TEMPLATE"

# generate a *debug* CCE policy (allows exec — test only) and inject it:
az confcom acipolicygen -a "$TEMPLATE" --debug-mode

# record the expected HOST_DATA value (sha256 of the decoded policy):
python3 - "$TEMPLATE" <<'EOF'
import base64, hashlib, json, sys
t = json.load(open(sys.argv[1]))
pol = t["resources"][0]["properties"]["confidentialComputeProperties"]["ccePolicy"]
print("expected HOST_DATA:", hashlib.sha256(base64.b64decode(pol)).hexdigest())
EOF

# ---------------------------------------------------------------- 1. deploy
az group create -n "$RG" -l "$LOC"
az deployment group create -g "$RG" --template-file "$TEMPLATE"
az container show -g "$RG" -n snp-probe --query 'instanceView.state' -o tsv

# ---------------------------------------------------------------- 2. probe
az container exec -g "$RG" -n snp-probe --container-name probe \
  --exec-command "/bin/bash"
# --- RESULTS 2026-07-04 (see journal): /dev/sev-guest present, no vTPM, no
# paravisor (report VMPL=0, version 3). Nonce echoed; HOST_DATA == CCE policy
# hash; CHIP_ID real (AMD KDS works directly); id_key_digest nonzero (UVM
# launched with a Microsoft ID block). No HCL machinery needed.
#
# In-TEE report fetch (stock python3, no snpguest needed):
#   apt-get update -qq && apt-get install -y -qq python3 curl
#   curl -s -H Metadata:true \
#     http://169.254.169.254/metadata/THIM/amd/certification   # VCEK chain
#   python3 /dev/stdin <<'PYEOF'
# import ctypes, fcntl, os, struct, base64
# class Req(ctypes.Structure):
#     _fields_ = [("user_data", ctypes.c_ubyte*64), ("vmpl", ctypes.c_uint32),
#                 ("rsvd", ctypes.c_ubyte*28)]
# class Resp(ctypes.Structure):
#     _fields_ = [("data", ctypes.c_ubyte*4000)]
# class GuestReq(ctypes.Structure):
#     _fields_ = [("msg_version", ctypes.c_uint8), ("req_data", ctypes.c_uint64),
#                 ("resp_data", ctypes.c_uint64), ("fw_err", ctypes.c_uint64)]
# SNP_GET_REPORT = 0xC0205300   # _IOWR('S', 0x0, 32-byte struct)
# nonce = os.urandom(64)
# req = Req(vmpl=0); ctypes.memmove(req.user_data, nonce, 64)
# resp = Resp()
# gr = GuestReq(msg_version=1, req_data=ctypes.addressof(req),
#               resp_data=ctypes.addressof(resp), fw_err=0)
# fd = os.open("/dev/sev-guest", os.O_RDWR)
# fcntl.ioctl(fd, SNP_GET_REPORT, gr)
# status, size = struct.unpack_from("<II", bytes(resp.data), 0)
# assert status == 0 and size == 1184, (status, size, hex(gr.fw_err))
# report = bytes(resp.data)[32:32+1184]
# assert report[0x50:0x90] == nonce, "nonce not echoed"
# print("MEASUREMENT:", report[0x90:0xC0].hex())
# print("HOST_DATA:  ", report[0xC0:0xE0].hex())   # == policy sha256 from step 0
# print("CHIP_ID:    ", report[0x1A0:0x1E0].hex())
# open("/tmp/report.bin", "wb").write(report)
# print(base64.b64encode(report).decode())
# PYEOF
#
# Off-TEE appraisal: VCEK via THIM above or AMD KDS
# (https://kdsintf.amd.com/vcek/v1/Milan/<chip_id>?blSPL=..&teeSPL=..&snpSPL=..&ucodeSPL=..
# using reported_tcb fields at offset 0x180), then verifier.py against
# report.bin + chain; MEASUREMENT reference values are published in
# microsoft/confidential-sidecar-containers. No MAA anywhere in the path.

# ---------------------------------------------------------------- 3. teardown
# az group delete -n "$RG" --yes --no-wait
