#!/usr/bin/env bash
# aks-cc-testbed.sh — stand up a throwaway AKS cluster on confidential-child-capable
# (EC*_cc_v5) nodes to answer the journal's open question: native /dev/sev-guest
# vs HCL-mediated child attestation, firmware/ID-block control, HOST_DATA contents.
#
# Run sections interactively; don't blind-execute (feature registration has a wait).
#
# NOTE on VMExtensionError_K8SDownloadTimeout + curl 404: that's not a firewall
# problem — the node reached the endpoint and the artifact doesn't exist. Cause is
# a stale k8s-version/node-image combo (Azure Linux 2 images were removed
# 2026-03-31; old images also reference the retired acs-mirror.azureedge.net CDN).
# Mitigations baked in below: pin a current --kubernetes-version, keep aks-preview
# updated, and create the system pool and kata-cc pool separately to isolate
# failures.
set -euo pipefail

TEMPLATES_DIR="$(cd "$(dirname "$0")" && pwd)/templates"   # probe pod manifests

RG=solpbc-akscc-rg
LOC=eastus                       # cc_v5 SKUs are region-limited; verify below.
                                 # If the kata-cc pool 404s here, try westeurope/eastus2.
CLUSTER=solpbc-akscc
VM_SIZE=Standard_EC8as_cc_v5     # E-series: RAM-bound per cost analysis.
                                 # Docs' example is Standard_DC8as_cc_v5 — swap if
                                 # EC isn't offered in your region/quota.

# ---------------------------------------------------------------- 0. one-time setup
az extension add --upgrade --name aks-preview   # stale extension -> stale payloads
az extension add --upgrade --name confcom       # katapolicygen (CCE policy -> HOST_DATA)

az feature register --namespace Microsoft.ContainerService --name KataCcIsolationPreview
# poll until "Registered" (takes a few minutes):
az feature show --namespace Microsoft.ContainerService --name KataCcIsolationPreview \
  --query properties.state -o tsv
az provider register --namespace Microsoft.ContainerService

# confirm the SKU exists in the region (and check quota for the family):
az vm list-skus -l "$LOC" --all -o table | grep -i as_cc_v5

# pin the newest GA kubernetes version — do NOT rely on the default (see NOTE above):
az aks get-versions -l "$LOC" -o table
K8S_VERSION=1.35.5

# ---------------------------------------------------------------- 1. cluster
az group create -n "$RG" -l "$LOC"

# system pool on a plain size first — isolates generic provisioning failures
# from kata-cc VHD/artifact problems:
az aks create -g "$RG" -n "$CLUSTER" \
  --kubernetes-version "$K8S_VERSION" \
  --os-sku AzureLinux \
  --node-vm-size Standard_D4as_v7 \
  --node-count 1 \
  --enable-oidc-issuer --enable-workload-identity \
  --generate-ssh-keys

# then the confidential-child-capable pool:
az aks nodepool add -g "$RG" --cluster-name "$CLUSTER" -n katacc \
  --kubernetes-version "$K8S_VERSION" \
  --os-sku AzureLinux \
  --node-vm-size "$VM_SIZE" \
  --workload-runtime KataCcIsolation \
  --node-count 1

az aks get-credentials -g "$RG" -n "$CLUSTER"
kubectl get runtimeclass          # expect: kata-cc-isolation
kubectl get nodes -o wide

# --- if the nodepool add fails with the CSE 404: dump the exact URL it curled ---
# NODE_RG=$(az aks show -g "$RG" -n "$CLUSTER" --query nodeResourceGroup -o tsv)
# VMSS=$(az vmss list -g "$NODE_RG" --query '[?contains(name,`katacc`)].name | [0]' -o tsv)
# az vmss run-command invoke -g "$NODE_RG" -n "$VMSS" --instance-id 0 \
#   --command-id RunShellScript \
#   --scripts "tail -80 /var/log/azure/cluster-provision-cse-output.log; grep -oE 'https://[^\" ]+' /var/log/azure/cluster-provision.log | sort -u | tail -20"
# acs-mirror.azureedge.net or AL2 paths => version/image staleness: bump K8S_VERSION.
# missing kata-cc/IGVM artifact on packages.aks.azure.com => preview publication gap:
# try another region/minor version; file at https://github.com/Azure/AKS/issues

# ---------------------------------------------------------------- 2. Layer-1 probe:
# pod inside a SEV-SNP child UVM. Determines the child attestation path.
# Manifest: templates/snp-probe.yaml (kept pristine — policy is injected at apply time)
#
# generate a *debug* CCE policy (permits exec/logs — test only) without
# mutating the manifest; --print-policy emits the base64 Rego to stdout:
POLICY_B64=$(az confcom katapolicygen -y "$TEMPLATES_DIR/snp-probe.yaml" --debug-mode --print-policy)
# record the policy hash — this is what should land in HOST_DATA:
echo "$POLICY_B64" | base64 -d | sha256sum

# inject the policy annotation client-side and apply (source file untouched):
kubectl annotate --local -f "$TEMPLATES_DIR/snp-probe.yaml" -o yaml \
  "io.katacontainers.config.agent.policy=$POLICY_B64" | kubectl apply -f -
kubectl exec -it snp-probe -- bash
# --- inside the UVM, the decisive checks: ---
#   ls -l /dev/sev-guest /dev/sev /dev/tpm0 /dev/tpmrm0     # native vs vTPM path?
#   dmesg | grep -i -e sev -e snp -e hcl -e tpm
#   apt-get update && apt-get install -y tpm2-tools         # if a vTPM shows up:
#   tpm2_nvreadpublic                                        # HCLA at 0x01400001?
#   # if /dev/sev-guest exists: fetch a raw report (snpguest / sev-guest ioctl),
#   # inspect HOST_DATA (= policy hash above?), CHIP_ID (real or zeroed?),
#   # then feed it to verifier.py — MAA-free path, no lib/hcl.sh needed.
#   # THIM cert endpoint (VCEK chain without AMD KDS?):
#   curl -s http://169.254.169.254/metadata/THIM/amd/certification -H Metadata:true

# ---------------------------------------------------------------- 3. Layer-2 probe:
# privileged runc pod on the *parent* node. Determines whether we could launch
# our own children (own OVMF, ID block) — the solstone trust-shape question.
# Manifest: templates/parent-probe.yaml
kubectl apply -f "$TEMPLATES_DIR/parent-probe.yaml"
kubectl exec -it parent-probe -- bash
# --- on the parent: ---
#   ls -l /host/dev/sev /host/dev/sev-guest
#   cat /host/sys/module/kvm_amd/parameters/sev /host/sys/module/kvm_amd/parameters/sev_snp
#   ps aux | grep -e cloud-hypervisor -e qemu     # what launches the UVMs?
#   ls /host/opt/confidential-containers/share/kata-containers/   # IGVM / UVM image, reference-info
#   # if /dev/sev is usable: try a minimal SNP guest with own OVMF + ID block.

# ---------------------------------------------------------------- 4. cost control
az aks stop -g "$RG" -n "$CLUSTER"      # pause between sessions
# az aks start -g "$RG" -n "$CLUSTER"
# teardown:
# az group delete -n "$RG" --yes --no-wait
