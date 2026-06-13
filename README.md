# solpbc

Tooling for AMD SEV-SNP attestation on Azure Confidential VMs, without relying on Microsoft Azure Attestation (MAA) as the verification authority.

## Background

Azure Confidential VMs expose an AMD-signed SEV-SNP hardware report, but not via the standard `/dev/sev-guest` interface. Instead, the report is embedded in an HCL attestation blob stored at vTPM NV index `0x01400001`. This repo implements a verification path that roots trust in AMD silicon and uses a composite AMD report + vTPM quote for freshness binding — bypassing MAA as the release authority.

See [`docs/azure-sev-snp-attestation-brief.pdf`](docs/azure-sev-snp-attestation-brief.pdf) for the full research brief.

## Repo layout

```
.
├── Containerfile          # Container image definition (Ubuntu 24.04 base)
├── run.sh                 # Entry point script
├── .gitignore
└── docs/
    └── azure-sev-snp-attestation-brief.pdf
```

## Quick start

This tooling runs **on** an Azure Confidential VM and reads the SEV-SNP report
from the guest vTPM. The Azure CVM customizations (confidential-compute kernel,
paravisor/OpenHCL, vTPM provisioning, measured boot) live in the host VM image,
not in the container — so first provision the VM, then run the container on it
with the TPM passed through.

```bash
# 1. Provision an Ubuntu 24.04 LTS Confidential VM (AMD SEV-SNP, Gen2).
#    Free image; use `ubuntu-pro-cvm` instead for ongoing Pro patching.
az vm create \
  --name solpbc-cvm \
  --resource-group <your-rg> \
  --image Canonical:ubuntu-24_04-lts:cvm:latest \
  --size Standard_DC2as_v5 \
  --security-type ConfidentialVM \
  --enable-vtpm true \
  --enable-secure-boot true \
  --os-disk-security-encryption-type VMGuestStateOnly \
  --admin-username azureuser --generate-ssh-keys

# 2. On the CVM: build the container.
podman build -t solpbc .

# 3. Run it, passing through the vTPM resource-manager device.
podman run --rm --device /dev/tpmrm0 solpbc
```

## Attestation approach

The verification chain is:

```
AMD ARK → ASK/ASVK → VCEK/VLEK → AMD SEV-SNP report
    └─ report_data = H(HCL runtime data)
           └─ runtime data contains vTPM AK public key
                  └─ vTPM AK signs TPM quote over PCRs + H(nonce ∥ guest_pubkey ∥ ctx)
```

Key properties:
- AMD root of trust: report verifies to AMD CA without MAA
- No Microsoft as verifier: the verifier appraises the raw AMD report + vTPM quote directly
- Freshness: vTPM quote qualifying data carries the nonce + guest ephemeral public key
- Guest image integrity: vTPM PCRs + event log + optional IMA/dm-verity (not the AMD launch measurement, which covers HCL/UEFI only)

## Prerequisites

- Azure DCasv5/ECasv5 (or newer) Confidential VM with vTPM enabled, provisioned
  from a Confidential-Compute host image (Ubuntu 24.04 LTS, AMD64 Gen2):
  - `Canonical:ubuntu-24_04-lts:cvm:latest` — free
  - `Canonical:ubuntu-24_04-lts:ubuntu-pro-cvm:latest` — Ubuntu Pro (ongoing patching)
- `tpm2-tools`, `openssl`, `xxd`, `jq` (provided by the container; see `Containerfile`)
- Rust toolchain (for `snpguest` with `--features hyperv`)

## References

- [VirTEE snpguest](https://github.com/virtee/snpguest)
- [az-snp-vtpm / azure-cvm-tooling](https://docs.rs/az-snp-vtpm)
- [OpenHCL / OpenVMM](https://openvmm.dev)
- [AMD SEV-SNP firmware ABI spec](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf)
- [IETF RATS RFC 9334](https://www.rfc-editor.org/rfc/rfc9334)
