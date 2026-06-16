# solpbc

Tooling for AMD SEV-SNP attestation on Azure Confidential VMs, without relying on Microsoft Azure Attestation (MAA) as the verification authority.

## Background

Azure Confidential VMs expose an AMD-signed SEV-SNP hardware report, but not via the standard `/dev/sev-guest` interface. Instead, the report is embedded in an HCL attestation blob stored at vTPM NV index `0x01400001`. This repo implements a verification path that roots trust in AMD silicon and uses a composite AMD report + vTPM quote for freshness binding — bypassing MAA as the release authority.

See [`docs/azure-sev-snp-attestation-brief.pdf`](docs/azure-sev-snp-attestation-brief.pdf) for the full research brief.

## Repo layout

```
.
├── Containerfile          # Container image definition (Ubuntu 24.04 base)
├── demo.sh                # Default entrypoint: full challenge->attest->appraise demo
├── run.sh                 # Attester: AMD chain + vTPM quote freshness binding
├── verify.sh              # TOY in-container verifier (appraises the bundle)
├── lib/
│   └── hcl.sh             # HCLA parsing + freshness-binding helpers (custom logic)
├── test/
│   ├── build-check.sh     # Hardware-free build/lint/smoke/selftest harness
│   ├── freshness-selftest.sh  # Off-hardware tests for lib/hcl.sh
│   └── verifier-selftest.sh   # Off-hardware tests for verify.sh
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

# 2. On the CVM: get the code and build the container.
git clone https://github.com/solpbc/devops-lab.git solpbc && cd solpbc
podman build -t solpbc .

# 3. Grant your user (via the tss group) access to the raw vTPM device.
#    snpguest reads the pre-fetched report from /dev/tpm0, which is owned
#    tss:root — re-group it to tss so a rootless container can open it.
#    (Runtime-only; resets on reboot. A udev rule makes it permanent.)
sudo usermod -aG tss "$USER"          # then start a new shell / re-SSH
sudo chgrp tss /dev/tpm0 && sudo chmod g+rw /dev/tpm0

# 4. Run the full end-to-end demo (single command).
podman run --rm --device /dev/tpm0 --device /dev/tpmrm0 \
  --group-add keep-groups -v "$PWD:/out" solpbc
```

That one command runs the whole story (`demo.sh`): the **verifier** issues a
fresh nonce, the **attester** binds it and produces AMD-rooted evidence (fetch +
decode the SEV-SNP report, verify it to the AMD root, read the HCLA blob, confirm
the runtime-data binding, prove the vTPM AK is AMD-bound, take a fresh AK-signed
quote), and the **verifier** independently appraises that evidence and releases
a (toy) key to the guest — all with no MAA in the path (see
[Attestation approach](#attestation-approach)). Off-hardware it exits cleanly
with guidance.

Run an individual role instead of the full demo:

```bash
podman run ... --entrypoint /app/run.sh    solpbc              # attester only
podman run ... --entrypoint /app/verify.sh solpbc appraise /out  # verifier only
```

To exercise the HCLA parsing and freshness-binding logic **without** a CVM (just
`bash`, `openssl`, `jq`, `xxd`, `base64`), run the self-test:

```bash
./test/freshness-selftest.sh        # or: ./test/build-check.sh selftest
```

It fabricates a synthetic HCLA blob (with a stand-in RSA AK and a `report_data`
set to `H(runtime data)`) and drives every check in `lib/hcl.sh`, including the
negative cases.

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

### What `run.sh` implements

`run.sh` runs the chain in eight steps; the custom logic beyond `snpguest` lives
in `lib/hcl.sh`:

1–4. **AMD report.** Fetch the SEV-SNP report from the vTPM (`snpguest report --platform`), decode it, fetch the AMD CA + VCEK from the KDS, and verify the cert chain and report signature.

5. **Read the HCLA blob** from vTPM NV `0x01400001`, verify its header, and split out the embedded AMD report and the runtime-data JSON.

6. **Runtime-data binding.** Confirm `SHA-256(runtime data) == report_data[0..32]` — i.e. the AMD report commits to the HCL runtime claims.

7. **AK binding.** Extract `HCLAkPub` from the runtime claims and confirm it is the live vTPM AK by matching RSA moduli. The AK is trusted because it is inside AMD-bound runtime data, *not* because Azure issued a cert for it. (Matching the modulus avoids reconstructing a PEM from the JWK; the quote is still verified under the TPM's own AK PEM.)

8. **Freshness.** Generate an ephemeral X25519 guest key, take a nonce, and take an AK-signed TPM quote over the measured-boot PCRs whose qualifying data is `H("sol-key-release-v1" ∥ nonce ∥ guest_pubkey ∥ ctx)`. Verify the quote under the AK and confirm the qualifying data matches.

This closes the loop: a customer-side verifier can release a secret to the
quoted guest public key with AMD as the only root of trust. Reference values
for the guest PCR/event-log policy remain the verifier's decision (see the
brief's "Risks").

### Toy verifier (`verify.sh`)

`verify.sh` demonstrates the **verifier's role** — the half that, in a real
deployment, runs on customer-controlled hardware that is *not* the CVM. It is a
teaching aid: it runs in the same container as the attester and even unwraps the
released key locally to show the round-trip. It independently re-runs the
checks (it does not trust `run.sh`'s results) and only releases a secret if all
pass:

```bash
# on the CVM, inside the container working dir (-v $PWD:/out):
./verify.sh challenge          # verifier issues a fresh nonce -> nonce.hex
NONCE_HEX=$(cat nonce.hex) ./run.sh    # attester binds that nonce, writes the bundle
./verify.sh appraise           # re-verify the bundle + toy key release
```

`appraise` checks: HCLA header, runtime-data binding (`report_data == H(runtime
data)`), AMD cert chain + report signature (optionally against a pinned ARK via
`PINNED_ARK_SHA256`), the AK↔`HCLAkPub` binding, and the AK-signed quote whose
qualifying data must equal the binding recomputed from the verifier's own nonce.
On success it wraps a stand-in LUKS key to the guest's X25519 pubkey (ECDH →
SHA-256 KDF → AES-CTR — toy crypto, clearly labelled) and proves the guest can
unwrap it. What's deliberately **not** real here, flagged inline as `[TOY GAP]`:
it runs on the CVM rather than a separate verifier, trusts the fetched ARK
unless pinned, uses unauthenticated AES-CTR instead of an AEAD, and has only a
record-then-pin PCR policy (no Microsoft HCL reference values). The real
verifier is the next milestone — see `journal/2026-06-16-verifier-plan.md`.

The hardware-free parts (policy parsing, key-release round-trip) are covered by
`./test/verifier-selftest.sh`.

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
