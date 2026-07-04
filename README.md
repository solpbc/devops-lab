# solpbc

Tooling for AMD SEV-SNP attestation on Azure Confidential VMs, without relying on Microsoft Azure Attestation (MAA) as the verification authority.

## Background

Azure Confidential VMs expose an AMD-signed SEV-SNP hardware report, but not via the standard `/dev/sev-guest` interface. Instead, the report is embedded in an HCL attestation blob stored at vTPM NV index `0x01400001`. This repo implements a verification path that roots trust in AMD silicon and uses a composite AMD report + vTPM quote for freshness binding — bypassing MAA as the release authority.

See [`docs/azure-sev-snp-attestation-brief.pdf`](docs/azure-sev-snp-attestation-brief.pdf) for the full research brief.

## Repo layout

```
.
├── Containerfile          # CVM container image (vTPM path; Ubuntu 24.04 base)
├── Containerfile.aci      # ACI container image (raw /dev/sev-guest path)
├── fetch-report.py        # In-TEE raw report fetcher (stdlib-only, ACI path)
├── Makefile               # Local install/check/test convenience targets
├── aci-cc-testbed.sh      # ACI Confidential Containers testbed (raw SNP path)
├── aks-cc-testbed.sh      # AKS EC*_cc testbed (kata-cc; preview sunset 2026-03)
├── templates/             # Azure deployment templates + AKS probe pod manifests
│   ├── aci-snp-probe.json # Probe container group (stock ubuntu, zero config)
│   └── aci-solpbc.json    # Parameterized group for the solpbc image (ACR)
├── requirements.txt       # Python dependency set for verifier.py
├── demo.sh                # Default entrypoint: full challenge->attest->appraise demo
├── run.sh                 # Attester: AMD chain + vTPM quote freshness binding
├── verify.sh              # TOY in-container verifier (appraises the bundle)
├── verifier.py            # Off-CVM Python verifier spike (owner-side appraisal)
├── roots/amd/             # Pinned AMD ARK/ASK roots for verifier.py
├── lib/
│   └── hcl.sh             # HCLA parsing + freshness-binding helpers (custom logic)
├── test/
│   ├── build-check.sh     # Hardware-free build/lint/smoke/selftest harness
│   ├── freshness-selftest.sh  # Off-hardware tests for lib/hcl.sh
│   ├── python-verifier-selftest.py # Off-hardware tests for verifier.py
│   └── verifier-selftest.sh   # Off-hardware tests for verify.sh
├── .gitignore
└── docs/
    ├── off-cvm-python-verifier.md
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

## Running on ACI Confidential Containers (no vTPM)

ACI's confidential SKU runs the container inside an unparavisored SEV-SNP UVM
at VMPL0 with a native `/dev/sev-guest` — no vTPM, no HCLA blob, no paravisor
(verified 2026-07-04; see `journal/2026-07-04.md`). The vTPM demo flow
(`demo.sh`/`run.sh`) therefore does not apply; the ACI path is: fetch the raw
report in-TEE, appraise it off-TEE with `verifier.py appraise-raw`. Freshness
comes from `REPORT_DATA` carrying the verifier nonce directly, and workload
identity from `HOST_DATA` carrying the SHA-256 of the CCE policy.

The command blocks below are bash/zsh-neutral and contain no `#` comments, so
they paste cleanly into a default interactive zsh (which does not accept
comments unless `setopt interactive_comments` is set).

**0. Names used throughout.** ACR names are global DNS labels: 5–50 lowercase
alphanumerics, no dashes; `$RANDOM` is just a cheap uniqueness suffix.

```sh
RG=solpbc-aci-rg
LOC=eastus
ACR=solpbcacr$RANDOM
IMAGE="$ACR.azurecr.io/solpbc-aci:latest"
```

**1. Build for amd64 and push to ACR.** ACI has its own image:
`Containerfile.aci` builds `snpguest` with default features (the native
`/dev/sev-guest` ioctl path — there is no vTPM in this TEE) and ships
`fetch-report.py`; the main `Containerfile` is the CVM/vTPM variant and its
tooling is dead weight here. `--platform linux/amd64` is mandatory on Apple
Silicon — CCE policies are amd64-only. ACR rather than Docker Hub because the
Hub throttles anonymous pulls from ACI IP ranges. Bare `az acr login` needs a
Docker daemon; with podman, use the token flow with the `00000000-…` sentinel
username.

```sh
podman build --platform linux/amd64 -f Containerfile.aci -t solpbc-aci .
az provider register --namespace Microsoft.ContainerRegistry --wait
az group create -n "$RG" -l "$LOC"
az acr create -g "$RG" -n "$ACR" --sku Basic --admin-enabled true
TOKEN=$(az acr login -n "$ACR" --expose-token --query accessToken -o tsv)
podman login "$ACR.azurecr.io" -u 00000000-0000-0000-0000-000000000000 -p "$TOKEN"
podman tag solpbc-aci "$IMAGE"
podman push "$IMAGE"
```

**2. Write a parameters file.** `templates/aci-solpbc.json` is parameterized —
no template editing needed: it already runs `sleep infinity` (the default
`demo.sh` entrypoint expects a vTPM) and takes the image reference and ACR
pull credentials as parameters. ACR does not allow anonymous pull, so the
credentials are mandatory; the admin credentials work for a test registry
(don't use the short-lived `--expose-token` value here — longer-lived options
are a scoped ACR token or a managed identity with AcrPull). Both the policy
generator and the deployment consume this same file, so they can't drift.

```sh
ACR_USER=$(az acr credential show -n "$ACR" --query username -o tsv)
ACR_PASS=$(az acr credential show -n "$ACR" --query 'passwords[0].value' -o tsv)
cat > params.json <<EOF
{
  "\$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "image": { "value": "$IMAGE" },
    "registryUsername": { "value": "$ACR_USER" },
    "registryPassword": { "value": "$ACR_PASS" }
  }
}
EOF
cp templates/aci-solpbc.json template.json
```

**3. Generate and inject the CCE policy.** The policy generator computes
dm-verity hashes of every image layer and writes the result into
`template.json`'s `ccePolicy` field in place. It prints a sha256 on
injection: that is the expected `HOST_DATA` value in the SNP report — save
it. `--debug-mode` permits exec/logs; drop it for anything real. Rebuilding
the image changes the layer hashes, so regenerate after every build.

On Linux, it's one command:

```sh
az extension add --upgrade --name confcom
az confcom acipolicygen -a template.json -p params.json --debug-mode --approve-wildcards
```

`--approve-wildcards` consents (non-interactively) to the wildcard rule for
the `NONCE_HEX` env var — deliberate here: the nonce is unknown at policy
time, so the policy accepts any value in that one variable and the report
proves which value was actually bound.

On macOS the confcom extension does not run (`The extension for MacOS has not
been implemented`), so run it inside a Linux container instead. Two things
make this work daemon-free: the image layers are supplied as a tar
(`podman save` of the local tag from step 1 — no registry pull, and it's
already amd64), and a mapping file tells confcom which tar holds which image.
The mapping key must byte-match the image reference in `params.json`. The
`$PWD` mounts assume the repo lives under your home directory, which podman
machine shares by default.

```sh
podman save -o /private/tmp/policy-img.tar "$IMAGE"
printf '{"%s": "/work/img.tar"}' "$IMAGE" > /private/tmp/tarmap.json
podman run --rm \
  -v "$PWD/template.json":/work/template.json \
  -v "$PWD/params.json":/work/params.json \
  -v /private/tmp/policy-img.tar:/work/img.tar \
  -v /private/tmp/tarmap.json:/work/tarmap.json \
  mcr.microsoft.com/azure-cli \
  bash -c 'az extension add --name confcom -y && az confcom acipolicygen -a /work/template.json -p /work/params.json --debug-mode --approve-wildcards --tar /work/tarmap.json'
```

**4. Deploy, attest, appraise — no exec, no copy/paste.** The template binds a
verifier nonce (the `nonceHex` deployment parameter, wildcarded in the policy
because it's absent from `params.json`) into `REPORT_DATA` at startup, and the
container prints the report as base64 into its logs — the report's
machine-readable path out of the TEE. `fetch-vcek` locates the AMD cert from
the report itself (CHIP_ID + reported TCB; `--source acccache` uses
Microsoft's mirror of the same AMD-signed certs, no KDS rate limits). The
appraisal needs Python ≥3.11 plus `requirements.txt`; on a Mac without one,
run these two commands in any `python:3.12` container with the repo and
bundle mounted.

```sh
NONCE=$(openssl rand -hex 32)
az deployment group create -g "$RG" --template-file template.json \
  --parameters @params.json --parameters nonceHex=$NONCE
mkdir -p bundle
az container logs -g "$RG" -n solpbc | grep -E '^[A-Za-z0-9+/=]{200,}$' | tail -1 | base64 -d > bundle/report.bin
jq -r '.resources[0].properties.confidentialComputeProperties.ccePolicy' template.json > policy.b64
python3 verifier.py fetch-vcek bundle
python3 verifier.py appraise-raw bundle --roots roots/amd --cce-policy-file policy.b64 --nonce-hex $NONCE
```

Expect six `PASS` lines and `ALL CHECKS PASSED`. The nonce is fixed per
deployment; to re-attest with a fresh one, redeploy with a new `nonceHex`, or
`az container exec` in and run `fetch-report.py --nonce-hex <new>` manually.
`params.json` holds a registry password — don't commit it.

**5. Clean up.** The container group bills while it runs (`sleep infinity`
never exits on its own) and the resource group holds both the group and the
ACR, so one delete covers everything. Remove the local scratch files too —
`params.json` carries the registry password.

```sh
az group delete -n "$RG" --yes --no-wait
rm -f params.json template.json
```

To pause instead of delete (keeping the registry and the policy-bound
deployment for another session):

```sh
az container stop -g "$RG" -n solpbc
az container start -g "$RG" -n solpbc
```

In the TEE, fetch a report binding a verifier-issued nonce into `REPORT_DATA`:

```sh
python3 /app/fetch-report.py --nonce-hex <verifier-nonce> --out /tmp/report.bin
```

(The image also fetches one automatically at startup with a random nonce —
visible in `az container logs` — unless the template's `command` override is
in effect. `snpguest` in this image is the default build, i.e. the native
`/dev/sev-guest` path, not the CVM image's `hyperv` build.)

Certificates cannot be fetched from inside the TEE (verified 2026-07-04: the
AKS-style THIM IMDS endpoint doesn't exist on ACI, and the host declines
`SNP_GET_EXT_REPORT`, so `snpguest certificates` fails). Fetch the VCEK
out-of-band instead, using `CHIP_ID` plus the reported-TCB SPLs printed by
`fetch-report.py` / readable at report offset `0x180` (bytes 1, 2, 7, 8 =
bl, tee, snp, ucode). ACI hardware observed so far is **Genoa**, so the
product string is `Genoa` and the chain pins to `roots/amd/Genoa`:

```sh
curl -sf -o vcek.der "https://kdsintf.amd.com/vcek/v1/Genoa/$CHIP_ID?blSPL=10&teeSPL=0&snpSPL=23&ucodeSPL=84"
openssl x509 -inform der -in vcek.der -out certs/vcek.pem
```

Microsoft's public cert cache serves the same AMD-signed certificates without
KDS rate limits (`https://americas.acccache.azure.net/vcek/v1/...`, same URL
shape) — a CDN for AMD's signatures, not a trust anchor.

Off-TEE, appraise with the raw-report mode:

```bash
python3 verifier.py appraise-raw <bundle-dir> \
  --roots roots/amd \
  --cce-policy-file <base64-policy-from-template> \
  --nonce-hex <verifier-nonce>
```

where `<bundle-dir>` holds `report.bin` and `certs/` with the VCEK PEM.
`appraise-raw` verifies the AMD chain and report signature against the pinned
roots, SNP policy (VMPL, debug), the nonce in `REPORT_DATA`, and `HOST_DATA`
against the CCE policy hash (`--host-data <hex>` works too, and
`--measurement` pins the UVM launch measurement once reference values are
established).

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

### Off-CVM Python verifier (`verifier.py`)

`verifier.py` is the owner-side verifier spike: it runs off the CVM, issues the
nonce, validates the bundle against pinned AMD roots in `roots/amd/`, checks the
AMD report/runtime/AK/TPM-quote bindings, applies TCB + PCR policy, and releases
a secret with X25519 -> HKDF -> AES-256-GCM. See
[`docs/off-cvm-python-verifier.md`](docs/off-cvm-python-verifier.md) for the
bundle contract, commands, policy JSON, and the explicit record-then-pin PCR
reference-values gap.

For raw (non-HCLA) reports — the [ACI Confidential Containers
path](#running-on-aci-confidential-containers-no-vtpm) — use
`verifier.py appraise-raw`, which drops the HCLA/AK/quote checks and instead
binds freshness via `REPORT_DATA` and the CCE policy via `HOST_DATA`.

Hardware-free coverage:

```bash
python3 -m pip install -r requirements.txt
./test/python-verifier-selftest.py
```

## Prerequisites

- Azure DCasv5/ECasv5 (or newer) Confidential VM with vTPM enabled, provisioned
  from a Confidential-Compute host image (Ubuntu 24.04 LTS, AMD64 Gen2):
  - `Canonical:ubuntu-24_04-lts:cvm:latest` — free
  - `Canonical:ubuntu-24_04-lts:ubuntu-pro-cvm:latest` — Ubuntu Pro (ongoing patching)
- `tpm2-tools`, `openssl`, `xxd`, `jq` (provided by the container; see `Containerfile`)
- Rust toolchain (for `snpguest` with `--features hyperv`)
- Python 3 with `cryptography` for `verifier.py` (`make install` installs the
  pinned Python dependency range)

## References

- [VirTEE snpguest](https://github.com/virtee/snpguest)
- [az-snp-vtpm / azure-cvm-tooling](https://docs.rs/az-snp-vtpm)
- [OpenHCL / OpenVMM](https://openvmm.dev)
- [AMD SEV-SNP firmware ABI spec](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf)
- [IETF RATS RFC 9334](https://www.rfc-editor.org/rfc/rfc9334)
