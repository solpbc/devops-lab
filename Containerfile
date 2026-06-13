# solpbc — AMD SEV-SNP attestation tooling for Azure Confidential VMs
#
# Two-stage build:
#   1. builder  — compiles `snpguest` from source with the `hyperv` feature,
#                 which is required on Azure CVMs (the report is read from the
#                 vTPM NV index via `--platform`, not /dev/sev-guest).
#   2. runtime  — slim Ubuntu 24.04 LTS image with the attestation toolchain.
#
# The container runs ON the Confidential VM and talks to the vTPM device, so
# the host must pass through the TPM, e.g.:
#   podman build -t solpbc .
#   podman run --rm --device /dev/tpmrm0 solpbc
#
# HOST IMAGE (the Azure CVM this container is meant to run on)
# ------------------------------------------------------------
# The Azure SEV-SNP customizations (CVM kernel, paravisor/OpenHCL, vTPM
# provisioning, measured boot) live in the HOST VM image, not in this
# container. Azure marketplace images are VHDs, not OCI images, so they
# cannot be used as a `FROM` base. Provision the VM from one of these
# Confidential-Compute URNs (Ubuntu 24.04 LTS, Noble Numbat, AMD64 Gen2):
#   Canonical:ubuntu-24_04-lts:cvm:latest             # free
#   Canonical:ubuntu-24_04-lts:ubuntu-pro-cvm:latest  # Ubuntu Pro (ongoing patching)
# The container base below stays on Canonical's official `ubuntu:24.04`
# OCI image, which tracks the same Noble package set.

# ---------------------------------------------------------------------------
# Stage 1: build snpguest (with the hyperv/Azure feature)
# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
ARG SNPGUEST_REF=main

# Build dependencies: Rust toolchain via rustup, plus headers the `sev`
# crate needs to link against OpenSSL and TPM2 libraries.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        build-essential \
        pkg-config \
        libssl-dev \
        libtss2-dev \
    && rm -rf /var/lib/apt/lists/*

# Pin a recent stable Rust toolchain.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

# Build snpguest with the hyperv feature (Azure vTPM report path).
RUN git clone --depth 1 --branch "${SNPGUEST_REF}" \
        https://github.com/virtee/snpguest.git /src/snpguest \
    && cd /src/snpguest \
    && cargo build --release --features hyperv \
    && install -Dm0755 target/release/snpguest /out/snpguest

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM ubuntu:24.04

LABEL org.opencontainers.image.title="solpbc" \
      org.opencontainers.image.description="AMD SEV-SNP attestation tooling for Azure Confidential VMs (no MAA dependency)" \
      org.opencontainers.image.source="https://github.com/solpbc/devops-lab"

ENV DEBIAN_FRONTEND=noninteractive

# Runtime toolchain documented in the README:
#   tpm2-tools  — read the HCL blob / quote from the vTPM
#   openssl     — verify the AMD VCEK/VLEK certificate chain
#   xxd, jq     — parse the binary report and HCL runtime data
#   curl        — fetch VCEK/VLEK and CA certs from the AMD KDS
RUN apt-get update && apt-get install -y --no-install-recommends \
        tpm2-tools \
        openssl \
        xxd \
        jq \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# snpguest built with the hyperv feature.
COPY --from=builder /out/snpguest /usr/local/bin/snpguest

WORKDIR /app
COPY run.sh /app/run.sh
RUN chmod +x /app/run.sh

ENTRYPOINT ["/app/run.sh"]
