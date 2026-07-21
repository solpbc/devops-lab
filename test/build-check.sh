#!/usr/bin/env bash
#
# build-check.sh — repeatable test harness for the solpbc Containerfile.
#
# Runs the tiers that DON'T need SEV-SNP hardware:
#   Tier 0  lint      — static Containerfile lint (hadolint, if available)
#   Tier 1  build     — build the image (proves apt deps + snpguest compile)
#   Tier 2  smoke     — run snpguest --help to confirm the hyperv build works
#   Tier 3  selftest  — exercise the HCLA/freshness logic (lib/hcl.sh) on a
#                       synthetic fixture; no TPM required
#
# The full attestation path (Tier 4) requires a live Azure SEV-SNP CVM with a
# vTPM and is intentionally NOT covered here.
#
# Usage:
#   test/build-check.sh [lint|build|smoke|selftest|all]   (default: all)
#
# Notes:
#   * Requires an x86_64 host — the sev/snpguest crates target AMD x86.
#     On arm64 (e.g. Apple Silicon) set CONTAINER_BUILD_ARGS to force amd64:
#       CONTAINER_BUILD_ARGS="--platform linux/amd64" test/build-check.sh
#   * Uses podman if present, else docker.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTAINERFILE="${REPO_ROOT}/Containerfile"
IMAGE="${IMAGE:-solpbc:test}"
CONTAINER_BUILD_ARGS="${CONTAINER_BUILD_ARGS:-}"
STAGE="${1:-all}"

# --- pick a container engine -------------------------------------------------
ENGINE=""
for e in podman docker; do
  if command -v "$e" >/dev/null 2>&1; then ENGINE="$e"; break; fi
done

log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[skip] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m[fail] %s\033[0m\n' "$*" >&2; exit 1; }

# --- Tier 0: lint ------------------------------------------------------------
run_lint() {
  log "Tier 0: lint"
  if command -v hadolint >/dev/null 2>&1; then
    # hadolint exits non-zero on warnings; treat warnings as non-fatal so the
    # build/smoke tiers still run. Use --failure-threshold to gate on errors.
    if hadolint --failure-threshold error "$CONTAINERFILE"; then
      echo "hadolint: no errors (warnings, if any, shown above)"
    else
      die "hadolint reported error-level issues"
    fi
  else
    warn "hadolint not installed — skipping static lint"
    warn "install: https://github.com/hadolint/hadolint/releases"
  fi
}

# --- Tier 1: build -----------------------------------------------------------
run_build() {
  log "Tier 1: build image ($IMAGE)"
  [ -n "$ENGINE" ] || die "no container engine (podman/docker) found"
  # shellcheck disable=SC2086
  "$ENGINE" build $CONTAINER_BUILD_ARGS -t "$IMAGE" -f "$CONTAINERFILE" "$REPO_ROOT"
  echo "build: ok"
}

# --- Tier 2: smoke -----------------------------------------------------------
run_smoke() {
  log "Tier 2: smoke-test snpguest binary"
  [ -n "$ENGINE" ] || die "no container engine (podman/docker) found"
  "$ENGINE" run --rm --entrypoint snpguest "$IMAGE" --help >/dev/null \
    && echo "snpguest --help: ok"
  # The hyperv feature adds the vTPM/platform report path; surface it.
  "$ENGINE" run --rm --entrypoint snpguest "$IMAGE" report --help 2>/dev/null \
    | grep -i -- "--platform\|vtpm\|hyperv" \
    && echo "hyperv report path: present" \
    || warn "could not confirm --platform flag (check snpguest version)"
}

# --- Tier 3: selftest --------------------------------------------------------
run_selftest() {
  PATH="${REPO_ROOT}/test/bin:${PATH}"
  log "Tier 3: HCLA/freshness self-test (no hardware)"
  bash "${REPO_ROOT}/test/freshness-selftest.sh"
  log "Tier 3: toy-verifier self-test (no hardware)"
  bash "${REPO_ROOT}/test/verifier-selftest.sh"
  log "Tier 3: off-CVM Python verifier self-test (no hardware)"
  python3 "${REPO_ROOT}/test/python-verifier-selftest.py"
}

case "$STAGE" in
  lint)     run_lint ;;
  build)    run_build ;;
  smoke)    run_smoke ;;
  selftest) run_selftest ;;
  all)      run_lint; run_build; run_smoke; run_selftest ;;
  *)        die "unknown stage '$STAGE' (use: lint|build|smoke|selftest|all)" ;;
esac

log "done"
