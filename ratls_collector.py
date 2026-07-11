#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Live CVM evidence collector for ``ratls_gateway.py``.

Reads one gateway collector request from stdin and writes one JSON response to
stdout.  It must run inside the Azure H100 CVM with the vTPM, ``snpguest``,
``tpm2-tools``, ``nvidia-smi``, and Azure confidential-GPU onboarding stack.
Set ``SPP_NVIDIA_VERIFIER_SRC`` to the onboarding package directory containing
the ``verifier`` Python package.

Diagnostics go to stderr.  Evidence goes only to the gateway over stdout and
is held in an ephemeral temporary directory.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from ratls_contract import (
    CERTIFICATE_BINDING_DOMAIN,
    EXPORTER_BINDING_DOMAIN,
    OWNER_NONCE_BYTES,
)


GPU_ENVELOPE_MAGIC = b"SPPGPU1\x00"
AK_HANDLE = os.environ.get("SPP_AK_HANDLE", "0x81000003")
HCL_NV_INDEX = os.environ.get("SPP_HCL_NV_INDEX", "0x01400001")
PCR_LIST = os.environ.get("SPP_PCR_LIST", "sha256:0,2,4,7,8,9,15,16,22,23")
COMMAND_TIMEOUT = int(os.environ.get("SPP_COLLECT_COMMAND_TIMEOUT", "120"))


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: object, name: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be base64 text")
    return base64.b64decode(value, validate=True)


def _run(*command: str) -> bytes:
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=COMMAND_TIMEOUT,
        check=False,
    )
    if completed.returncode != 0:
        cause = completed.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"{' '.join(command)} failed ({completed.returncode}): {cause}")
    return completed.stdout


def _require_cc_production() -> None:
    state = _run("nvidia-smi", "conf-compute", "-f").decode("utf-8", "replace")
    environment = _run("nvidia-smi", "conf-compute", "-e").decode(
        "utf-8", "replace"
    )
    if "CC status: ON" not in state or "CC Environment: PRODUCTION" not in environment:
        raise RuntimeError("GPU is not in CC ON / PRODUCTION mode")


def _vendor_import() -> tuple[Any, Any]:
    vendor_src = os.environ.get("SPP_NVIDIA_VERIFIER_SRC")
    if not vendor_src:
        raise RuntimeError("SPP_NVIDIA_VERIFIER_SRC is required")
    sys.path.insert(0, vendor_src)
    verifier = importlib.import_module("verifier")
    chains = importlib.import_module("verifier.nvml.gpu_cert_chains")
    return verifier.cc_admin, chains.GpuCertificateChains


def _gpu_tlv(owner_nonce: bytes) -> bytes:
    cc_admin, certificate_chains = _vendor_import()
    with contextlib.redirect_stdout(sys.stderr):
        evidence = cc_admin.collect_gpu_evidence(owner_nonce.hex(), no_gpu_mode=False)
    if len(evidence) != 1:
        raise RuntimeError(f"expected exactly one local GPU, found {len(evidence)}")
    gpu = evidence[0]
    fields = (
        (1, owner_nonce),
        (2, gpu.get_attestation_report()),
        (
            3,
            base64.b64decode(
                certificate_chains.extract_gpu_cert_chain_base64(
                    gpu.get_attestation_cert_chain()
                )
            ),
        ),
        (4, gpu.get_driver_version().encode("utf-8")),
        (5, gpu.get_vbios_version().encode("utf-8")),
        (6, str(gpu.get_uuid()).encode("utf-8")),
        (7, gpu.get_gpu_architecture().encode("utf-8")),
    )
    return GPU_ENVELOPE_MAGIC + struct.pack(">H", len(fields)) + b"".join(
        struct.pack(">HI", field_id, len(value)) + value
        for field_id, value in fields
    )


def _quote(directory: Path, qualifying_data: bytes) -> dict[str, str]:
    ak_public = directory / "akpub.pem"
    quote_message = directory / "quote.msg"
    quote_signature = directory / "quote.sig"
    quote_pcrs = directory / "quote.pcrs"
    _run("tpm2_readpublic", "-c", AK_HANDLE, "-f", "pem", "-o", str(ak_public))
    _run(
        "tpm2_quote",
        "-c",
        AK_HANDLE,
        "-l",
        PCR_LIST,
        "-q",
        qualifying_data.hex(),
        "-m",
        str(quote_message),
        "-s",
        str(quote_signature),
        "-o",
        str(quote_pcrs),
        "-g",
        "sha256",
    )
    _run(
        "tpm2_checkquote",
        "-u",
        str(ak_public),
        "-m",
        str(quote_message),
        "-s",
        str(quote_signature),
        "-f",
        str(quote_pcrs),
        "-g",
        "sha256",
        "-q",
        qualifying_data.hex(),
    )
    return {
        "ak_public_key_pem_b64": _b64(ak_public.read_bytes()),
        "quote_message_b64": _b64(quote_message.read_bytes()),
        "quote_signature_b64": _b64(quote_signature.read_bytes()),
        "quote_pcrs_b64": _b64(quote_pcrs.read_bytes()),
        "qualifying_data_hex": qualifying_data.hex(),
    }


def _certificate_evidence(request: dict[str, Any]) -> dict[str, str]:
    if request.get("binding_domain") != CERTIFICATE_BINDING_DOMAIN.decode("ascii"):
        raise ValueError("wrong certificate binding domain")
    owner_nonce = _decode(request.get("owner_nonce_b64"), "owner_nonce_b64")
    if len(owner_nonce) != OWNER_NONCE_BYTES:
        raise ValueError("owner nonce must be exactly 32 bytes")
    spki_der = _decode(request.get("tls_spki_der_b64"), "tls_spki_der_b64")
    _require_cc_production()
    gpu_envelope = _gpu_tlv(owner_nonce)
    qualifying_data = hashlib.sha256(
        CERTIFICATE_BINDING_DOMAIN
        + owner_nonce
        + hashlib.sha256(spki_der).digest()
        + hashlib.sha256(gpu_envelope).digest()
    ).digest()

    with tempfile.TemporaryDirectory(prefix="spp-ratls-") as temp:
        directory = Path(temp)
        report = directory / "report.bin"
        request_file = directory / "request.bin"
        hcl_report = directory / "hcl_report.bin"
        certs = directory / "certs"
        certs.mkdir()
        _run("snpguest", "report", "--platform", str(report), str(request_file))
        _run("snpguest", "fetch", "ca", "pem", str(certs), "--report", str(report))
        _run("snpguest", "fetch", "vcek", "pem", str(certs), str(report))
        _run("snpguest", "verify", "certs", str(certs))
        _run("snpguest", "verify", "attestation", str(certs), str(report))
        _run("tpm2_nvread", "-C", "o", HCL_NV_INDEX, "-o", str(hcl_report))
        quote = _quote(directory, qualifying_data)
        return {
            "owner_nonce_b64": _b64(owner_nonce),
            "tls_spki_der_b64": _b64(spki_der),
            "amd_report_b64": _b64(report.read_bytes()),
            "hcl_report_b64": _b64(hcl_report.read_bytes()),
            "amd_ark_pem_b64": _b64((certs / "ark.pem").read_bytes()),
            "amd_ask_pem_b64": _b64((certs / "ask.pem").read_bytes()),
            "amd_vcek_pem_b64": _b64((certs / "vcek.pem").read_bytes()),
            "gpu_envelope_b64": _b64(gpu_envelope),
            **quote,
        }


def _exporter_proof(request: dict[str, Any]) -> dict[str, str]:
    if request.get("binding_domain") != EXPORTER_BINDING_DOMAIN.decode("ascii"):
        raise ValueError("wrong exporter binding domain")
    qualifying_hex = request.get("qualifying_data_hex")
    if not isinstance(qualifying_hex, str):
        raise ValueError("qualifying_data_hex is required")
    qualifying_data = bytes.fromhex(qualifying_hex)
    if len(qualifying_data) != 32:
        raise ValueError("exporter qualifying data must be exactly 32 bytes")
    with tempfile.TemporaryDirectory(prefix="spp-ratls-exporter-") as temp:
        quote = _quote(Path(temp), qualifying_data)
    return {
        "quote_message_b64": quote["quote_message_b64"],
        "quote_signature_b64": quote["quote_signature_b64"],
        "quote_pcrs_b64": quote["quote_pcrs_b64"],
        "qualifying_data_hex": quote["qualifying_data_hex"],
    }


def main() -> int:
    try:
        request = json.load(sys.stdin)
        if not isinstance(request, dict):
            raise ValueError("collector request must be an object")
        operation = request.get("operation")
        if operation == "certificate-evidence-v1":
            response = _certificate_evidence(request)
        elif operation == "exporter-proof-v1":
            response = _exporter_proof(request)
        else:
            raise ValueError(f"unsupported collector operation {operation!r}")
        print(json.dumps(response, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as exc:
        print(f"collector failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
