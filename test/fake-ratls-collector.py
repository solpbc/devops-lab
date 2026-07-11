#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Deterministic no-hardware collector for gateway protocol tests."""

from __future__ import annotations

import base64
import hashlib
import json
import sys


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def main() -> int:
    request = json.load(sys.stdin)
    operation = request["operation"]
    if operation == "certificate-evidence-v1":
        nonce = base64.b64decode(request["owner_nonce_b64"])
        spki = base64.b64decode(request["tls_spki_der_b64"])
        gpu = b"SPPGPU1\x00" + b"test-gpu-evidence"
        qualifying = hashlib.sha256(
            request["binding_domain"].encode()
            + nonce
            + hashlib.sha256(spki).digest()
            + hashlib.sha256(gpu).digest()
        ).hexdigest()
        fields = {
            "owner_nonce_b64": b64(nonce),
            "tls_spki_der_b64": b64(spki),
            "amd_report_b64": b64(b"amd-report"),
            "hcl_report_b64": b64(b"hcl-report"),
            "ak_public_key_pem_b64": b64(b"ak-pem"),
            "quote_message_b64": b64(b"certificate-quote-message"),
            "quote_signature_b64": b64(b"certificate-quote-signature"),
            "quote_pcrs_b64": b64(b"certificate-pcrs"),
            "amd_ark_pem_b64": b64(b"ark-pem"),
            "amd_ask_pem_b64": b64(b"ask-pem"),
            "amd_vcek_pem_b64": b64(b"vcek-pem"),
            "gpu_envelope_b64": b64(gpu),
            "qualifying_data_hex": qualifying,
        }
    elif operation == "exporter-proof-v1":
        fields = {
            "quote_message_b64": b64(b"exporter-quote-message"),
            "quote_signature_b64": b64(b"exporter-quote-signature"),
            "quote_pcrs_b64": b64(b"exporter-pcrs"),
            "qualifying_data_hex": request["qualifying_data_hex"],
        }
    else:
        raise ValueError(f"unknown operation {operation!r}")
    print(json.dumps(fields, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
