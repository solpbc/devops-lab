#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""SPP RA-TLS v1 wire-contract constants and minimal DER codec.

This module is the code source of truth for the engine-side contract.  The
checked-in ``ratls-contract.json`` artifact is generated from these constants
with ``python3 ratls_contract.py generate``.  Consumers must read that artifact
or port this codec; they must not re-type identifiers from prose.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Final


PREFACE_MAGIC: Final = b"SPPRAT1\x00"
OWNER_NONCE_BYTES: Final = 32
EXPORTER_BYTES: Final = 32
# UUIDv5 dd12d0b5-d2b9-567d-8182-5e68403c1712 split into uint32 arcs.
# cryptography's OID parser caps each arc at uint32, so the standard single
# 128-bit 2.25 UUID integer cannot be represented by our shared parser.
COMPOSITE_EVIDENCE_OID: Final = (
    "2.25.3708997813.3535365757.2172800616.1077671698"
)
EXPORTER_LABEL: Final = b"EXPERIMENTAL-sol-spp-engine-attestation-v1"
EXPORTER_CONTEXT_DOMAIN: Final = b"sol-spp-ratls-exporter-context-v1"
CERTIFICATE_BINDING_DOMAIN: Final = b"sol-spp-ratls-certificate-bind-v1"
EXPORTER_BINDING_DOMAIN: Final = b"sol-spp-ratls-exporter-bind-v1"
EXPORTER_PROOF_PATH: Final = "/._sol/spp/exporter-proof"
COMPOSITE_MEDIA_TYPE: Final = "application/vnd.sol.spp-composite-evidence-v1+der"
EXPORTER_PROOF_MEDIA_TYPE: Final = "application/vnd.sol.spp-exporter-proof-v1+der"
PROTOCOL_VERSION: Final = 1


COMPOSITE_FIELDS: Final = (
    "version",
    "owner_nonce",
    "tls_spki_der",
    "amd_report",
    "hcl_report",
    "ak_public_key_pem",
    "quote_message",
    "quote_signature",
    "quote_pcrs",
    "amd_ark_pem",
    "amd_ask_pem",
    "amd_vcek_pem",
    "gpu_envelope",
)
EXPORTER_PROOF_FIELDS: Final = (
    "version",
    "owner_nonce",
    "tls_spki_der",
    "tls_exporter",
    "quote_message",
    "quote_signature",
    "quote_pcrs",
)


def _der_length(length: int) -> bytes:
    if length < 0:
        raise ValueError("DER length must be non-negative")
    if length < 128:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(value)) + value


def _der_integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("only non-negative DER integers are supported")
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return _der_tlv(0x02, encoded)


def _der_octets(value: bytes) -> bytes:
    return _der_tlv(0x04, value)


def _der_sequence(parts: list[bytes]) -> bytes:
    return _der_tlv(0x30, b"".join(parts))


def encode_sequence(version: int, fields: list[bytes]) -> bytes:
    """Encode a fixed-order DER sequence containing one integer and octets."""

    return _der_sequence([_der_integer(version), *(_der_octets(item) for item in fields)])


def _read_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("truncated DER length")
    first = data[offset]
    offset += 1
    if first < 128:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 4 or offset + count > len(data):
        raise ValueError("invalid DER length")
    encoded = data[offset : offset + count]
    if encoded[0] == 0:
        raise ValueError("non-minimal DER length")
    length = int.from_bytes(encoded, "big")
    if length < 128:
        raise ValueError("non-minimal DER length")
    return length, offset + count


def _read_tlv(data: bytes, offset: int, expected_tag: int) -> tuple[bytes, int]:
    if offset >= len(data) or data[offset] != expected_tag:
        raise ValueError(f"expected DER tag 0x{expected_tag:02x}")
    length, value_offset = _read_length(data, offset + 1)
    end = value_offset + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return data[value_offset:end], end


def decode_sequence(data: bytes, octet_count: int) -> tuple[int, list[bytes]]:
    """Strictly decode the fixed sequence used by both SPP v1 envelopes."""

    body, end = _read_tlv(data, 0, 0x30)
    if end != len(data):
        raise ValueError("trailing bytes after DER sequence")
    integer, offset = _read_tlv(body, 0, 0x02)
    if not integer or (len(integer) > 1 and integer[0] == 0 and integer[1] < 0x80):
        raise ValueError("non-minimal DER integer")
    version = int.from_bytes(integer, "big")
    fields: list[bytes] = []
    for _ in range(octet_count):
        value, offset = _read_tlv(body, offset, 0x04)
        fields.append(value)
    if offset != len(body):
        raise ValueError("unexpected field in DER sequence")
    return version, fields


@dataclass(frozen=True)
class CompositeEvidence:
    owner_nonce: bytes
    tls_spki_der: bytes
    amd_report: bytes
    hcl_report: bytes
    ak_public_key_pem: bytes
    quote_message: bytes
    quote_signature: bytes
    quote_pcrs: bytes
    amd_ark_pem: bytes
    amd_ask_pem: bytes
    amd_vcek_pem: bytes
    gpu_envelope: bytes

    def to_der(self) -> bytes:
        return encode_sequence(PROTOCOL_VERSION, list(self.__dict__.values()))

    @classmethod
    def from_der(cls, data: bytes) -> "CompositeEvidence":
        version, fields = decode_sequence(data, len(COMPOSITE_FIELDS) - 1)
        if version != PROTOCOL_VERSION:
            raise ValueError(f"unsupported composite evidence version {version}")
        return cls(*fields)


@dataclass(frozen=True)
class ExporterProof:
    owner_nonce: bytes
    tls_spki_der: bytes
    tls_exporter: bytes
    quote_message: bytes
    quote_signature: bytes
    quote_pcrs: bytes

    def to_der(self) -> bytes:
        return encode_sequence(PROTOCOL_VERSION, list(self.__dict__.values()))

    @classmethod
    def from_der(cls, data: bytes) -> "ExporterProof":
        version, fields = decode_sequence(data, len(EXPORTER_PROOF_FIELDS) - 1)
        if version != PROTOCOL_VERSION:
            raise ValueError(f"unsupported exporter proof version {version}")
        return cls(*fields)


def contract_artifact() -> dict[str, object]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "preface": {"magic_ascii_nul": "SPPRAT1", "owner_nonce_bytes": OWNER_NONCE_BYTES},
        "x509_extension": {
            "oid": COMPOSITE_EVIDENCE_OID,
            "critical": True,
            "encoding": "DER",
            "fields": list(COMPOSITE_FIELDS),
            "media_type": COMPOSITE_MEDIA_TYPE,
        },
        "exporter": {
            "label": EXPORTER_LABEL.decode("ascii"),
            "context_domain": EXPORTER_CONTEXT_DOMAIN.decode("ascii"),
            "length": EXPORTER_BYTES,
            "proof_path": EXPORTER_PROOF_PATH,
            "proof_encoding": "DER",
            "proof_fields": list(EXPORTER_PROOF_FIELDS),
            "proof_media_type": EXPORTER_PROOF_MEDIA_TYPE,
        },
        "binding": {
            "certificate_domain": CERTIFICATE_BINDING_DOMAIN.decode("ascii"),
            "certificate_formula": "SHA256(domain || nonce || SHA256(tls_spki_der) || SHA256(SPPGPU1_TLV))",
            "exporter_domain": EXPORTER_BINDING_DOMAIN.decode("ascii"),
            "exporter_formula": "SHA256(domain || nonce || SHA256(tls_spki_der) || tls_exporter || SHA256(SPPGPU1_TLV))",
            "exporter_context_formula": "SHA256(context_domain || nonce || SHA256(tls_spki_der))",
        },
        "ingress_gate": "No credential or inference bytes are admitted until the certificate evidence and exporter proof both verify.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("generate", "check"))
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("ratls-contract.json"))
    args = parser.parse_args()
    rendered = json.dumps(contract_artifact(), indent=2, sort_keys=True) + "\n"
    if args.command == "generate":
        args.output.write_text(rendered)
        return 0
    if not args.output.exists() or args.output.read_text() != rendered:
        raise SystemExit(f"{args.output} is stale; run: python3 ratls_contract.py generate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
