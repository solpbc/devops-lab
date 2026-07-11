#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Fail-closed SPP engine RA-TLS gateway.

The client sends a bounded nonce preface, verifies the per-session certificate
evidence during the TLS 1.3 handshake, then verifies an exporter-bound AK quote
at the reserved proof endpoint.  Only after both phases does this process turn
the connection into an opaque byte tunnel to loopback SGLang.  It never logs or
parses inference request/response bodies.

The external collector command reads one JSON object on stdin and writes one
JSON object on stdout.  It owns hardware-specific evidence collection; this
gateway owns the TLS key, framing, binding values, admission gate, and proxy.
Run with ``--print-collector-contract`` for the exact operation schemas.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import selectors
import shlex
import socket
import socketserver
import subprocess
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier
from OpenSSL import SSL, crypto

from ratls_contract import (
    CERTIFICATE_BINDING_DOMAIN,
    COMPOSITE_EVIDENCE_OID,
    EXPORTER_BINDING_DOMAIN,
    EXPORTER_BYTES,
    EXPORTER_CONTEXT_DOMAIN,
    EXPORTER_LABEL,
    EXPORTER_PROOF_MEDIA_TYPE,
    EXPORTER_PROOF_PATH,
    OWNER_NONCE_BYTES,
    PREFACE_MAGIC,
    CompositeEvidence,
    ExporterProof,
)


LOG = logging.getLogger("spp-ratls-gateway")
MAX_PROOF_REQUEST_BYTES = 16 * 1024
MAX_COLLECTOR_OUTPUT_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 180


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(payload: dict[str, Any], key: str) -> bytes:
    value = payload.get(key)
    if not isinstance(value, str):
        raise ValueError(f"collector response field {key!r} must be base64 text")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(f"collector response field {key!r} is invalid base64") from exc


def certificate_binding(owner_nonce: bytes, spki_der: bytes, gpu_envelope: bytes) -> bytes:
    return hashlib.sha256(
        CERTIFICATE_BINDING_DOMAIN
        + owner_nonce
        + hashlib.sha256(spki_der).digest()
        + hashlib.sha256(gpu_envelope).digest()
    ).digest()


def exporter_context(owner_nonce: bytes, spki_der: bytes) -> bytes:
    return hashlib.sha256(
        EXPORTER_CONTEXT_DOMAIN + owner_nonce + hashlib.sha256(spki_der).digest()
    ).digest()


def exporter_binding(
    owner_nonce: bytes, spki_der: bytes, tls_exporter: bytes, gpu_envelope: bytes
) -> bytes:
    return hashlib.sha256(
        EXPORTER_BINDING_DOMAIN
        + owner_nonce
        + hashlib.sha256(spki_der).digest()
        + tls_exporter
        + hashlib.sha256(gpu_envelope).digest()
    ).digest()


class CommandCollector:
    def __init__(self, command: list[str], timeout: int) -> None:
        if not command:
            raise ValueError("collector command is required")
        self.command = command
        self.timeout = timeout

    def call(self, request: dict[str, object]) -> dict[str, Any]:
        completed = subprocess.run(
            self.command,
            input=(json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=self.timeout,
            check=False,
        )
        if completed.returncode != 0:
            cause = completed.stderr.decode("utf-8", "replace").strip()
            raise RuntimeError(
                f"attestation collector failed with exit {completed.returncode}: {cause}"
            )
        if len(completed.stdout) > MAX_COLLECTOR_OUTPUT_BYTES:
            raise RuntimeError("attestation collector output exceeds limit")
        try:
            response = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("attestation collector returned invalid JSON") from exc
        if not isinstance(response, dict):
            raise RuntimeError("attestation collector response must be an object")
        return response

    def collect_composite(self, owner_nonce: bytes, spki_der: bytes) -> CompositeEvidence:
        response = self.call(
            {
                "operation": "certificate-evidence-v1",
                "owner_nonce_b64": _b64(owner_nonce),
                "tls_spki_der_b64": _b64(spki_der),
                "binding_domain": CERTIFICATE_BINDING_DOMAIN.decode("ascii"),
                "binding_formula": "SHA256(domain || nonce || SHA256(tls_spki_der) || SHA256(SPPGPU1_TLV))",
            }
        )
        evidence = CompositeEvidence(
            owner_nonce=_unb64(response, "owner_nonce_b64"),
            tls_spki_der=_unb64(response, "tls_spki_der_b64"),
            amd_report=_unb64(response, "amd_report_b64"),
            hcl_report=_unb64(response, "hcl_report_b64"),
            ak_public_key_pem=_unb64(response, "ak_public_key_pem_b64"),
            quote_message=_unb64(response, "quote_message_b64"),
            quote_signature=_unb64(response, "quote_signature_b64"),
            quote_pcrs=_unb64(response, "quote_pcrs_b64"),
            amd_ark_pem=_unb64(response, "amd_ark_pem_b64"),
            amd_ask_pem=_unb64(response, "amd_ask_pem_b64"),
            amd_vcek_pem=_unb64(response, "amd_vcek_pem_b64"),
            gpu_envelope=_unb64(response, "gpu_envelope_b64"),
        )
        if evidence.owner_nonce != owner_nonce:
            raise RuntimeError("collector echoed a different owner nonce")
        if evidence.tls_spki_der != spki_der:
            raise RuntimeError("collector echoed a different TLS SPKI")
        expected = certificate_binding(owner_nonce, spki_der, evidence.gpu_envelope)
        if response.get("qualifying_data_hex") != expected.hex():
            raise RuntimeError("collector certificate quote used the wrong qualifying data")
        return evidence

    def collect_exporter_proof(
        self,
        owner_nonce: bytes,
        spki_der: bytes,
        tls_exporter: bytes,
        gpu_envelope: bytes,
    ) -> ExporterProof:
        qualifying_data = exporter_binding(
            owner_nonce, spki_der, tls_exporter, gpu_envelope
        )
        response = self.call(
            {
                "operation": "exporter-proof-v1",
                "owner_nonce_b64": _b64(owner_nonce),
                "tls_spki_der_b64": _b64(spki_der),
                "tls_exporter_b64": _b64(tls_exporter),
                "gpu_envelope_sha256": hashlib.sha256(gpu_envelope).hexdigest(),
                "qualifying_data_hex": qualifying_data.hex(),
                "binding_domain": EXPORTER_BINDING_DOMAIN.decode("ascii"),
                "binding_formula": "SHA256(domain || nonce || SHA256(tls_spki_der) || tls_exporter || SHA256(SPPGPU1_TLV))",
            }
        )
        if response.get("qualifying_data_hex") != qualifying_data.hex():
            raise RuntimeError("collector exporter quote used the wrong qualifying data")
        return ExporterProof(
            owner_nonce=owner_nonce,
            tls_spki_der=spki_der,
            tls_exporter=tls_exporter,
            quote_message=_unb64(response, "quote_message_b64"),
            quote_signature=_unb64(response, "quote_signature_b64"),
            quote_pcrs=_unb64(response, "quote_pcrs_b64"),
        )


def _make_certificate(
    key: ec.EllipticCurvePrivateKey, extension_der: bytes
) -> x509.Certificate:
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "spp-engine")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=10))
        .add_extension(
            x509.UnrecognizedExtension(
                ObjectIdentifier(COMPOSITE_EVIDENCE_OID), extension_der
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )


def _tls_context(
    key: ec.EllipticCurvePrivateKey, certificate: x509.Certificate
) -> SSL.Context:
    context = SSL.Context(SSL.TLS_SERVER_METHOD)
    context.set_min_proto_version(SSL.TLS1_3_VERSION)
    context.set_max_proto_version(SSL.TLS1_3_VERSION)
    context.set_options(SSL.OP_NO_TICKET)
    context.use_privatekey(crypto.PKey.from_cryptography_key(key))
    context.use_certificate(crypto.X509.from_cryptography(certificate))
    context.check_privatekey()
    return context


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = sock.recv(length - len(chunks))
        if not chunk:
            raise ConnectionError("peer closed during RA-TLS preface")
        chunks.extend(chunk)
    return bytes(chunks)


def _recv_proof_request(connection: SSL.Connection) -> None:
    data = bytearray()
    marker = b"\r\n\r\n"
    while marker not in data:
        if len(data) >= MAX_PROOF_REQUEST_BYTES:
            raise ValueError("exporter-proof request headers exceed limit")
        chunk = connection.recv(min(4096, MAX_PROOF_REQUEST_BYTES - len(data)))
        if not chunk:
            raise ConnectionError("peer closed before exporter-proof request")
        data.extend(chunk)
    head, remainder = bytes(data).split(marker, 1)
    if remainder:
        raise ValueError("application bytes arrived before exporter proof completed")
    lines = head.split(b"\r\n")
    if not lines or lines[0] != f"GET {EXPORTER_PROOF_PATH} HTTP/1.1".encode("ascii"):
        raise ValueError("first TLS request must be the exporter-proof endpoint")
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if not separator:
            raise ValueError("malformed exporter-proof request header")
        if name.strip().lower() == b"content-length" and value.strip() != b"0":
            raise ValueError("exporter-proof request must not carry a body")


def _send_proof(connection: SSL.Connection, proof_der: bytes) -> None:
    response = (
        b"HTTP/1.1 200 OK\r\n"
        + f"Content-Type: {EXPORTER_PROOF_MEDIA_TYPE}\r\n".encode("ascii")
        + f"Content-Length: {len(proof_der)}\r\n".encode("ascii")
        + b"Cache-Control: no-store\r\nConnection: keep-alive\r\n\r\n"
        + proof_der
    )
    connection.sendall(response)


def _tunnel(client: SSL.Connection, upstream: socket.socket) -> None:
    selector = selectors.DefaultSelector()
    selector.register(client, selectors.EVENT_READ, (client, upstream))
    selector.register(upstream, selectors.EVENT_READ, (upstream, client))
    try:
        while True:
            events = selector.select(timeout=DEFAULT_TIMEOUT_SECONDS)
            if not events:
                raise TimeoutError("idle attested channel timed out")
            for key, _mask in events:
                source, destination = key.data
                try:
                    chunk = source.recv(65536)
                except (SSL.WantReadError, SSL.WantWriteError):
                    continue
                if not chunk:
                    return
                destination.sendall(chunk)
    finally:
        selector.close()


class GatewayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        collector: CommandCollector,
        upstream: tuple[str, int],
        socket_timeout: int,
    ) -> None:
        self.collector = collector
        self.upstream = upstream
        self.socket_timeout = socket_timeout
        super().__init__(address, GatewayHandler)


class GatewayHandler(socketserver.BaseRequestHandler):
    server: GatewayServer

    def handle(self) -> None:
        raw: socket.socket = self.request
        raw.settimeout(self.server.socket_timeout)
        connection: SSL.Connection | None = None
        try:
            preface = _recv_exact(raw, len(PREFACE_MAGIC) + OWNER_NONCE_BYTES)
            if preface[: len(PREFACE_MAGIC)] != PREFACE_MAGIC:
                raise ValueError("invalid RA-TLS preface magic")
            owner_nonce = preface[len(PREFACE_MAGIC) :]

            key = ec.generate_private_key(ec.SECP256R1())
            spki_der = key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            evidence = self.server.collector.collect_composite(owner_nonce, spki_der)
            certificate = _make_certificate(key, evidence.to_der())
            connection = SSL.Connection(_tls_context(key, certificate), raw)
            connection.setblocking(1)
            connection.set_accept_state()
            connection.do_handshake()

            context = exporter_context(owner_nonce, spki_der)
            tls_exporter = connection.export_keying_material(
                EXPORTER_LABEL, EXPORTER_BYTES, context
            )
            _recv_proof_request(connection)
            proof = self.server.collector.collect_exporter_proof(
                owner_nonce, spki_der, tls_exporter, evidence.gpu_envelope
            )
            _send_proof(connection, proof.to_der())

            with socket.create_connection(
                self.server.upstream, timeout=self.server.socket_timeout
            ) as upstream:
                upstream.settimeout(None)
                raw.settimeout(None)
                LOG.info("event=attested_channel_admitted")
                _tunnel(connection, upstream)
        except Exception as exc:
            LOG.warning("event=attested_channel_rejected cause=%s", str(exc))
        finally:
            if connection is not None:
                try:
                    connection.shutdown()
                except Exception:
                    pass
                connection.close()


COLLECTOR_CONTRACT = {
    "stdin": "one JSON object",
    "stdout": "one JSON object; no diagnostic text",
    "stderr": "diagnostics only; never evidence or content",
    "certificate-evidence-v1 response base64 fields": [
        "owner_nonce_b64",
        "tls_spki_der_b64",
        "amd_report_b64",
        "hcl_report_b64",
        "ak_public_key_pem_b64",
        "quote_message_b64",
        "quote_signature_b64",
        "quote_pcrs_b64",
        "amd_ark_pem_b64",
        "amd_ask_pem_b64",
        "amd_vcek_pem_b64",
        "gpu_envelope_b64",
    ],
    "certificate-evidence-v1 response hex fields": ["qualifying_data_hex"],
    "exporter-proof-v1 response base64 fields": [
        "quote_message_b64",
        "quote_signature_b64",
        "quote_pcrs_b64",
    ],
    "exporter-proof-v1 response hex fields": ["qualifying_data_hex"],
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=9443)
    parser.add_argument("--upstream-host", default="127.0.0.1")
    parser.add_argument("--upstream-port", type=int, default=8000)
    parser.add_argument("--collector-command")
    parser.add_argument("--collector-timeout", type=int, default=120)
    parser.add_argument("--socket-timeout", type=int, default=180)
    parser.add_argument("--print-collector-contract", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.print_collector_contract:
        print(json.dumps(COLLECTOR_CONTRACT, indent=2, sort_keys=True))
        return 0
    if not args.collector_command:
        raise SystemExit("--collector-command is required")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    collector = CommandCollector(shlex.split(args.collector_command), args.collector_timeout)
    with GatewayServer(
        (args.listen_host, args.listen_port),
        collector,
        (args.upstream_host, args.upstream_port),
        args.socket_timeout,
    ) as server:
        host, port = server.server_address
        print(json.dumps({"event": "listening", "host": host, "port": port}), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
