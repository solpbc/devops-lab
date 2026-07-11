#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""No-hardware contract and live TLS gateway self-test."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
import unittest
from pathlib import Path

from cryptography import x509
from OpenSSL import SSL, crypto


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ratls_contract import (  # noqa: E402
    COMPOSITE_EVIDENCE_OID,
    EXPORTER_BYTES,
    EXPORTER_CONTEXT_DOMAIN,
    EXPORTER_LABEL,
    EXPORTER_PROOF_PATH,
    OWNER_NONCE_BYTES,
    PREFACE_MAGIC,
    CompositeEvidence,
    ExporterProof,
)


def recv_http(connection: SSL.Connection) -> tuple[bytes, bytes]:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        data.extend(connection.recv(4096))
    head, body = bytes(data).split(b"\r\n\r\n", 1)
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.lower() == b"content-length":
            length = int(value.strip())
    while len(body) < length:
        body += connection.recv(length - len(body))
    return head, body[:length]


class Upstream:
    def __init__(self) -> None:
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.request = b""
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def run(self) -> None:
        conn, _ = self.listener.accept()
        with conn:
            self.request = conn.recv(4096)
            response = b'{"status":"ok"}'
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(response)}\r\nConnection: close\r\n\r\n".encode()
                + response
            )
        self.listener.close()


class GatewayProcess:
    def __init__(self, upstream_port: int) -> None:
        self.process = subprocess.Popen(
            [
                sys.executable,
                str(ROOT / "ratls_gateway.py"),
                "--listen-host",
                "127.0.0.1",
                "--listen-port",
                "0",
                "--upstream-port",
                str(upstream_port),
                "--collector-command",
                f"{sys.executable} {ROOT / 'test/fake-ratls-collector.py'}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert self.process.stdout is not None
        ready = json.loads(self.process.stdout.readline())
        self.port = ready["port"]

    def close(self) -> None:
        self.process.terminate()
        self.process.communicate(timeout=5)


class RatlsGatewayTest(unittest.TestCase):
    def test_der_round_trip_and_strict_trailing_reject(self) -> None:
        evidence = CompositeEvidence(*[bytes([index]) for index in range(1, 13)])
        self.assertEqual(CompositeEvidence.from_der(evidence.to_der()), evidence)
        with self.assertRaisesRegex(ValueError, "trailing"):
            CompositeEvidence.from_der(evidence.to_der() + b"x")

    def test_two_phase_gate_and_proxy(self) -> None:
        upstream = Upstream()
        upstream.start()
        gateway = GatewayProcess(upstream.port)
        try:
            nonce = bytes(range(OWNER_NONCE_BYTES))
            raw = socket.create_connection(("127.0.0.1", gateway.port), timeout=5)
            raw.sendall(PREFACE_MAGIC + nonce)
            context = SSL.Context(SSL.TLS_CLIENT_METHOD)
            context.set_min_proto_version(SSL.TLS1_3_VERSION)
            context.set_max_proto_version(SSL.TLS1_3_VERSION)
            context.set_verify(SSL.VERIFY_NONE, lambda *_args: True)
            connection = SSL.Connection(context, raw)
            connection.setblocking(1)
            connection.set_connect_state()
            connection.set_tlsext_host_name(b"spp-engine")
            connection.do_handshake()

            peer = connection.get_peer_certificate().to_cryptography()
            extension = peer.extensions.get_extension_for_oid(
                x509.ObjectIdentifier(COMPOSITE_EVIDENCE_OID)
            )
            self.assertTrue(extension.critical)
            evidence = CompositeEvidence.from_der(extension.value.value)
            self.assertEqual(evidence.owner_nonce, nonce)
            self.assertEqual(
                evidence.tls_spki_der,
                peer.public_key().public_bytes(
                    encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER,
                    format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.SubjectPublicKeyInfo,
                ),
            )

            import hashlib

            exporter_context = hashlib.sha256(
                EXPORTER_CONTEXT_DOMAIN
                + nonce
                + hashlib.sha256(evidence.tls_spki_der).digest()
            ).digest()
            client_exporter = connection.export_keying_material(
                EXPORTER_LABEL, EXPORTER_BYTES, exporter_context
            )
            connection.sendall(
                f"GET {EXPORTER_PROOF_PATH} HTTP/1.1\r\nHost: spp-engine\r\nContent-Length: 0\r\n\r\n".encode()
            )
            proof_head, proof_body = recv_http(connection)
            self.assertIn(b"200 OK", proof_head)
            proof = ExporterProof.from_der(proof_body)
            self.assertEqual(proof.owner_nonce, nonce)
            self.assertEqual(proof.tls_exporter, client_exporter)

            connection.sendall(b"GET /health HTTP/1.1\r\nHost: spp-engine\r\nConnection: close\r\n\r\n")
            response_head, response_body = recv_http(connection)
            self.assertIn(b"200 OK", response_head)
            self.assertEqual(response_body, b'{"status":"ok"}')
            connection.close()
            raw.close()
            upstream.thread.join(timeout=5)
            self.assertTrue(upstream.request.startswith(b"GET /health HTTP/1.1"))
        finally:
            gateway.close()

    def test_inference_before_exporter_proof_is_rejected(self) -> None:
        upstream = Upstream()
        upstream.start()
        gateway = GatewayProcess(upstream.port)
        try:
            raw = socket.create_connection(("127.0.0.1", gateway.port), timeout=5)
            raw.sendall(PREFACE_MAGIC + b"n" * OWNER_NONCE_BYTES)
            context = SSL.Context(SSL.TLS_CLIENT_METHOD)
            context.set_verify(SSL.VERIFY_NONE, lambda *_args: True)
            connection = SSL.Connection(context, raw)
            connection.setblocking(1)
            connection.set_connect_state()
            connection.do_handshake()
            connection.sendall(b"POST /v1/chat/completions HTTP/1.1\r\nHost: spp-engine\r\nContent-Length: 0\r\n\r\n")
            with self.assertRaises((SSL.SysCallError, SSL.ZeroReturnError, ConnectionError)):
                if connection.recv(1) == b"":
                    raise ConnectionError("closed")
            self.assertEqual(upstream.request, b"")
            connection.close()
            raw.close()
        finally:
            gateway.close()
            upstream.listener.close()


if __name__ == "__main__":
    unittest.main()
