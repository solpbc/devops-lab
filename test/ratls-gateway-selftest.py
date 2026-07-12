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
from ratls_gateway import CollectorError, CommandCollector  # noqa: E402


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
    def __init__(self, upstream_port: int, audio_upstream_port: int | None = None) -> None:
        command = [
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
        ]
        if audio_upstream_port is not None:
            command += ["--audio-upstream-port", str(audio_upstream_port)]
        self.process = subprocess.Popen(
            command,
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


class RecordingUpstream:
    """Loop-accepting HTTP upstream that records every request it serves."""

    def __init__(self, response_body: bytes = b'{"status":"ok"}', chunked: bool = False) -> None:
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.port = self.listener.getsockname()[1]
        self.response_body = response_body
        self.chunked = chunked
        self.requests: list[tuple[bytes, bytes]] = []
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self) -> None:
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            with conn:
                data = bytearray()
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
                if b"\r\n\r\n" not in data:
                    continue
                head, body = bytes(data).split(b"\r\n\r\n", 1)
                length = 0
                for line in head.split(b"\r\n")[1:]:
                    name, _, value = line.partition(b":")
                    if name.lower() == b"content-length":
                        length = int(value.strip())
                while len(body) < length:
                    chunk = conn.recv(length - len(body))
                    if not chunk:
                        break
                    body += chunk
                self.requests.append((head, body[:length]))
                if self.chunked:
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                        b"Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
                    )
                    for piece in (self.response_body[:4], self.response_body[4:]):
                        conn.sendall(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
                    conn.sendall(b"0\r\n\r\n")
                else:
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        + f"Content-Length: {len(self.response_body)}\r\n".encode()
                        + b"Connection: keep-alive\r\n\r\n"
                        + self.response_body
                    )

    def close(self) -> None:
        self.listener.close()


def admitted_connection(
    gateway_port: int, nonce: bytes
) -> tuple[SSL.Connection, socket.socket]:
    """Run the full two-phase client admission dance; return the open channel."""
    import hashlib

    raw = socket.create_connection(("127.0.0.1", gateway_port), timeout=10)
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
    evidence = CompositeEvidence.from_der(extension.value.value)
    exporter_context = hashlib.sha256(
        EXPORTER_CONTEXT_DOMAIN + nonce + hashlib.sha256(evidence.tls_spki_der).digest()
    ).digest()
    connection.export_keying_material(EXPORTER_LABEL, EXPORTER_BYTES, exporter_context)
    connection.sendall(
        f"GET {EXPORTER_PROOF_PATH} HTTP/1.1\r\nHost: spp-engine\r\n"
        "Content-Length: 0\r\n\r\n".encode()
    )
    proof_head, proof_body = recv_http(connection)
    assert b"200 OK" in proof_head
    ExporterProof.from_der(proof_body)
    return connection, raw


class RatlsGatewayTest(unittest.TestCase):
    def test_der_round_trip_and_strict_trailing_reject(self) -> None:
        evidence = CompositeEvidence(*[bytes([index]) for index in range(1, 13)])
        self.assertEqual(CompositeEvidence.from_der(evidence.to_der()), evidence)
        with self.assertRaisesRegex(ValueError, "trailing"):
            CompositeEvidence.from_der(evidence.to_der() + b"x")

    def test_collector_stderr_cannot_escape_failure(self) -> None:
        collector = CommandCollector(
            [
                sys.executable,
                "-c",
                "import sys; sys.stderr.write('nonce=device-secret-evidence'); sys.exit(7)",
            ],
            timeout=5,
        )
        with self.assertRaises(CollectorError) as caught:
            collector.call({"operation": "test"})
        self.assertEqual(
            str(caught.exception), "attestation collector failed with exit 7"
        )
        self.assertNotIn("secret", str(caught.exception))

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


class RoutedRelayTest(unittest.TestCase):
    def setUp(self) -> None:
        self.default_upstream = RecordingUpstream(b'{"upstream":"sglang"}')
        self.audio_upstream = RecordingUpstream(b'{"upstream":"asr"}')
        self.gateway = GatewayProcess(
            self.default_upstream.port, audio_upstream_port=self.audio_upstream.port
        )

    def tearDown(self) -> None:
        self.gateway.close()
        self.default_upstream.close()
        self.audio_upstream.close()

    def test_per_request_path_routing_on_one_channel(self) -> None:
        connection, raw = admitted_connection(self.gateway.port, bytes(range(32)))
        try:
            audio_body = b"FAKE-CANONICAL-WAV-BYTES"
            connection.sendall(
                b"POST /v1/audio/transcriptions HTTP/1.1\r\nHost: spp-engine\r\n"
                + f"Content-Length: {len(audio_body)}\r\n\r\n".encode()
                + audio_body
            )
            head, body = recv_http(connection)
            self.assertIn(b"200 OK", head)
            self.assertEqual(body, b'{"upstream":"asr"}')

            chat_body = b'{"messages":[]}'
            connection.sendall(
                b"POST /v1/chat/completions HTTP/1.1\r\nHost: spp-engine\r\n"
                + f"Content-Length: {len(chat_body)}\r\n\r\n".encode()
                + chat_body
            )
            head, body = recv_http(connection)
            self.assertEqual(body, b'{"upstream":"sglang"}')

            connection.sendall(
                b"GET /v1/models HTTP/1.1\r\nHost: spp-engine\r\n\r\n"
            )
            head, body = recv_http(connection)
            self.assertEqual(body, b'{"upstream":"sglang"}')
        finally:
            connection.close()
            raw.close()

        self.assertEqual(len(self.audio_upstream.requests), 1)
        audio_head, recorded_audio_body = self.audio_upstream.requests[0]
        self.assertTrue(audio_head.startswith(b"POST /v1/audio/transcriptions HTTP/1.1"))
        self.assertEqual(recorded_audio_body, audio_body)
        self.assertEqual(len(self.default_upstream.requests), 2)
        self.assertTrue(
            self.default_upstream.requests[0][0].startswith(b"POST /v1/chat/completions")
        )
        self.assertTrue(self.default_upstream.requests[1][0].startswith(b"GET /v1/models"))

    def test_chunked_response_streams_through(self) -> None:
        chunked_upstream = RecordingUpstream(b'{"streamed":true}', chunked=True)
        gateway = GatewayProcess(
            chunked_upstream.port, audio_upstream_port=self.audio_upstream.port
        )
        try:
            connection, raw = admitted_connection(gateway.port, b"c" * 32)
            try:
                connection.sendall(
                    b"GET /v1/models HTTP/1.1\r\nHost: spp-engine\r\n\r\n"
                )
                data = bytearray()
                while b"0\r\n\r\n" not in data:
                    data.extend(connection.recv(4096))
                self.assertIn(b"Transfer-Encoding: chunked", data)
                self.assertIn(b'{"st', data)
                self.assertIn(b'reamed":true}', data)

                # the channel remains usable after a chunked exchange
                connection.sendall(
                    b"GET /health HTTP/1.1\r\nHost: spp-engine\r\n\r\n"
                )
                data = bytearray()
                while b"0\r\n\r\n" not in data:
                    data.extend(connection.recv(4096))
            finally:
                connection.close()
                raw.close()
        finally:
            gateway.close()
            chunked_upstream.close()

    def test_premature_inference_rejected_zero_bytes_both_upstreams(self) -> None:
        raw = socket.create_connection(("127.0.0.1", self.gateway.port), timeout=5)
        raw.sendall(PREFACE_MAGIC + b"n" * OWNER_NONCE_BYTES)
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        context.set_verify(SSL.VERIFY_NONE, lambda *_args: True)
        connection = SSL.Connection(context, raw)
        connection.setblocking(1)
        connection.set_connect_state()
        connection.do_handshake()
        connection.sendall(
            b"POST /v1/audio/transcriptions HTTP/1.1\r\nHost: spp-engine\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        with self.assertRaises((SSL.SysCallError, SSL.ZeroReturnError, ConnectionError)):
            if connection.recv(1) == b"":
                raise ConnectionError("closed")
        self.assertEqual(self.audio_upstream.requests, [])
        self.assertEqual(self.default_upstream.requests, [])
        connection.close()
        raw.close()

    def test_chunked_request_body_fails_closed(self) -> None:
        connection, raw = admitted_connection(self.gateway.port, b"d" * 32)
        try:
            connection.sendall(
                b"POST /v1/audio/transcriptions HTTP/1.1\r\nHost: spp-engine\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
            )
            with self.assertRaises((SSL.SysCallError, SSL.ZeroReturnError, ConnectionError)):
                if connection.recv(1) == b"":
                    raise ConnectionError("closed")
            self.assertEqual(self.audio_upstream.requests, [])
            self.assertEqual(self.default_upstream.requests, [])
        finally:
            connection.close()
            raw.close()


if __name__ == "__main__":
    unittest.main()
