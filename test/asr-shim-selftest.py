#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""No-hardware ASR sidecar self-test (stub transcriber, stdlib only)."""

from __future__ import annotations

import http.client
import json
import socket
import struct
import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from asr_shim import MODEL_ID, MultipartReject, create_server, parse_multipart  # noqa: E402
from strict_wav import CANONICAL_SAMPLE_RATE, build_canonical_wav  # noqa: E402

BOUNDARY = "testboundary1234"


def canonical_wav(seconds: float) -> bytes:
    return build_canonical_wav(bytes(2 * int(CANONICAL_SAMPLE_RATE * seconds)))


def multipart_body(
    file_bytes: bytes | None, extra: dict[str, str] | None = None
) -> bytes:
    parts = []
    if file_bytes is not None:
        parts.append(
            f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="file"; '
            f'filename="audio.wav"\r\nContent-Type: audio/wav\r\n\r\n'.encode()
            + file_bytes
            + b"\r\n"
        )
    for name, value in (extra or {}).items():
        parts.append(
            f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="{name}"'
            f"\r\n\r\n{value}\r\n".encode()
        )
    return b"".join(parts) + f"--{BOUNDARY}--\r\n".encode()


class StubTranscriber:
    """Deterministic transcriber; optionally blocks on an event."""

    def __init__(self, gate: threading.Event | None = None) -> None:
        self.gate = gate
        self.batches: list[int] = []

    def transcribe_batch(self, pcm_batch: list[bytes]) -> list[dict]:
        if self.gate is not None:
            self.gate.wait(30)
        self.batches.append(len(pcm_batch))
        results = []
        for pcm in pcm_batch:
            duration = len(pcm) / (2 * CANONICAL_SAMPLE_RATE)
            results.append(
                {
                    "text": "stub transcript.",
                    "duration": duration,
                    "words": [
                        {"word": "stub", "start": 0.0, "end": 0.4, "conf": None},
                        {"word": "transcript.", "start": 0.5, "end": 1.0, "conf": None},
                    ],
                }
            )
        return results


class ShimFixture:
    def __init__(self, transcriber: StubTranscriber, **kwargs) -> None:
        self.server = create_server(
            ("127.0.0.1", 0), lambda: transcriber, **kwargs
        )
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def wait_ready(self, timeout: float = 10.0) -> None:
        if not self.server.worker.ready.wait(timeout):
            raise TimeoutError("shim never became ready")

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def post_wav(
        self, payload: bytes, device: str | None = None
    ) -> tuple[int, bytes]:
        headers = {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"}
        if device:
            headers["x-sol-device"] = device
        body = multipart_body(
            payload,
            {"response_format": "verbose_json", "timestamp_granularities[]": "word"},
        )
        status, _headers, response = self.request(
            "POST", "/v1/audio/transcriptions", body, headers
        )
        return status, response

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def non_canonical_probes() -> dict[str, bytes]:
    """The nine non-canonical intake classes from the runner eval (smoke G)."""
    pcm = bytes(CANONICAL_SAMPLE_RATE * 2)

    def wav(fmt_tag=1, channels=1, rate=16000, bits=16, data=pcm) -> bytes:
        byte_rate = rate * channels * bits // 8
        return (
            b"RIFF" + struct.pack("<I", 36 + len(data)) + b"WAVE" + b"fmt "
            + struct.pack("<IHHIIHH", 16, fmt_tag, channels, rate, byte_rate,
                          channels * bits // 8, bits)
            + b"data" + struct.pack("<I", len(data)) + data
        )

    return {
        "flac": b"fLaC" + bytes(64),
        "ogg": b"OggS" + bytes(64),
        "mp3": b"ID3\x04\x00\x00\x00\x00\x00\x00" + b"\xff\xfb" + bytes(64),
        "stereo": wav(channels=2),
        "float32": wav(fmt_tag=3, bits=32),
        "rate24k": wav(rate=24000),
        "bits8": wav(bits=8),
        "truncated": wav()[:200],
        "random": bytes(range(256)) * 16,
    }


class WireParserImportHygieneTest(unittest.TestCase):
    """No decoder library is importable from the wire-byte parsers.

    Pins the recipe § 0 "no transcoder reachable with wire bytes" invariant
    mechanically (CSO A7 F2): NeMo transitively installs audio libraries
    (soundfile/librosa), so the dependency set can't carry the property —
    the modules that touch wire bytes must never import a decoder, directly
    or lazily.
    """

    FORBIDDEN = {
        "aifc", "audioop", "audioread", "av", "ffmpeg", "librosa",
        "miniaudio", "pydub", "scipy", "sndhdr", "soundfile", "torchaudio",
        "wave",
    }

    def test_wire_parsers_import_no_decoder_library(self) -> None:
        import ast

        for filename in ("asr_shim.py", "strict_wav.py"):
            tree = ast.parse((ROOT / filename).read_text(), filename=filename)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                else:
                    continue
                for name in names:
                    self.assertNotIn(
                        name.split(".")[0],
                        self.FORBIDDEN,
                        f"{filename} imports decoder library {name!r}",
                    )


class MultipartParserTest(unittest.TestCase):
    def test_round_trip_and_strict_rejects(self) -> None:
        body = multipart_body(b"AUDIOBYTES", {"response_format": "verbose_json"})
        fields = parse_multipart(body, BOUNDARY.encode())
        self.assertEqual(fields["file"], b"AUDIOBYTES")
        self.assertEqual(fields["response_format"], b"verbose_json")
        for broken in (
            b"preamble" + body,                      # preamble
            body.replace(b"--" + BOUNDARY.encode() + b"--", b"", 1),  # unterminated
            body + b"trailing-garbage",              # epilogue content
        ):
            with self.assertRaises(MultipartReject):
                parse_multipart(broken, BOUNDARY.encode())
        duplicated = multipart_body(b"A") [: -len(f"--{BOUNDARY}--\r\n")] + multipart_body(b"B")
        with self.assertRaises(MultipartReject):
            parse_multipart(duplicated, BOUNDARY.encode())


class AsrShimTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.transcriber = StubTranscriber()
        cls.shim = ShimFixture(cls.transcriber)
        cls.shim.wait_ready()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.shim.close()

    def test_smoke_f_canonical_wav_to_verbose_json_words(self) -> None:
        status, body = self.shim.post_wav(canonical_wav(2.0), device="dev-abc.1")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        # the exact checks the journal's _parse_words applies
        self.assertIn("words", payload)
        self.assertIsInstance(payload["words"], list)
        for item in payload["words"]:
            self.assertIsInstance(item["word"], str)
            float(item["start"]), float(item["end"])
            self.assertIsNone(item["conf"])
        self.assertIsInstance(payload["text"], str)
        self.assertAlmostEqual(payload["duration"], 2.0, places=3)

    def test_smoke_g_strict_intake_rejects_all_nine(self) -> None:
        for name, probe in non_canonical_probes().items():
            status, body = self.shim.post_wav(probe)
            self.assertEqual(status, 400, f"probe {name} was not rejected")
            self.assertIn(b"unsupported audio format", body, f"probe {name}")

    def test_smoke_h_served_model_identity(self) -> None:
        status, _headers, body = self.shim.request("GET", "/v1/audio/models")
        self.assertEqual(status, 200)
        models = json.loads(body)
        self.assertEqual([entry["id"] for entry in models["data"]], [MODEL_ID])

    def test_over_duration_rejected(self) -> None:
        # just over the 330s duration cap while still under the byte cap
        status, body = self.shim.post_wav(canonical_wav(330.02))
        self.assertEqual(status, 400)
        self.assertIn(b"maximum duration", body)
        # far over: rejected by the byte cap instead, still a 400
        status, body = self.shim.post_wav(canonical_wav(340.0))
        self.assertEqual(status, 400)
        self.assertIn(b"maximum size", body)

    def test_oversize_content_length_rejected_before_read(self) -> None:
        with socket.create_connection(("127.0.0.1", self.shim.port), timeout=10) as sock:
            sock.sendall(
                b"POST /v1/audio/transcriptions HTTP/1.1\r\n"
                b"Host: shim\r\nContent-Type: multipart/form-data; boundary=x\r\n"
                b"Content-Length: 99999999\r\n\r\n"
            )
            response = sock.recv(4096)
        self.assertIn(b"413", response.split(b"\r\n", 1)[0])

    def test_bad_content_type_drains_body_and_keeps_connection(self) -> None:
        connection = http.client.HTTPConnection("127.0.0.1", self.shim.port, timeout=30)
        try:
            connection.request(
                "POST",
                "/v1/audio/transcriptions",
                body=b"not multipart",
                headers={"Content-Type": "application/octet-stream"},
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 400)
            self.assertFalse(response.will_close)
            response.read()
            first_socket = connection.sock
            self.assertIsNotNone(first_socket)

            connection.request("GET", "/health")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
            self.assertIs(connection.sock, first_socket)
        finally:
            connection.close()

    def test_response_format_pinned(self) -> None:
        body = multipart_body(canonical_wav(1.0), {"response_format": "json"})
        status, _headers, response = self.shim.request(
            "POST", "/v1/audio/transcriptions", body,
            {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"},
        )
        self.assertEqual(status, 400)
        self.assertIn(b"verbose_json", response)

    def test_missing_file_field_rejected(self) -> None:
        body = multipart_body(None, {"response_format": "verbose_json"})
        status, _headers, response = self.shim.request(
            "POST", "/v1/audio/transcriptions", body,
            {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"},
        )
        self.assertEqual(status, 400)
        self.assertIn(b"missing file", response)

    def test_health_and_metrics_content_free(self) -> None:
        status, _headers, body = self.shim.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ready"])
        status, _body = self.shim.post_wav(canonical_wav(1.5), device="dev-abc.1")
        self.assertEqual(status, 200)
        status, _headers, metrics = self.shim.request("GET", "/metrics")
        self.assertEqual(status, 200)
        text = metrics.decode()
        self.assertIn('spp_asr_device_audio_seconds_total{device="dev-abc.1"}', text)
        self.assertIn("spp_asr_audio_seconds_total", text)
        self.assertNotIn("stub transcript", text)  # never content


class BackpressureAndReadinessTest(unittest.TestCase):
    def test_not_ready_returns_503(self) -> None:
        gate = threading.Event()

        class SlowFactory:
            def __call__(self) -> StubTranscriber:
                gate.wait(30)
                return StubTranscriber()

        server = create_server(("127.0.0.1", 0), SlowFactory())
        fixture = ShimFixture.__new__(ShimFixture)
        fixture.server = server
        fixture.port = server.server_address[1]
        fixture.thread = threading.Thread(target=server.serve_forever, daemon=True)
        fixture.thread.start()
        connection = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=30)
        try:
            body = multipart_body(canonical_wav(1.0))
            connection.request(
                "POST",
                "/v1/audio/transcriptions",
                body=body,
                headers={"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"},
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 503)
            self.assertFalse(response.will_close)
            response.read()
            first_socket = connection.sock
            self.assertIsNotNone(first_socket)

            connection.request("GET", "/health")
            response = connection.getresponse()
            self.assertEqual(response.status, 503)
            response.read()
            self.assertIs(connection.sock, first_socket)

            gate.set()
            fixture.wait_ready()
            connection.request("GET", "/health")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
            self.assertIs(connection.sock, first_socket)
        finally:
            gate.set()
            connection.close()
            fixture.close()

    def test_bounded_queue_returns_429(self) -> None:
        gate = threading.Event()
        gate.set()  # let the startup self-smoke through
        transcriber = StubTranscriber(gate=gate)
        fixture = ShimFixture(transcriber, max_queue=2, request_timeout_s=30.0)
        fixture.wait_ready()
        gate.clear()  # now block the worker to build queue pressure
        try:
            statuses: list[int] = []
            lock = threading.Lock()

            def post() -> None:
                status, _body = fixture.post_wav(canonical_wav(0.5))
                with lock:
                    statuses.append(status)

            threads = [threading.Thread(target=post) for _ in range(5)]
            for thread in threads:
                thread.start()
                time.sleep(0.15)  # first is dequeued by the worker; 2 queue; rest 429
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                with lock:
                    if statuses.count(429) >= 2:
                        break
                time.sleep(0.05)
            gate.set()
            for thread in threads:
                thread.join(timeout=30)
            self.assertEqual(statuses.count(429), 2, statuses)
            self.assertEqual(statuses.count(200), 3, statuses)
        finally:
            gate.set()
            fixture.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
