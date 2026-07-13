#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Production ASR sidecar for the spp engine — hosted STT at local parity.

Serves the exact wire the journal's local STT client already speaks:

  POST /v1/audio/transcriptions   multipart: file=<canonical PCM16-WAV 16k mono>,
      response_format=verbose_json, timestamp_granularities[]=word
  → {"text": ..., "duration": ..., "words": [{"word","start","end","conf"}, ...]}
  GET  /v1/audio/models           served-model identity (the parity observable)
  GET  /v1/audio/health, /health  readiness (CC gate + pinned model + self-smoke)
  GET  /metrics                   Prometheus counters — loopback only, never
                                  routed by the gateway (only /v1/audio/* is)

Model: nvidia/parakeet-tdt-0.6b-v3 via NeMo 2.7.3, bf16, CUDA graphs ON,
micro-batch capped at 8. Loaded from a sha256-pinned local .nemo artifact —
zero runtime model egress.

Fail-closed properties baked in:
- CC-PRODUCTION gate re-runs on every start; a box or restart that is not in
  CC PRODUCTION mode exits instead of serving (supervisor discipline, recipe §5).
- strict_wav.parse_canonical_wav is the ONLY parser touching wire audio bytes;
  every non-canonical payload is rejected 400 (reject-don't-convert), and the
  multipart reader here is a strict bounded owned parser, not a framework's.
- Bounded queue with 429 backpressure; request size cap with 413; readiness
  gate with 503; per-request timeout with 504.
- Content-free logging and metrics: counts, durations, and reason classes
  only. No transcript, path payload, or audio byte ever reaches a log line.
- Per-device audio-seconds metering counter, keyed by the opaque x-sol-device
  header — capacity-shaped entitlement/fleet telemetry only (Article 8).

Stdlib HTTP server + owned multipart parser: no web framework inside the
attested boundary. NeMo/numpy import lazily at model load, so the module is
testable without GPU dependencies (inject a stub transcriber).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import queue
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from strict_wav import (
    CANONICAL_SAMPLE_RATE,
    WavReject,
    build_canonical_wav,
    parse_canonical_wav,
)

LOG = logging.getLogger("spp-asr-shim")

MODEL_ID = "nvidia/parakeet-tdt-0.6b-v3"
MAX_BATCH_HARD_CAP = 8  # locked constraint: micro-batch <= 8 for co-location
# canonical 300s WAV is ~9.6 MB; allow validator tolerance + multipart framing
MAX_REQUEST_BYTES = 11 * 1024 * 1024
MAX_MULTIPART_PARTS = 8
DEVICE_LABEL_MAX = 4096  # metering-label cardinality bound
DEVICE_LABEL_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
# TDT/FastConformer frame stride: window_stride 0.01s x 8x subsampling
FRAME_SEC = 0.08


class MultipartReject(ValueError):
    """Raised for any request body that is not strict multipart/form-data."""


def parse_multipart(body: bytes, boundary: bytes) -> dict[str, bytes]:
    """Strict bounded multipart/form-data parser for exactly our wire.

    Returns {field_name: value_bytes}. Rejects preambles, epilogue content,
    duplicate fields, missing names, and more than MAX_MULTIPART_PARTS parts.
    """
    if not boundary or len(boundary) > 128:
        raise MultipartReject("invalid multipart boundary")
    delimiter = b"--" + boundary
    if not body.startswith(delimiter):
        raise MultipartReject("multipart body must start with the boundary")
    fields: dict[str, bytes] = {}
    pos = len(delimiter)
    while True:
        if body[pos : pos + 2] == b"--":
            if body[pos + 2 :].strip(b"\r\n") != b"":
                raise MultipartReject("unexpected bytes after closing boundary")
            return fields
        if body[pos : pos + 2] != b"\r\n":
            raise MultipartReject("malformed boundary delimiter")
        pos += 2
        header_end = body.find(b"\r\n\r\n", pos)
        if header_end < 0:
            raise MultipartReject("part headers not terminated")
        name: str | None = None
        for line in body[pos:header_end].split(b"\r\n"):
            header_name, separator, value = line.partition(b":")
            if not separator:
                raise MultipartReject("malformed part header")
            if header_name.strip().lower() == b"content-disposition":
                disposition = value.decode("latin-1")
                match = re.search(r'name="([^"]{1,64})"', disposition)
                if not match or not disposition.strip().startswith("form-data"):
                    raise MultipartReject("part is not a named form-data field")
                name = match.group(1)
        if name is None:
            raise MultipartReject("part missing content-disposition name")
        if name in fields:
            raise MultipartReject("duplicate multipart field")
        if len(fields) >= MAX_MULTIPART_PARTS:
            raise MultipartReject("too many multipart parts")
        value_start = header_end + 4
        next_delim = body.find(b"\r\n" + delimiter, value_start)
        if next_delim < 0:
            raise MultipartReject("part not terminated by boundary")
        fields[name] = body[value_start:next_delim]
        pos = next_delim + 2 + len(delimiter)


def check_cc_production() -> None:
    """Fail-closed CC gate: require CC status ON and PRODUCTION environment."""
    for flag, needle in (("-f", "CC status: ON"), ("-e", "PRODUCTION")):
        result = subprocess.run(
            ["nvidia-smi", "conf-compute", flag],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if result.returncode != 0 or needle not in result.stdout:
            raise RuntimeError(f"CC gate failed on conf-compute {flag}")


def verify_model_sha256(path: str, expected_hex: str) -> None:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != expected_hex.lower():
        raise RuntimeError("model artifact sha256 mismatch")


class NemoTranscriber:
    """NeMo 2.7.3 serving parakeet-tdt-0.6b-v3 from a pinned local artifact."""

    def __init__(self, model_path: str, bf16: bool) -> None:
        from nemo.utils import logging as nemo_logging

        nemo_logging.set_verbosity(nemo_logging.ERROR)  # content-free logs

        import nemo.collections.asr as nemo_asr

        started = time.perf_counter()
        self._model = nemo_asr.models.ASRModel.restore_from(restore_path=model_path)
        self._model.eval()
        if bf16:
            import torch

            self._model = self._model.to(torch.bfloat16)
        LOG.info("model loaded in %.1fs bf16=%s", time.perf_counter() - started, bf16)

    def transcribe_batch(self, pcm_batch: list[bytes]) -> list[dict]:
        import numpy as np

        arrays = [
            np.frombuffer(pcm, dtype="<i2").astype(np.float32) / 32768.0
            for pcm in pcm_batch
        ]
        hypotheses = self._model.transcribe(
            arrays, timestamps=True, batch_size=len(arrays), verbose=False
        )
        results = []
        for array, hypothesis in zip(arrays, hypotheses):
            results.append(
                {
                    "text": str(getattr(hypothesis, "text", "")),
                    "duration": len(array) / CANONICAL_SAMPLE_RATE,
                    "words": _words_from_hypothesis(hypothesis),
                }
            )
        return results


def _words_from_hypothesis(hypothesis: Any) -> list[dict]:
    """Normalize NeMo word timestamps to the journal wire shape."""
    stamps = getattr(hypothesis, "timestamp", None) or {}
    words = []
    for item in stamps.get("word", []):
        if item.get("start") is not None:
            start = float(item["start"])
            end = float(item["end"])
        else:  # offset-only variants
            start = float(item["start_offset"]) * FRAME_SEC
            end = float(item["end_offset"]) * FRAME_SEC
        words.append(
            {
                "word": str(item.get("word", "")).strip(),
                "start": start,
                "end": end,
                "conf": None,  # no per-word confidence on this runtime (#15143)
            }
        )
    return words


class Metrics:
    """Content-free Prometheus counters with bounded label cardinality."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.outcomes: dict[str, int] = {}
        self.audio_seconds = 0.0
        self.device_audio_seconds: dict[str, float] = {}
        self.batches = 0
        self.batched_requests = 0
        self.inference_seconds = 0.0

    def record_outcome(self, outcome: str) -> None:
        with self._lock:
            self.outcomes[outcome] = self.outcomes.get(outcome, 0) + 1

    def record_audio(self, seconds: float, device: str | None) -> None:
        label = device if device and DEVICE_LABEL_RE.match(device) else "unlabeled"
        with self._lock:
            self.audio_seconds += seconds
            if label not in self.device_audio_seconds and (
                len(self.device_audio_seconds) >= DEVICE_LABEL_MAX
            ):
                label = "overflow"
            self.device_audio_seconds[label] = (
                self.device_audio_seconds.get(label, 0.0) + seconds
            )

    def record_batch(self, size: int, wall_seconds: float) -> None:
        with self._lock:
            self.batches += 1
            self.batched_requests += size
            self.inference_seconds += wall_seconds

    def render(self, queue_depth: int, ready: bool) -> str:
        with self._lock:
            lines = [
                "# TYPE spp_asr_requests_total counter",
                *(
                    f'spp_asr_requests_total{{outcome="{key}"}} {value}'
                    for key, value in sorted(self.outcomes.items())
                ),
                "# TYPE spp_asr_audio_seconds_total counter",
                f"spp_asr_audio_seconds_total {self.audio_seconds:.3f}",
                "# TYPE spp_asr_device_audio_seconds_total counter",
                *(
                    f'spp_asr_device_audio_seconds_total{{device="{key}"}} {value:.3f}'
                    for key, value in sorted(self.device_audio_seconds.items())
                ),
                "# TYPE spp_asr_batches_total counter",
                f"spp_asr_batches_total {self.batches}",
                "# TYPE spp_asr_batched_requests_total counter",
                f"spp_asr_batched_requests_total {self.batched_requests}",
                "# TYPE spp_asr_inference_seconds_total counter",
                f"spp_asr_inference_seconds_total {self.inference_seconds:.3f}",
                "# TYPE spp_asr_queue_depth gauge",
                f"spp_asr_queue_depth {queue_depth}",
                "# TYPE spp_asr_ready gauge",
                f"spp_asr_ready {int(ready)}",
            ]
        return "\n".join(lines) + "\n"


class _PendingResult:
    """One queued request's completion slot."""

    def __init__(self) -> None:
        self.event = threading.Event()
        self.result: dict | None = None
        self.error: Exception | None = None


class BatchWorker(threading.Thread):
    """Micro-batching worker: coalesce queued requests into one NeMo batch."""

    def __init__(
        self,
        transcriber_factory: Callable[[], Any],
        metrics: Metrics,
        max_batch: int,
        batch_window_s: float,
        max_queue: int,
    ) -> None:
        super().__init__(daemon=True)
        self.queue: queue.Queue = queue.Queue(maxsize=max_queue)
        self.ready = threading.Event()
        self.metrics = metrics
        self.max_batch = min(max_batch, MAX_BATCH_HARD_CAP)
        self.batch_window_s = batch_window_s
        self._transcriber_factory = transcriber_factory
        self._transcriber: Any = None

    def run(self) -> None:
        try:
            self._transcriber = self._transcriber_factory()
            self._self_smoke()
        except Exception as exc:  # content-free: type only, then fail closed
            LOG.error("startup failed (%s); refusing to serve", type(exc).__name__)
            os._exit(3)
        self.ready.set()
        LOG.info("ready: self-smoke passed, admitting traffic")
        while True:
            first = self.queue.get()
            batch = [first]
            deadline = time.monotonic() + self.batch_window_s
            while len(batch) < self.max_batch:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    batch.append(self.queue.get(timeout=remaining))
                except queue.Empty:
                    break
            pcm_payloads = [item[0] for item in batch]
            pending = [item[1] for item in batch]
            started = time.perf_counter()
            try:
                results = self._transcriber.transcribe_batch(pcm_payloads)
                if len(results) != len(pending):
                    raise RuntimeError("batch result count mismatch")
            except Exception as exc:  # noqa: BLE001
                for slot in pending:
                    slot.error = exc
                    slot.event.set()
                LOG.warning("batch failed (%s)", type(exc).__name__)
                continue
            elapsed = time.perf_counter() - started
            total_seconds = sum(len(p) for p in pcm_payloads) / (
                2 * CANONICAL_SAMPLE_RATE
            )
            self.metrics.record_batch(len(batch), elapsed)
            LOG.info(
                "batch=%d audio=%.1fs wall=%.2fs rtfx=%.1f",
                len(batch), total_seconds, elapsed, total_seconds / max(elapsed, 1e-3),
            )
            for slot, result in zip(pending, results):
                slot.result = result
                slot.event.set()

    def _self_smoke(self) -> None:
        """Prove the intake->inference->wire path on synthetic audio."""
        wav_seconds = 2
        pcm = bytes(2 * CANONICAL_SAMPLE_RATE * wav_seconds)  # silence
        parsed, _count = parse_canonical_wav(build_canonical_wav(pcm))
        results = self._transcriber.transcribe_batch([parsed])
        result = results[0]
        if not (
            isinstance(result.get("text"), str)
            and isinstance(result.get("words"), list)
            and isinstance(result.get("duration"), float)
        ):
            raise RuntimeError("self-smoke result shape invalid")


class AsrHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: "AsrServer"

    # content-free logging: BaseHTTPRequestHandler's default logs request
    # lines; the shim logs only counts/durations/reason classes itself.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _send_json(
        self,
        status: int,
        payload: dict,
        extra_headers: dict[str, str] | None = None,
        close: bool = False,
    ) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if close:
            # the request body was not consumed; keep-alive would desync
            self.send_header("Connection", "close")
            self.close_connection = True
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        worker = self.server.worker
        if self.path in ("/health", "/v1/audio/health"):
            ready = worker.ready.is_set()
            self._send_json(200 if ready else 503, {"ok": ready, "ready": ready})
        elif self.path == "/v1/audio/models":
            self._send_json(
                200,
                {
                    "object": "list",
                    "data": [{"id": MODEL_ID, "object": "model", "owned_by": "sol pbc"}],
                },
            )
        elif self.path == "/metrics":
            body = self.server.metrics.render(
                worker.queue.qsize(), worker.ready.is_set()
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/audio/transcriptions":
            self._send_json(404, {"error": "not found"})
            return
        metrics = self.server.metrics
        worker = self.server.worker
        length_header = self.headers.get("Content-Length")
        if length_header is None or not length_header.strip().isdigit():
            metrics.record_outcome("rejected")
            self._send_json(411, {"error": "content-length required"}, close=True)
            return
        length = int(length_header)
        if length > MAX_REQUEST_BYTES:
            metrics.record_outcome("too_large")
            self._send_json(413, {"error": "request exceeds maximum size"}, close=True)
            return
        body = self.rfile.read(length)
        if len(body) != length:
            metrics.record_outcome("rejected")
            self._send_json(400, {"error": "truncated request body"})
            return
        if not worker.ready.is_set():
            metrics.record_outcome("not_ready")
            self._send_json(
                503,
                {"error": "transcription not ready"},
                {"Retry-After": "5"},
            )
            return
        content_type = self.headers.get("Content-Type", "")
        boundary_match = re.search(
            r'multipart/form-data;.*boundary="?([^";,\s]+)"?', content_type
        )
        if not boundary_match:
            metrics.record_outcome("rejected")
            self._send_json(400, {"error": "expected multipart/form-data"})
            return
        try:
            fields = parse_multipart(body, boundary_match.group(1).encode("latin-1"))
        except MultipartReject as exc:
            metrics.record_outcome("rejected")
            LOG.info("rejected multipart (%d bytes): %s", length, exc)
            self._send_json(400, {"error": f"invalid multipart request: {exc}"})
            return
        upload = fields.get("file")
        if upload is None:
            metrics.record_outcome("rejected")
            self._send_json(400, {"error": "missing file field"})
            return
        response_format = fields.get("response_format", b"verbose_json")
        if response_format.strip() != b"verbose_json":
            metrics.record_outcome("rejected")
            self._send_json(400, {"error": "only verbose_json is served"})
            return
        try:
            pcm, sample_count = parse_canonical_wav(upload)
        except WavReject as exc:
            # content-free rejection: reason class only, never bytes
            metrics.record_outcome("rejected")
            LOG.info("rejected non-canonical payload (%d bytes): %s", len(upload), exc)
            self._send_json(400, {"error": f"unsupported audio format: {exc}"})
            return
        pending = _PendingResult()
        try:
            worker.queue.put_nowait((pcm, pending))
        except queue.Full:
            metrics.record_outcome("backpressure")
            self._send_json(
                429, {"error": "transcription queue full"}, {"Retry-After": "1"}
            )
            return
        if not pending.event.wait(self.server.request_timeout_s):
            metrics.record_outcome("timeout")
            self._send_json(504, {"error": "transcription timed out"})
            return
        if pending.error is not None or pending.result is None:
            metrics.record_outcome("error")
            self._send_json(500, {"error": "transcription failed"})
            return
        audio_seconds = sample_count / CANONICAL_SAMPLE_RATE
        metrics.record_outcome("ok")
        metrics.record_audio(audio_seconds, self.headers.get("x-sol-device"))
        self._send_json(200, pending.result)


class AsrServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        worker: BatchWorker,
        metrics: Metrics,
        request_timeout_s: float,
    ) -> None:
        self.worker = worker
        self.metrics = metrics
        self.request_timeout_s = request_timeout_s
        super().__init__(address, AsrHandler)


def create_server(
    address: tuple[str, int],
    transcriber_factory: Callable[[], Any],
    *,
    max_batch: int = MAX_BATCH_HARD_CAP,
    batch_window_s: float = 0.10,
    max_queue: int = 64,
    request_timeout_s: float = 120.0,
) -> AsrServer:
    metrics = Metrics()
    worker = BatchWorker(
        transcriber_factory, metrics, max_batch, batch_window_s, max_queue
    )
    server = AsrServer(address, worker, metrics, request_timeout_s)
    worker.start()
    return server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8100)
    parser.add_argument("--model-path", required=True,
                        help="local .nemo artifact (no runtime model egress)")
    parser.add_argument("--model-sha256", required=True,
                        help="pinned sha256 of the model artifact")
    parser.add_argument("--max-batch", type=int, default=MAX_BATCH_HARD_CAP)
    parser.add_argument("--batch-window-s", type=float, default=0.10)
    parser.add_argument("--max-queue", type=int, default=64)
    parser.add_argument("--request-timeout-s", type=float, default=120.0)
    parser.add_argument("--no-bf16", action="store_true")
    parser.add_argument(
        "--skip-cc-gate", action="store_true",
        help="dev/test only: skip the CC-PRODUCTION gate (never in the pool)",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    if args.max_batch > MAX_BATCH_HARD_CAP:
        raise SystemExit(f"--max-batch is capped at {MAX_BATCH_HARD_CAP} (locked)")
    if args.skip_cc_gate:
        LOG.warning("CC-PRODUCTION gate SKIPPED — dev/test mode only")
    else:
        check_cc_production()
        LOG.info("CC gate passed: ON / PRODUCTION")
    verify_model_sha256(args.model_path, args.model_sha256)
    LOG.info("model artifact sha256 verified")

    def factory() -> NemoTranscriber:
        return NemoTranscriber(args.model_path, bf16=not args.no_bf16)

    server = create_server(
        (args.host, args.port),
        factory,
        max_batch=args.max_batch,
        batch_window_s=args.batch_window_s,
        max_queue=args.max_queue,
        request_timeout_s=args.request_timeout_s,
    )
    host, port = server.server_address[:2]
    print(json.dumps({"event": "listening", "host": host, "port": port}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
