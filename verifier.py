#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Off-CVM verifier spike for Azure SEV-SNP evidence bundles.

The attester still writes the bundle produced by run.sh. This verifier runs
outside the CVM, owns the nonce, pins AMD roots locally, appraises the bundle,
and releases a secret to the guest X25519 public key only after all checks pass.
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import ExtensionOID, NameOID

HCL_SIG = b"HCLA"
HCL_HEADER_SIZE = 32
HCL_REPORT_OFFSET = 32
HCL_REPORT_SIZE = 1184
HCL_RUNTIME_OFFSET = HCL_REPORT_OFFSET + HCL_REPORT_SIZE

SNP_OFF_VERSION = 0x000
SNP_OFF_GUEST_SVN = 0x004
SNP_OFF_POLICY = 0x008
SNP_OFF_VMPL = 0x030
SNP_OFF_SIG_ALGO = 0x034
SNP_OFF_CURRENT_TCB = 0x038
SNP_OFF_PLATFORM_INFO = 0x040
SNP_OFF_KEY_INFO = 0x048
SNP_OFF_REPORT_DATA = 0x050
SNP_OFF_MEASUREMENT = 0x090
SNP_OFF_HOST_DATA = 0x0C0
SNP_OFF_REPORTED_TCB = 0x180
SNP_OFF_CHIP_ID = 0x1A0
SNP_OFF_CPUID_FAMILY = 0x188
SNP_OFF_CPUID_MODEL = 0x189
SNP_OFF_CPUID_STEP = 0x18A
SNP_OFF_COMMITTED_TCB = 0x1E0
SNP_OFF_CURRENT_VERSION = 0x1E8
SNP_OFF_COMMITTED_VERSION = 0x1EC
SNP_OFF_LAUNCH_TCB = 0x1F0
SNP_OFF_SIGNATURE = 0x2A0
SNP_SIGNED_PREFIX_LEN = 0x2A0

SNP_POLICY_DEBUG_BIT = 19
DEFAULT_BINDING_DOMAIN = "sol-key-release-v1"
RELEASE_INFO = b"sol-key-release-aead-v1"


class VerificationError(RuntimeError):
    """A bundle failed appraisal."""


@dataclass(frozen=True)
class HclaBlob:
    version: int
    request_type: int
    report: bytes
    runtime_json: bytes
    runtime: dict[str, Any]


@dataclass(frozen=True)
class TcbVersion:
    boot_loader: int | None
    tee: int | None
    snp: int | None
    microcode: int | None
    fmc: int | None = None

    @classmethod
    def from_raw(cls, raw: bytes, generation: str) -> "TcbVersion":
        if len(raw) != 8:
            raise VerificationError(f"TCB field is {len(raw)} bytes, expected 8")
        if generation == "turin":
            return cls(
                fmc=raw[0],
                boot_loader=raw[1],
                tee=raw[2],
                snp=raw[3],
                microcode=raw[7],
            )
        return cls(
            boot_loader=raw[0],
            tee=raw[1],
            snp=raw[6],
            microcode=raw[7],
        )

    def as_dict(self) -> dict[str, int | None]:
        return {
            "boot_loader": self.boot_loader,
            "tee": self.tee,
            "snp": self.snp,
            "microcode": self.microcode,
            "fmc": self.fmc,
        }


@dataclass(frozen=True)
class TcbFloor:
    boot_loader: int | None = None
    tee: int | None = None
    snp: int | None = None
    microcode: int | None = None
    fmc: int | None = None

    @classmethod
    def from_mapping(cls, mapping: dict[str, Any]) -> "TcbFloor":
        if not isinstance(mapping, dict):
            raise VerificationError("TCB floor policy must be an object")
        allowed = set(cls.__dataclass_fields__)
        unknown = sorted(set(mapping) - allowed)
        if unknown:
            raise VerificationError(f"unknown TCB floor field(s): {', '.join(unknown)}")
        fields: dict[str, int | None] = {}
        for name in allowed:
            value = mapping.get(name)
            if value is not None and (not isinstance(value, int) or not 0 <= value <= 255):
                raise VerificationError(f"TCB floor {name} must be an integer byte value")
            fields[name] = value
        return cls(**fields)

    def check(self, observed: TcbVersion, label: str) -> None:
        values = observed.as_dict()
        for field_name, floor in self.__dict__.items():
            if floor is None:
                continue
            value = values[field_name]
            if value is None:
                raise VerificationError(f"{label} TCB has no {field_name} field")
            if value < floor:
                raise VerificationError(
                    f"{label} TCB {field_name}={value} is below policy floor {floor}"
                )


@dataclass(frozen=True)
class Policy:
    allowed_report_versions: set[int] = field(default_factory=lambda: {3, 5})
    allowed_hcla_versions: set[int] = field(default_factory=lambda: {1, 2})
    allowed_vmpl: set[int] = field(default_factory=lambda: {0})
    require_debug_disabled: bool = True
    min_tcb: dict[str, TcbFloor] = field(default_factory=dict)
    pcr_mode: str = "record"
    pcr_pins: set[str] = field(default_factory=set)

    @classmethod
    def from_file(cls, path: Path | None) -> "Policy":
        if path is None:
            return cls()
        data = json.loads(path.read_text())
        min_tcb = data.get("min_tcb", {})
        if not isinstance(min_tcb, dict):
            raise VerificationError("min_tcb policy must be an object")
        pcr_policy = data.get("pcr_policy", {})
        if not isinstance(pcr_policy, dict):
            raise VerificationError("pcr_policy must be an object")
        pcr_pins = pcr_policy.get("pins", [])
        if not isinstance(pcr_pins, list) or any(not isinstance(pin, str) for pin in pcr_pins):
            raise VerificationError("pcr_policy.pins must be a list of hex strings")
        return cls(
            allowed_report_versions=set(data.get("allowed_report_versions", [3, 5])),
            allowed_hcla_versions=set(data.get("allowed_hcla_versions", [1, 2])),
            allowed_vmpl=set(data.get("allowed_vmpl", [0])),
            require_debug_disabled=bool(data.get("require_debug_disabled", True)),
            min_tcb={
                label: TcbFloor.from_mapping(value)
                for label, value in min_tcb.items()
            },
            pcr_mode=pcr_policy.get("mode", "record"),
            pcr_pins={p.lower() for p in pcr_pins},
        )


@dataclass(frozen=True)
class SnpReport:
    raw: bytes
    version: int
    guest_svn: int
    policy: int
    vmpl: int
    sig_algo: int
    platform_info: int
    key_info: int
    report_data: bytes
    measurement: bytes
    host_data: bytes
    chip_id: bytes
    cpuid_family: int | None
    cpuid_model: int | None
    cpuid_step: int | None
    generation: str
    current_tcb: TcbVersion
    reported_tcb: TcbVersion
    committed_tcb: TcbVersion
    launch_tcb: TcbVersion
    current_version: str
    committed_version: str

    @classmethod
    def parse(cls, raw: bytes) -> "SnpReport":
        if len(raw) != HCL_REPORT_SIZE:
            raise VerificationError(f"AMD report is {len(raw)} bytes, expected {HCL_REPORT_SIZE}")
        version = _u32(raw, SNP_OFF_VERSION)
        family = raw[SNP_OFF_CPUID_FAMILY] if version >= 3 else None
        model = raw[SNP_OFF_CPUID_MODEL] if version >= 3 else None
        step = raw[SNP_OFF_CPUID_STEP] if version >= 3 else None
        generation = _generation_for_cpuid(family, model)
        return cls(
            raw=raw,
            version=version,
            guest_svn=_u32(raw, SNP_OFF_GUEST_SVN),
            policy=_u64(raw, SNP_OFF_POLICY),
            vmpl=_u32(raw, SNP_OFF_VMPL),
            sig_algo=_u32(raw, SNP_OFF_SIG_ALGO),
            platform_info=_u64(raw, SNP_OFF_PLATFORM_INFO),
            key_info=_u32(raw, SNP_OFF_KEY_INFO),
            report_data=raw[SNP_OFF_REPORT_DATA : SNP_OFF_REPORT_DATA + 64],
            measurement=raw[SNP_OFF_MEASUREMENT : SNP_OFF_MEASUREMENT + 48],
            host_data=raw[SNP_OFF_HOST_DATA : SNP_OFF_HOST_DATA + 32],
            chip_id=raw[SNP_OFF_CHIP_ID : SNP_OFF_CHIP_ID + 64],
            cpuid_family=family,
            cpuid_model=model,
            cpuid_step=step,
            generation=generation,
            current_tcb=TcbVersion.from_raw(raw[SNP_OFF_CURRENT_TCB : SNP_OFF_CURRENT_TCB + 8], generation),
            reported_tcb=TcbVersion.from_raw(raw[SNP_OFF_REPORTED_TCB : SNP_OFF_REPORTED_TCB + 8], generation),
            committed_tcb=TcbVersion.from_raw(raw[SNP_OFF_COMMITTED_TCB : SNP_OFF_COMMITTED_TCB + 8], generation),
            launch_tcb=TcbVersion.from_raw(raw[SNP_OFF_LAUNCH_TCB : SNP_OFF_LAUNCH_TCB + 8], generation),
            current_version=_version(raw[SNP_OFF_CURRENT_VERSION : SNP_OFF_CURRENT_VERSION + 3]),
            committed_version=_version(raw[SNP_OFF_COMMITTED_VERSION : SNP_OFF_COMMITTED_VERSION + 3]),
        )

    @property
    def debug_allowed(self) -> bool:
        return ((self.policy >> SNP_POLICY_DEBUG_BIT) & 1) == 1


@dataclass(frozen=True)
class AmdRootSet:
    product: str
    ark: x509.Certificate
    ask: x509.Certificate
    ark_path: Path
    ask_path: Path


@dataclass
class AppraisalResult:
    bundle: str
    steps: list[dict[str, str]] = field(default_factory=list)
    hcla_version: int | None = None
    report_version: int | None = None
    cpuid: dict[str, int | None] = field(default_factory=dict)
    tcb: dict[str, dict[str, int | None]] = field(default_factory=dict)
    pcr_sha256: str | None = None
    release_path: str | None = None
    host_data: str | None = None
    measurement: str | None = None
    chip_id: str | None = None

    def ok(self, name: str, detail: str) -> None:
        self.steps.append({"name": name, "status": "ok", "detail": detail})

    def to_json(self) -> str:
        return json.dumps(
            {
                "bundle": self.bundle,
                "status": "ok",
                "steps": self.steps,
                "hcla_version": self.hcla_version,
                "report_version": self.report_version,
                "cpuid": self.cpuid,
                "tcb": self.tcb,
                "pcr_sha256": self.pcr_sha256,
                "release_path": self.release_path,
                "host_data": self.host_data,
                "measurement": self.measurement,
                "chip_id": self.chip_id,
            },
            indent=2,
            sort_keys=True,
        )


class Tpm2QuoteVerifier:
    def verify(
        self,
        ak_pub: Path,
        quote_msg: Path,
        quote_sig: Path,
        quote_pcrs: Path,
        binding_hex: str,
    ) -> None:
        if shutil.which("tpm2_checkquote") is None:
            raise VerificationError("tpm2_checkquote not found; cannot verify TPM quote")
        subprocess.run(
            [
                "tpm2_checkquote",
                "-u",
                str(ak_pub),
                "-m",
                str(quote_msg),
                "-s",
                str(quote_sig),
                "-f",
                str(quote_pcrs),
                "-g",
                "sha256",
                "-q",
                binding_hex,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )


def issue_challenge(bundle: Path) -> str:
    bundle.mkdir(parents=True, exist_ok=True)
    nonce = secrets.token_hex(32)
    (bundle / "nonce.hex").write_text(nonce + "\n")
    return nonce


def appraise_bundle(
    bundle: Path,
    *,
    roots_dir: Path,
    policy: Policy,
    release_secret: bytes | None = None,
    release_dir: Path | None = None,
    binding_domain: str = DEFAULT_BINDING_DOMAIN,
    ctx: bytes = b"",
    quote_verifier: Tpm2QuoteVerifier | Any | None = None,
) -> AppraisalResult:
    quote_verifier = quote_verifier or Tpm2QuoteVerifier()
    result = AppraisalResult(bundle=str(bundle))

    paths = _bundle_paths(bundle)
    _require(paths, "hcl", "ak_pub", "guest_pub", "nonce", "quote_msg", "quote_sig", "quote_pcrs")

    hcla = parse_hcla(paths["hcl"].read_bytes())
    if hcla.version not in policy.allowed_hcla_versions:
        raise VerificationError(f"HCLA version {hcla.version} is not allowed")
    result.hcla_version = hcla.version
    result.ok("hcla", f"sig=HCLA version={hcla.version} request_type={hcla.request_type}")

    if paths["report"].exists() and paths["report"].read_bytes() != hcla.report:
        result.ok("standalone-report", "report.bin differs; using HCLA-embedded report")

    report = SnpReport.parse(hcla.report)
    result.report_version = report.version
    result.cpuid = {
        "family": report.cpuid_family,
        "model": report.cpuid_model,
        "step": report.cpuid_step,
    }
    result.tcb = {
        "current": report.current_tcb.as_dict(),
        "reported": report.reported_tcb.as_dict(),
        "committed": report.committed_tcb.as_dict(),
        "launch": report.launch_tcb.as_dict(),
    }

    check_runtime_binding(report, hcla.runtime_json)
    result.ok("runtime-binding", "report_data == SHA-256(runtime JSON)")

    vcek = verify_amd_chain_and_report(report, paths["certs"], roots_dir)
    result.ok("amd-chain", f"VCEK chains to pinned {name_cn(vcek.issuer)} roots")
    result.ok("amd-report-signature", "VCEK signed report bytes 0..0x29f")

    check_policy(report, policy)
    result.ok(
        "snp-policy",
        f"version={report.version} vmpl={report.vmpl} debug_allowed={report.debug_allowed}",
    )

    verify_ak_binding(hcla.runtime, paths["ak_pub"])
    result.ok("ak-binding", "bundle AK public key matches AMD-bound HCLAkPub")

    nonce = bytes.fromhex(_read_nonce(paths["nonce"]))
    guest_pub = paths["guest_pub"].read_bytes()
    binding = binding_hash(binding_domain, nonce, guest_pub, ctx)
    quote_verifier.verify(paths["ak_pub"], paths["quote_msg"], paths["quote_sig"], paths["quote_pcrs"], binding.hex())
    result.ok("quote", "AK quote signature valid and extraData matches verifier nonce + guest key")

    pcr_sha256 = _sha256(paths["quote_pcrs"].read_bytes()).hex()
    result.pcr_sha256 = pcr_sha256
    check_pcr_policy(pcr_sha256, policy)
    if policy.pcr_mode == "record":
        result.ok("pcr-policy", f"record-then-pin v1 fingerprint={pcr_sha256}")
    else:
        result.ok("pcr-policy", f"pinned PCR fingerprint matched {pcr_sha256}")

    release_dir = release_dir or (bundle / "release-py")
    secret = release_secret if release_secret is not None else secrets.token_bytes(32)
    release_path = release_to_guest(
        secret,
        guest_pub_der=guest_pub,
        nonce=nonce,
        pcr_sha256=pcr_sha256,
        release_dir=release_dir,
        binding_domain=binding_domain,
    )
    result.release_path = str(release_path)
    result.ok("key-release", f"AES-GCM release written to {release_path}")
    return result


def appraise_raw_report(
    bundle: Path,
    *,
    roots_dir: Path,
    policy: Policy,
    expected_host_data: bytes | None = None,
    nonce_hex: str | None = None,
    expected_measurement: bytes | None = None,
) -> AppraisalResult:
    """Appraise a raw SEV-SNP report with no HCL/vTPM mediation.

    This is the ACI Confidential Containers path (journal 2026-07-04): the UVM
    runs unparavisored at VMPL0 and /dev/sev-guest returns a native report.
    Freshness comes from REPORT_DATA carrying the verifier nonce directly;
    workload identity comes from HOST_DATA carrying the SHA-256 of the CCE
    policy. Trust chain is report signature -> VCEK -> pinned ASK/ARK only.

    Bundle layout: report.bin plus certs/ containing the VCEK PEM.
    """
    result = AppraisalResult(bundle=str(bundle))
    paths = _bundle_paths(bundle)
    _require(paths, "report", "certs")

    report = SnpReport.parse(paths["report"].read_bytes())
    result.report_version = report.version
    result.cpuid = {
        "family": report.cpuid_family,
        "model": report.cpuid_model,
        "step": report.cpuid_step,
    }
    result.tcb = {
        "current": report.current_tcb.as_dict(),
        "reported": report.reported_tcb.as_dict(),
        "committed": report.committed_tcb.as_dict(),
        "launch": report.launch_tcb.as_dict(),
    }
    result.host_data = report.host_data.hex()
    result.measurement = report.measurement.hex()
    result.chip_id = report.chip_id.hex()

    vcek = verify_amd_chain_and_report(report, paths["certs"], roots_dir)
    result.ok("amd-chain", f"VCEK chains to pinned {name_cn(vcek.issuer)} roots")
    result.ok("amd-report-signature", "VCEK signed report bytes 0..0x29f")

    check_policy(report, policy)
    result.ok(
        "snp-policy",
        f"version={report.version} vmpl={report.vmpl} debug_allowed={report.debug_allowed}",
    )

    if nonce_hex is not None:
        nonce = bytes.fromhex("".join(nonce_hex.split()))
        if len(nonce) == 32:
            expected = nonce + b"\x00" * 32
        elif len(nonce) == 64:
            expected = nonce
        else:
            raise VerificationError(f"nonce is {len(nonce)} bytes, expected 32 or 64")
        if report.report_data != expected:
            raise VerificationError(
                "freshness binding failed: REPORT_DATA does not carry the verifier nonce"
            )
        result.ok("freshness", "REPORT_DATA == verifier nonce")
    else:
        result.ok("freshness", "recorded (no verifier nonce supplied)")

    if expected_host_data is not None:
        if len(expected_host_data) != 32:
            raise VerificationError(
                f"expected HOST_DATA is {len(expected_host_data)} bytes, expected 32"
            )
        if report.host_data != expected_host_data:
            raise VerificationError(
                "HOST_DATA mismatch: "
                f"report={report.host_data.hex()} expected={expected_host_data.hex()}"
            )
        result.ok("host-data", "HOST_DATA == expected CCE policy hash")
    else:
        result.ok("host-data", f"recorded {report.host_data.hex()}")

    if expected_measurement is not None:
        if report.measurement != expected_measurement:
            raise VerificationError(
                "MEASUREMENT mismatch: "
                f"report={report.measurement.hex()} expected={expected_measurement.hex()}"
            )
        result.ok("measurement", "launch MEASUREMENT matches pinned reference")
    else:
        result.ok("measurement", f"recorded {report.measurement.hex()}")

    return result


def parse_hcla(blob: bytes) -> HclaBlob:
    if len(blob) < HCL_RUNTIME_OFFSET:
        raise VerificationError(f"HCLA blob is {len(blob)} bytes; expected at least {HCL_RUNTIME_OFFSET}")
    sig = blob[:4]
    version = _u32(blob, 4)
    request_type = _u32(blob, 12)
    if sig != HCL_SIG:
        raise VerificationError(f"HCLA signature mismatch: {sig!r}")
    if request_type != 2:
        raise VerificationError(f"HCLA request_type={request_type}, expected AMD-SNP request_type 2")
    report = blob[HCL_REPORT_OFFSET : HCL_REPORT_OFFSET + HCL_REPORT_SIZE]
    runtime_json = extract_runtime_json(blob)
    try:
        runtime = json.loads(runtime_json)
    except json.JSONDecodeError as exc:
        raise VerificationError(f"HCL runtime JSON did not parse: {exc}") from exc
    return HclaBlob(version=version, request_type=request_type, report=report, runtime_json=runtime_json, runtime=runtime)


def extract_runtime_json(blob: bytes) -> bytes:
    start = blob.find(b'{"', HCL_RUNTIME_OFFSET)
    if start < 0:
        raise VerificationError(f"no JSON object found at/after HCLA offset {HCL_RUNTIME_OFFSET}")
    end = blob.find(b"\x00", start)
    if end < 0:
        end = len(blob)
    return blob[start:end]


def check_runtime_binding(report: SnpReport, runtime_json: bytes) -> None:
    digest = _sha256(runtime_json)
    if report.report_data[:32] != digest:
        raise VerificationError(
            "runtime-data binding failed: "
            f"SHA-256(runtime)={digest.hex()} report_data={report.report_data[:32].hex()}"
        )
    if report.report_data[32:] != b"\x00" * 32:
        raise VerificationError("report_data[32..64] is nonzero; expected SHA-256 runtime binding")


def verify_amd_chain_and_report(report: SnpReport, certs_dir: Path, roots_dir: Path) -> x509.Certificate:
    certs = load_certs_from_dir(certs_dir)
    vcek = select_vcek(certs)
    root = select_root_set(vcek, load_root_sets(roots_dir))
    verify_cert_signature(root.ask, root.ark)
    verify_cert_signature(root.ark, root.ark)
    verify_cert_signature(vcek, root.ask)
    for cert in [root.ark, root.ask, vcek]:
        check_cert_time(cert)
    reject_mismatched_bundle_cas(certs, root)
    verify_report_signature(report.raw, vcek)
    return vcek


def load_certs_from_dir(certs_dir: Path) -> list[x509.Certificate]:
    if not certs_dir.is_dir():
        raise VerificationError(f"missing certs directory: {certs_dir}")
    certs: list[x509.Certificate] = []
    for path in sorted(certs_dir.glob("*.pem")):
        certs.append(x509.load_pem_x509_certificate(path.read_bytes()))
    if not certs:
        raise VerificationError(f"no PEM certificates in {certs_dir}")
    return certs


def load_root_sets(roots_dir: Path) -> list[AmdRootSet]:
    root_sets: list[AmdRootSet] = []
    for product_dir in sorted(roots_dir.glob("*")):
        if not product_dir.is_dir():
            continue
        ark_path = product_dir / "ark.pem"
        ask_path = product_dir / "ask.pem"
        if not ark_path.exists() or not ask_path.exists():
            continue
        root_sets.append(
            AmdRootSet(
                product=product_dir.name,
                ark=x509.load_pem_x509_certificate(ark_path.read_bytes()),
                ask=x509.load_pem_x509_certificate(ask_path.read_bytes()),
                ark_path=ark_path,
                ask_path=ask_path,
            )
        )
    if not root_sets:
        raise VerificationError(f"no AMD root sets under {roots_dir}")
    return root_sets


def select_vcek(certs: list[x509.Certificate]) -> x509.Certificate:
    candidates = [
        cert
        for cert in certs
        if not is_ca(cert) and isinstance(cert.public_key(), ec.EllipticCurvePublicKey)
    ]
    if len(candidates) != 1:
        raise VerificationError(f"expected exactly one VCEK/VLEK cert, found {len(candidates)}")
    return candidates[0]


def select_root_set(vcek: x509.Certificate, root_sets: list[AmdRootSet]) -> AmdRootSet:
    issuer = name_cn(vcek.issuer)
    for root in root_sets:
        if name_cn(root.ask.subject) == issuer:
            return root
    products = ", ".join(f"{root.product}:{name_cn(root.ask.subject)}" for root in root_sets)
    raise VerificationError(f"no pinned AMD ASK for VCEK issuer {issuer}; available {products}")


def reject_mismatched_bundle_cas(certs: list[x509.Certificate], root: AmdRootSet) -> None:
    pinned = {
        name_cn(root.ark.subject): root.ark.fingerprint(hashes.SHA256()),
        name_cn(root.ask.subject): root.ask.fingerprint(hashes.SHA256()),
    }
    for cert in certs:
        subject = name_cn(cert.subject)
        if subject in pinned and cert.fingerprint(hashes.SHA256()) != pinned[subject]:
            raise VerificationError(f"bundle CA {subject} does not match pinned root material")


def verify_cert_signature(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    public_key = issuer.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            params = cert.signature_algorithm_parameters
            if params is None:
                params = padding.PKCS1v15()
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                params,
                cert.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        else:
            raise VerificationError(f"unsupported issuer key type: {type(public_key).__name__}")
    except InvalidSignature as exc:
        raise VerificationError(
            f"certificate signature invalid: {name_cn(cert.subject)} <- {name_cn(issuer.subject)}"
        ) from exc


def verify_report_signature(report: bytes, vcek: x509.Certificate) -> None:
    if len(report) != HCL_REPORT_SIZE:
        raise VerificationError(f"report length {len(report)} != {HCL_REPORT_SIZE}")
    raw_sig = report[SNP_OFF_SIGNATURE : SNP_OFF_SIGNATURE + 512]
    if raw_sig[144:] != b"\x00" * (512 - 144):
        raise VerificationError("AMD report signature reserved bytes are nonzero")
    r = int.from_bytes(raw_sig[:72], "little")
    s = int.from_bytes(raw_sig[72:144], "little")
    der_sig = utils.encode_dss_signature(r, s)
    public_key = vcek.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise VerificationError("VCEK public key is not an EC key")
    try:
        public_key.verify(der_sig, report[:SNP_SIGNED_PREFIX_LEN], ec.ECDSA(hashes.SHA384()))
    except InvalidSignature as exc:
        raise VerificationError("VCEK did not sign the AMD report") from exc


def check_policy(report: SnpReport, policy: Policy) -> None:
    if report.version not in policy.allowed_report_versions:
        raise VerificationError(f"SNP report version {report.version} not allowed")
    if policy.allowed_vmpl and report.vmpl not in policy.allowed_vmpl:
        raise VerificationError(f"VMPL {report.vmpl} not allowed")
    if policy.require_debug_disabled and report.debug_allowed:
        raise VerificationError("SNP guest policy allows DEBUG")
    tcb_fields = {
        "current": report.current_tcb,
        "reported": report.reported_tcb,
        "committed": report.committed_tcb,
        "launch": report.launch_tcb,
    }
    for label, floor in policy.min_tcb.items():
        if label not in tcb_fields:
            raise VerificationError(f"unknown TCB policy label: {label}")
        floor.check(tcb_fields[label], label)


def verify_ak_binding(runtime: dict[str, Any], ak_pub_path: Path) -> None:
    jwk = None
    keys = runtime.get("keys", [])
    if not isinstance(keys, list):
        raise VerificationError("runtime claims field 'keys' is not a list")
    for key in keys:
        if isinstance(key, dict) and key.get("kid") == "HCLAkPub":
            jwk = key
            break
    if jwk is None:
        raise VerificationError("HCLAkPub not found in HCL runtime claims")
    if "n" not in jwk or "e" not in jwk:
        raise VerificationError("HCLAkPub JWK is missing RSA modulus or exponent")
    runtime_n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    runtime_e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    ak_pub = serialization.load_pem_public_key(ak_pub_path.read_bytes())
    if not isinstance(ak_pub, rsa.RSAPublicKey):
        raise VerificationError("bundle AK public key is not RSA")
    ak_numbers = ak_pub.public_numbers()
    if ak_numbers.n != runtime_n or ak_numbers.e != runtime_e:
        raise VerificationError("bundle AK public key does not match AMD-bound HCLAkPub")


def binding_hash(domain: str, nonce: bytes, guest_pub_der: bytes, ctx: bytes = b"") -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(domain.encode())
    digest.update(nonce)
    digest.update(guest_pub_der)
    digest.update(ctx)
    return digest.finalize()


def check_pcr_policy(pcr_sha256: str, policy: Policy) -> None:
    if policy.pcr_mode == "record":
        return
    if policy.pcr_mode != "pin":
        raise VerificationError(f"unknown PCR policy mode {policy.pcr_mode!r}")
    if pcr_sha256.lower() not in policy.pcr_pins:
        raise VerificationError(f"PCR fingerprint {pcr_sha256} not in pinned policy")


def release_to_guest(
    secret: bytes,
    *,
    guest_pub_der: bytes,
    nonce: bytes,
    pcr_sha256: str,
    release_dir: Path,
    binding_domain: str,
) -> Path:
    guest_pub = serialization.load_der_public_key(guest_pub_der)
    if not isinstance(guest_pub, x25519.X25519PublicKey):
        raise VerificationError("guest public key is not X25519")
    verifier_key = x25519.X25519PrivateKey.generate()
    verifier_pub_der = verifier_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    shared = verifier_key.exchange(guest_pub)
    salt = _sha256(nonce + guest_pub_der)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=RELEASE_INFO).derive(shared)
    aead_nonce = secrets.token_bytes(12)
    aad_obj = {
        "version": 1,
        "algorithm": "X25519-HKDF-SHA256-AES-256-GCM",
        "domain": binding_domain,
        "nonce": nonce.hex(),
        "guest_pub_sha256": _sha256(guest_pub_der).hex(),
        "pcr_sha256": pcr_sha256,
    }
    aad = _canonical_json(aad_obj)
    ciphertext = AESGCM(key).encrypt(aead_nonce, secret, aad)
    release_dir.mkdir(parents=True, exist_ok=True)
    (release_dir / "verifier_pub.der").write_bytes(verifier_pub_der)
    release = {
        **aad_obj,
        "verifier_pub_der_b64": base64.b64encode(verifier_pub_der).decode(),
        "aead_nonce_b64": base64.b64encode(aead_nonce).decode(),
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
    }
    release_path = release_dir / "release.json"
    release_path.write_text(json.dumps(release, indent=2, sort_keys=True) + "\n")
    return release_path


def unwrap_release_for_test(release_path: Path, guest_private_key: Path, out: Path) -> None:
    release = json.loads(release_path.read_text())
    private = serialization.load_pem_private_key(guest_private_key.read_bytes(), password=None)
    if not isinstance(private, x25519.X25519PrivateKey):
        raise VerificationError("guest private key is not X25519")
    verifier_pub = serialization.load_der_public_key(base64.b64decode(release["verifier_pub_der_b64"]))
    if not isinstance(verifier_pub, x25519.X25519PublicKey):
        raise VerificationError("verifier public key is not X25519")
    shared = private.exchange(verifier_pub)
    nonce = bytes.fromhex(release["nonce"])
    # The guest public key hash is part of the release AAD; derive the same salt
    # from the private key's public DER.
    guest_pub_der = private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if _sha256(guest_pub_der).hex() != release["guest_pub_sha256"]:
        raise VerificationError("guest private key does not match release recipient")
    salt = _sha256(nonce + guest_pub_der)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=RELEASE_INFO).derive(shared)
    aad_obj = {
        key_name: release[key_name]
        for key_name in ["version", "algorithm", "domain", "nonce", "guest_pub_sha256", "pcr_sha256"]
    }
    plaintext = AESGCM(key).decrypt(
        base64.b64decode(release["aead_nonce_b64"]),
        base64.b64decode(release["ciphertext_b64"]),
        _canonical_json(aad_obj),
    )
    out.write_bytes(plaintext)


def is_ca(cert: x509.Certificate) -> bool:
    try:
        return cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        return False


def check_cert_time(cert: x509.Certificate) -> None:
    now = datetime.now(UTC)
    before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=UTC)
    after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=UTC)
    if now < before or now > after:
        raise VerificationError(f"certificate outside validity window: {name_cn(cert.subject)}")


def name_cn(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else name.rfc4514_string()


def _bundle_paths(bundle: Path) -> dict[str, Path]:
    return {
        "hcl": bundle / "hcl_report.bin",
        "report": bundle / "report.bin",
        "certs": bundle / "certs",
        "ak_pub": bundle / "akpub.pem",
        "guest_pub": bundle / "guest_x25519.pub.der",
        "nonce": bundle / "nonce.hex",
        "quote_msg": bundle / "quote.msg",
        "quote_sig": bundle / "quote.sig",
        "quote_pcrs": bundle / "quote.pcrs",
    }


def _require(paths: dict[str, Path], *names: str) -> None:
    missing = [str(paths[name]) for name in names if not paths[name].exists()]
    if missing:
        raise VerificationError("missing bundle files: " + ", ".join(missing))


def _read_nonce(path: Path) -> str:
    nonce = "".join(path.read_text().split())
    if len(nonce) != 64:
        raise VerificationError(f"nonce is {len(nonce)} hex chars, expected 64")
    bytes.fromhex(nonce)
    return nonce


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _u64(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 8], "little")


def _version(raw: bytes) -> str:
    if len(raw) != 3:
        return "unknown"
    return f"{raw[2]}.{raw[1]}.{raw[0]}"


def _generation_for_cpuid(family: int | None, model: int | None) -> str:
    # AMD ABI 1.58 gives Turin a different TCB byte layout. Azure DCas v5/v6
    # observations are pre-Turin, but keep the split explicit for portability.
    if family == 0x1A and model is not None and (0x90 <= model <= 0xAF or 0xC0 <= model <= 0xCF):
        return "turin"
    return "pre_turin"


def _b64url_decode(value: str) -> bytes:
    value = value.replace("-", "+").replace("_", "/")
    value += "=" * ((4 - len(value) % 4) % 4)
    return base64.b64decode(value)


def _sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def _canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def _read_secret(path: Path | None) -> bytes | None:
    return None if path is None else path.read_bytes()


def _read_ctx(path: Path | None) -> bytes:
    return b"" if path is None else path.read_bytes()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    challenge = sub.add_parser("challenge", help="issue a fresh verifier nonce")
    challenge.add_argument("bundle", type=Path)

    appraise = sub.add_parser("appraise", help="appraise a file-based evidence bundle")
    appraise.add_argument("bundle", type=Path)
    appraise.add_argument("--roots", type=Path, default=Path("roots/amd"))
    appraise.add_argument("--policy", type=Path)
    appraise.add_argument("--release-secret", type=Path, help="secret bytes to release; random 32B if omitted")
    appraise.add_argument("--release-out", type=Path, help="output directory for release.json")
    appraise.add_argument("--binding-domain", default=DEFAULT_BINDING_DOMAIN)
    appraise.add_argument("--ctx-file", type=Path)
    appraise.add_argument("--json", action="store_true", help="emit machine-readable appraisal result")

    raw = sub.add_parser(
        "appraise-raw",
        help="appraise a raw SNP report (no HCL/vTPM; e.g. ACI Confidential Containers)",
    )
    raw.add_argument("bundle", type=Path)
    raw.add_argument("--roots", type=Path, default=Path("roots/amd"))
    raw.add_argument("--policy", type=Path)
    host_data_group = raw.add_mutually_exclusive_group()
    host_data_group.add_argument("--host-data", help="expected HOST_DATA as 64 hex chars")
    host_data_group.add_argument(
        "--cce-policy-file",
        type=Path,
        help="file holding the base64 CCE policy; expected HOST_DATA = SHA-256 of decoded bytes",
    )
    raw.add_argument("--nonce-hex", help="verifier nonce expected in REPORT_DATA (32 or 64 bytes, hex)")
    raw.add_argument("--measurement", help="expected launch MEASUREMENT as 96 hex chars")
    raw.add_argument("--json", action="store_true", help="emit machine-readable appraisal result")

    unwrap = sub.add_parser("unwrap-for-test", help="test-only guest-side AEAD unwrap proof")
    unwrap.add_argument("release", type=Path)
    unwrap.add_argument("guest_private_key", type=Path)
    unwrap.add_argument("out", type=Path)

    args = parser.parse_args(argv)
    try:
        if args.cmd == "challenge":
            nonce = issue_challenge(args.bundle)
            print(nonce)
            return 0
        if args.cmd == "appraise":
            result = appraise_bundle(
                args.bundle,
                roots_dir=args.roots,
                policy=Policy.from_file(args.policy),
                release_secret=_read_secret(args.release_secret),
                release_dir=args.release_out,
                binding_domain=args.binding_domain,
                ctx=_read_ctx(args.ctx_file),
            )
            if args.json:
                print(result.to_json())
            else:
                for step in result.steps:
                    print(f"PASS {step['name']}: {step['detail']}")
                print(f"ALL CHECKS PASSED; release={result.release_path}")
            return 0
        if args.cmd == "appraise-raw":
            expected_host_data = None
            if args.host_data:
                expected_host_data = bytes.fromhex(args.host_data)
            elif args.cce_policy_file:
                expected_host_data = _sha256(
                    base64.b64decode("".join(args.cce_policy_file.read_text().split()))
                )
            result = appraise_raw_report(
                args.bundle,
                roots_dir=args.roots,
                policy=Policy.from_file(args.policy),
                expected_host_data=expected_host_data,
                nonce_hex=args.nonce_hex,
                expected_measurement=bytes.fromhex(args.measurement) if args.measurement else None,
            )
            if args.json:
                print(result.to_json())
            else:
                for step in result.steps:
                    print(f"PASS {step['name']}: {step['detail']}")
                print("ALL CHECKS PASSED")
            return 0
        if args.cmd == "unwrap-for-test":
            unwrap_release_for_test(args.release, args.guest_private_key, args.out)
            print(f"wrote {args.out}")
            return 0
    except (OSError, ValueError, VerificationError, subprocess.CalledProcessError) as exc:
        if isinstance(exc, subprocess.CalledProcessError):
            detail = exc.stderr.strip() if exc.stderr else str(exc)
        else:
            detail = str(exc)
        print(f"FAIL {detail}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
