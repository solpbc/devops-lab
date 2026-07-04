#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Hardware-free tests for verifier.py."""

from __future__ import annotations

import base64
import json
import shutil
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import verifier

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class SyntheticQuoteVerifier:
    def verify(self, ak_pub: Path, quote_msg: Path, quote_sig: Path, quote_pcrs: Path, binding_hex: str) -> None:
        del ak_pub, quote_sig, quote_pcrs
        expected = quote_msg.read_text().strip()
        if expected != binding_hex:
            raise verifier.VerificationError("synthetic quote extraData mismatch")


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp_s:
        tmp = Path(tmp_s)
        fixture = build_fixture(tmp)
        secret = b"test secret for python verifier".ljust(32, b"\x00")
        release_dir = tmp / "release"
        policy = verifier.Policy(pcr_mode="pin", pcr_pins={fixture["pcr_sha256"]})

        print("== positive appraisal ==")
        result = verifier.appraise_bundle(
            fixture["bundle"],
            roots_dir=fixture["roots"],
            policy=policy,
            release_secret=secret,
            release_dir=release_dir,
            quote_verifier=SyntheticQuoteVerifier(),
        )
        recovered = tmp / "recovered.bin"
        verifier.unwrap_release_for_test(Path(result.release_path), fixture["guest_key"], recovered)
        assert recovered.read_bytes() == secret
        ok("appraisal passes and AES-GCM release round-trips")

        print("\n== negative cases ==")
        expect_fail("tampered report_data rejected", lambda: appraise_mutated(fixture, tamper_report_data))
        expect_fail("wrong nonce rejected", lambda: appraise_mutated(fixture, wrong_nonce))
        expect_fail("wrong guest key rejected", lambda: appraise_mutated(fixture, wrong_guest_key))
        expect_fail("bad measurement rejected", lambda: appraise_mutated(fixture, bad_pcr_measurement))
        expect_fail("debug-enabled report rejected", lambda: appraise_mutated(fixture, debug_report))
        expect_fail("bad AMD report signature rejected", lambda: appraise_mutated(fixture, bad_report_signature))
        expect_fail("invalid TCB policy rejected", lambda: load_bad_tcb_policy(tmp))

        print("\n== raw-report appraisal (ACI path) ==")
        raw = build_raw_fixture(tmp)
        raw_result = verifier.appraise_raw_report(
            raw["bundle"],
            roots_dir=raw["roots"],
            policy=verifier.Policy(),
            expected_host_data=raw["host_data"],
            nonce_hex=raw["nonce_hex"],
        )
        assert raw_result.host_data == raw["host_data"].hex()
        assert raw_result.chip_id is not None
        ok("raw appraisal passes with nonce + HOST_DATA")
        expect_fail(
            "raw: wrong HOST_DATA rejected",
            lambda: verifier.appraise_raw_report(
                raw["bundle"],
                roots_dir=raw["roots"],
                policy=verifier.Policy(),
                expected_host_data=b"\x00" * 32,
                nonce_hex=raw["nonce_hex"],
            ),
        )
        expect_fail(
            "raw: wrong nonce rejected",
            lambda: verifier.appraise_raw_report(
                raw["bundle"],
                roots_dir=raw["roots"],
                policy=verifier.Policy(),
                expected_host_data=raw["host_data"],
                nonce_hex="22" * 64,
            ),
        )
        expect_fail(
            "raw: wrong measurement rejected",
            lambda: verifier.appraise_raw_report(
                raw["bundle"],
                roots_dir=raw["roots"],
                policy=verifier.Policy(),
                expected_measurement=b"\xff" * 48,
            ),
        )
        expect_fail(
            "raw: tampered report rejected",
            lambda: verifier.appraise_raw_report(
                raw["tampered_bundle"],
                roots_dir=raw["roots"],
                policy=verifier.Policy(),
            ),
        )

        report_bytes = bytearray((raw["bundle"] / "report.bin").read_bytes())
        report_bytes[0x1A0:0x1E0] = bytes(range(64))
        parsed = verifier.SnpReport.parse(bytes(report_bytes))
        url = verifier.vcek_url(parsed, verifier.VCEK_SOURCES["kds"])
        assert "/vcek/v1/Milan/" in url, url
        assert url.endswith("blSPL=4&teeSPL=0&snpSPL=24&ucodeSPL=219"), url
        assert bytes(range(64)).hex() in url
        ok("vcek URL built from CHIP_ID + reported TCB")
        zeroed = verifier.SnpReport.parse((raw["bundle"] / "report.bin").read_bytes())
        expect_fail(
            "vcek: zeroed CHIP_ID rejected",
            lambda: verifier.vcek_url(zeroed, verifier.VCEK_SOURCES["kds"]),
        )

    print("\n== summary: 15 passed, 0 failed ==")
    return 0


def appraise_mutated(fixture: dict[str, object], mutator) -> None:
    with tempfile.TemporaryDirectory() as tmp_s:
        tmp = Path(tmp_s)
        bundle = tmp / "bundle"
        shutil.copytree(fixture["bundle"], bundle)
        mutator(bundle, fixture)
        policy = verifier.Policy(pcr_mode="pin", pcr_pins={fixture["pcr_sha256"]})
        verifier.appraise_bundle(
            bundle,
            roots_dir=fixture["roots"],
            policy=policy,
            release_secret=b"x" * 32,
            release_dir=tmp / "release",
            quote_verifier=SyntheticQuoteVerifier(),
        )


def expect_fail(label: str, fn) -> None:
    try:
        fn()
    except verifier.VerificationError:
        ok(label)
        return
    raise AssertionError(label)


def ok(label: str) -> None:
    print(f"  ok   - {label}")


def load_bad_tcb_policy(tmp: Path) -> verifier.Policy:
    path = tmp / "bad-policy.json"
    path.write_text(json.dumps({"min_tcb": {"reported": {"snp": "not-a-byte"}}}))
    return verifier.Policy.from_file(path)


def build_fixture(tmp: Path) -> dict[str, Path | str]:
    roots = tmp / "roots"
    bundle = tmp / "bundle"
    certs = bundle / "certs"
    (roots / "Test").mkdir(parents=True)
    certs.mkdir(parents=True)

    ark_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ask_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    vcek_key = ec.generate_private_key(ec.SECP384R1())
    ark_cert = make_cert("ARK-Test", "ARK-Test", ark_key.public_key(), ark_key, is_ca=True)
    ask_cert = make_cert("SEV-Test", "ARK-Test", ask_key.public_key(), ark_key, is_ca=True)
    vcek_cert = make_cert("VCEK-Test", "SEV-Test", vcek_key.public_key(), ask_key, is_ca=False)
    write_pem(roots / "Test" / "ark.pem", ark_cert)
    write_pem(roots / "Test" / "ask.pem", ask_cert)
    write_pem(certs / "vcek.pem", vcek_cert)

    ak_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ak_pub_pem = ak_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (bundle / "akpub.pem").write_bytes(ak_pub_pem)

    guest_key = x25519.X25519PrivateKey.generate()
    guest_key_path = bundle / "guest_x25519.key"
    guest_key_path.write_bytes(
        guest_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    guest_pub_der = guest_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (bundle / "guest_x25519.pub.der").write_bytes(guest_pub_der)

    runtime = make_runtime_json(ak_key.public_key())
    report = make_report(runtime, vcek_key)
    hcla = make_hcla(report, runtime)
    (bundle / "hcl_report.bin").write_bytes(hcla)
    (bundle / "report.bin").write_bytes(report)

    nonce = "11" * 32
    (bundle / "nonce.hex").write_text(nonce + "\n")
    binding = verifier.binding_hash(verifier.DEFAULT_BINDING_DOMAIN, bytes.fromhex(nonce), guest_pub_der)
    (bundle / "quote.msg").write_text(binding.hex() + "\n")
    (bundle / "quote.sig").write_bytes(b"synthetic")
    (bundle / "quote.pcrs").write_bytes(b"synthetic-pcr-state")

    return {
        "roots": roots,
        "bundle": bundle,
        "guest_key": guest_key_path,
        "pcr_sha256": verifier._sha256(b"synthetic-pcr-state").hex(),
        "vcek_key": vcek_key,
    }


def build_raw_fixture(tmp: Path) -> dict[str, object]:
    """Raw-report bundle (report.bin + certs/ only) mimicking the ACI CoCo path."""
    roots = tmp / "raw-roots"
    bundle = tmp / "raw-bundle"
    certs = bundle / "certs"
    (roots / "Test").mkdir(parents=True)
    certs.mkdir(parents=True)

    ark_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ask_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    vcek_key = ec.generate_private_key(ec.SECP384R1())
    ark_cert = make_cert("ARK-Raw", "ARK-Raw", ark_key.public_key(), ark_key, is_ca=True)
    ask_cert = make_cert("SEV-Raw", "ARK-Raw", ask_key.public_key(), ark_key, is_ca=True)
    vcek_cert = make_cert("VCEK-Raw", "SEV-Raw", vcek_key.public_key(), ask_key, is_ca=False)
    write_pem(roots / "Test" / "ark.pem", ark_cert)
    write_pem(roots / "Test" / "ask.pem", ask_cert)
    write_pem(certs / "vcek.pem", vcek_cert)

    nonce = bytes(range(64))
    host_data = verifier._sha256(b"synthetic-cce-policy")
    report = make_report(b"", vcek_key, report_data=nonce, host_data=host_data)
    (bundle / "report.bin").write_bytes(report)

    tampered_bundle = tmp / "raw-bundle-tampered"
    (tampered_bundle / "certs").mkdir(parents=True)
    write_pem(tampered_bundle / "certs" / "vcek.pem", vcek_cert)
    tampered = bytearray(report)
    tampered[0x090] ^= 0xFF  # flip a measurement byte after signing
    (tampered_bundle / "report.bin").write_bytes(bytes(tampered))

    return {
        "roots": roots,
        "bundle": bundle,
        "tampered_bundle": tampered_bundle,
        "host_data": host_data,
        "nonce_hex": nonce.hex(),
    }


def make_cert(subject_cn: str, issuer_cn: str, public_key, issuer_key, *, is_ca: bool) -> x509.Certificate:
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None), critical=True)
    )
    if not is_ca:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA384())


def write_pem(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def make_runtime_json(ak_public_key) -> bytes:
    n = ak_public_key.public_numbers().n.to_bytes(256, "big")
    runtime = {
        "keys": [
            {
                "kid": "HCLAkPub",
                "kty": "RSA",
                "e": "AQAB",
                "n": b64url(n),
            }
        ],
        "vm-configuration": {
            "secure-boot": True,
            "tpm-enabled": True,
            "vmUniqueId": "00000000-0000-0000-0000-000000000000",
        },
    }
    return json.dumps(runtime, sort_keys=True, separators=(",", ":")).encode()


def make_report(
    runtime_json: bytes,
    vcek_key,
    *,
    debug: bool = False,
    report_data: bytes | None = None,
    host_data: bytes | None = None,
) -> bytes:
    report = bytearray(1184)
    put_u32(report, 0x000, 5)
    put_u32(report, 0x004, 10)
    policy = 0x00030000 | ((1 << 19) if debug else 0)
    put_u64(report, 0x008, policy)
    put_u32(report, 0x030, 0)
    put_u32(report, 0x034, 1)
    tcb = bytes([4, 0, 0, 0, 0, 0, 24, 219])
    report[0x038 : 0x040] = tcb
    report[0x180 : 0x188] = tcb
    report[0x188] = 0x19
    report[0x189] = 0x01
    report[0x18A] = 0x00
    report[0x1E0 : 0x1E8] = tcb
    report[0x1E8 : 0x1EB] = bytes([29, 55, 1])
    report[0x1EC : 0x1EF] = bytes([29, 55, 1])
    report[0x1F0 : 0x1F8] = tcb
    if report_data is None:
        runtime_hash = verifier._sha256(runtime_json)
        report[0x050 : 0x070] = runtime_hash
        report[0x070 : 0x090] = b"\x00" * 32
    else:
        report[0x050 : 0x090] = report_data
    if host_data is not None:
        report[0x0C0 : 0x0E0] = host_data
    der_sig = vcek_key.sign(bytes(report[:0x2A0]), ec.ECDSA(hashes.SHA384()))
    r, s = utils.decode_dss_signature(der_sig)
    report[0x2A0 : 0x2A0 + 72] = r.to_bytes(72, "little")
    report[0x2A0 + 72 : 0x2A0 + 144] = s.to_bytes(72, "little")
    return bytes(report)


def make_hcla(report: bytes, runtime_json: bytes) -> bytes:
    header = bytearray(32)
    header[:4] = b"HCLA"
    put_u32(header, 4, 1)
    put_u32(header, 8, len(report))
    put_u32(header, 12, 2)
    metadata = b"".join(
        [
            (20).to_bytes(4, "little"),
            (2).to_bytes(4, "little"),
            (2).to_bytes(4, "little"),
            (1).to_bytes(4, "little"),
            len(runtime_json).to_bytes(4, "little"),
        ]
    )
    return bytes(header) + report + metadata + runtime_json + (b"\x00" * 64)


def tamper_report_data(bundle: Path, fixture: dict[str, object]) -> None:
    del fixture
    hcla = bytearray((bundle / "hcl_report.bin").read_bytes())
    hcla[32 + 0x50] ^= 0xFF
    (bundle / "hcl_report.bin").write_bytes(hcla)


def wrong_nonce(bundle: Path, fixture: dict[str, object]) -> None:
    del fixture
    (bundle / "nonce.hex").write_text(("22" * 32) + "\n")


def wrong_guest_key(bundle: Path, fixture: dict[str, object]) -> None:
    del fixture
    other = x25519.X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (bundle / "guest_x25519.pub.der").write_bytes(other)


def bad_pcr_measurement(bundle: Path, fixture: dict[str, object]) -> None:
    del fixture
    (bundle / "quote.pcrs").write_bytes(b"different-pcr-state")


def debug_report(bundle: Path, fixture: dict[str, object]) -> None:
    runtime_json = verifier.extract_runtime_json((bundle / "hcl_report.bin").read_bytes())
    report = make_report(runtime_json, fixture["vcek_key"], debug=True)
    (bundle / "hcl_report.bin").write_bytes(make_hcla(report, runtime_json))
    (bundle / "report.bin").write_bytes(report)


def bad_report_signature(bundle: Path, fixture: dict[str, object]) -> None:
    del fixture
    hcla = bytearray((bundle / "hcl_report.bin").read_bytes())
    hcla[32 + 0x2A0] ^= 0x01
    (bundle / "hcl_report.bin").write_bytes(hcla)


def put_u32(buf: bytearray, off: int, value: int) -> None:
    buf[off : off + 4] = value.to_bytes(4, "little")


def put_u64(buf: bytearray, off: int, value: int) -> None:
    buf[off : off + 8] = value.to_bytes(8, "little")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


if __name__ == "__main__":
    raise SystemExit(main())
