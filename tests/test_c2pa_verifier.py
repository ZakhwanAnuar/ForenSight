"""End-to-end tests for the C2PA cryptographic verifier.

These build a *real* signed C2PA manifest (self-signed EC certificate, COSE_Sign1
over the claim, a c2pa.hash.data assertion over the asset bytes) and embed it in
a JPEG via APP11, then confirm the verifier:

  * validates a genuine signature and reports the signer/self-signed status,
  * detects the asset being edited after signing (hash.data mismatch),
  * detects a forged/corrupted signature,
  * detects an assertion being swapped after signing (binding failure).

The builder lives here (test-only) so production code carries no signing path.
"""
from __future__ import annotations

import io
import struct

import pytest

cbor2 = pytest.importorskip("cbor2")
crypto = pytest.importorskip("cryptography")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID
import datetime
import hashlib

from PIL import Image

from forensight import c2pa_verifier as cv

_UUID_SUFFIX = bytes.fromhex("00110010800000aa00389b71")


# ---------------------------------------------------------------------------
# JUMBF builders
# ---------------------------------------------------------------------------
def _box(btype: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + btype + payload


def _jumb(uuid4: bytes, label: str, content: bytes) -> bytes:
    jumd = uuid4 + _UUID_SUFFIX + b"\x03" + label.encode() + b"\x00"
    return _box(b"jumb", _box(b"jumd", jumd) + content)


def _cbor_box(obj) -> bytes:
    return _box(b"cbor", cbor2.dumps(obj))


def _make_cert():
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "ForenSight Test Signer"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ForenSight FYP"),
    ])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    return key, cert


def _cose_sign1(key, cert, payload: bytes, x5_string=False) -> bytes:
    protected = cbor2.dumps({1: -7})                       # alg = ES256
    der = cert.public_bytes(serialization.Encoding.DER)
    # C2PA 2.x uses the integer COSE label 33; C2PA 1.x used the text "x5chain".
    unprotected = {"x5chain": [der]} if x5_string else {33: [der]}
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    der_sig = key.sign(sig_structure, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")   # COSE wants raw r||s
    return cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected, payload, raw]))


def _base_jpeg() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (32, 32), (120, 40, 200)).save(buf, format="JPEG")
    return buf.getvalue()


def _app11(jumbf: bytes) -> bytes:
    body = b"\x4A\x50" + struct.pack(">H", 1) + struct.pack(">I", 1) + jumbf
    return b"\xFF\xEB" + struct.pack(">H", len(body) + 2) + body


def build_signed_jpeg(*, break_sig=False, swap_assertion=False, x5_string=False):
    """Return JPEG bytes carrying a genuine, self-signed C2PA manifest.

    Uses a fixpoint on the exclusion length so the c2pa.hash.data assertion
    excludes exactly the embedded APP11 segment (whose size depends on the
    assertion it contains).
    """
    base = _base_jpeg()
    key, cert = _make_cert()
    asset_hash = hashlib.sha256(base).digest()            # hash of asset sans manifest

    excl_len = 0
    manifest = b""
    for _ in range(6):                                     # converge exclusion length
        hashd = {"exclusions": [{"start": 2, "length": excl_len}],
                 "alg": "sha256", "hash": asset_hash}
        # The claim always commits to the legitimate assertion box's PAYLOAD
        # (everything after the 8-byte JUMBF header), as real C2PA does...
        legit_box = _jumb(b"cbor", "c2pa.hash.data", _cbor_box(hashd))
        a_hash = hashlib.sha256(legit_box[8:]).digest()
        # ...but a swapped run embeds a DIFFERENT assertion, breaking the binding.
        embedded = hashd if not swap_assertion else dict(hashd, hash=b"\x00" * 32)
        embedded_box = _jumb(b"cbor", "c2pa.hash.data", _cbor_box(embedded))
        assertion_store = _jumb(b"c2as", "c2pa.assertions", embedded_box)
        claim = {
            "dc:format": "image/jpeg",
            "instanceID": "xmp:iid:forensight-test",
            "claim_generator": "ForenSightTest/1.0",
            "alg": "sha256",
            "assertions": [{
                "url": "self#jumbf=c2pa.assertions/c2pa.hash.data",
                "hash": a_hash, "alg": "sha256"}],
            "signature": "self#jumbf=c2pa.signature",
        }
        claim_bytes = cbor2.dumps(claim)
        cose = _cose_sign1(key, cert, claim_bytes, x5_string=x5_string)
        if break_sig:                                     # flip a signature byte
            obj = list(cbor2.loads(cose).value)
            sig = bytearray(obj[3]); sig[-1] ^= 0xFF; obj[3] = bytes(sig)
            cose = cbor2.dumps(cbor2.CBORTag(18, obj))
        manifest = _jumb(
            b"c2pa", "c2pa",
            _jumb(b"c2ma", "urn:uuid:forensight-test",
                  assertion_store + _jumb(b"c2cl", "c2pa.claim", _cbor_box(claim))
                  + _jumb(b"c2cs", "c2pa.signature", _box(b"cbor", cose))))
        app11 = _app11(manifest)
        if len(app11) == excl_len:
            break
        excl_len = len(app11)                             # feed back, re-sign

    return base[:2] + app11 + base[2:]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_valid_manifest_verifies_and_asset_intact():
    result = cv.verify_bytes(build_signed_jpeg())
    assert result.present and result.parsed
    assert result.signature_valid is True
    assert result.self_signed is True
    assert "ForenSight Test Signer" in result.signer_subject
    assert result.sig_alg == "ES256"
    assert result.asset_hash_present
    assert result.asset_hash_valid is True
    assert result.assertions_bound is True
    assert result.cryptographically_trustworthy
    assert not result.tampered_after_signing


def test_editing_asset_after_signing_is_detected():
    signed = bytearray(build_signed_jpeg())
    signed[-8] ^= 0xFF                                     # flip a pixel-data byte
    result = cv.verify_bytes(bytes(signed))
    assert result.signature_valid is True                 # manifest itself intact
    assert result.asset_hash_valid is False               # but asset changed
    assert result.tampered_after_signing
    assert not result.cryptographically_trustworthy


def test_forged_signature_is_detected():
    result = cv.verify_bytes(build_signed_jpeg(break_sig=True))
    assert result.present and result.parsed
    assert result.signature_valid is False
    assert not result.cryptographically_trustworthy


def test_swapped_assertion_breaks_binding():
    # The stored hash.data no longer matches the hash the claim committed to.
    result = cv.verify_bytes(build_signed_jpeg(swap_assertion=True))
    assert result.signature_valid is True
    assert result.assertions_bound is False


def test_no_manifest_is_clean():
    result = cv.verify_bytes(_base_jpeg())
    assert not result.present
    assert result.signature_valid is None
    assert result.summary() == ""


def test_summary_wording():
    r = cv.verify_bytes(build_signed_jpeg())
    assert "signature valid and asset intact" in r.summary().lower()


def test_x5chain_text_header_c2pa_v1():
    # C2PA 1.x stores the certificate under the text label "x5chain" (not the
    # integer COSE label 33).  Verified against real Adobe test files.
    result = cv.verify_bytes(build_signed_jpeg(x5_string=True))
    assert result.signature_valid is True
    assert result.cert_count == 1
    assert "ForenSight Test Signer" in result.signer_subject


def test_reassemble_strips_repeated_continuation_header():
    # A JUMBF box split across multiple JPEG APP11 packets repeats its 8-byte
    # LBox+TBox header in each continuation packet; reassembly must drop the
    # duplicate (regression for the multi-segment Adobe manifests).
    box = struct.pack(">I", 8 + 40) + b"jumb" + bytes(range(40))
    p1 = box[:8 + 15]                       # header + first 15 content bytes
    p2 = box[:8] + box[8 + 15:]            # repeated header + remaining content
    assert cv._reassemble([(1, p1), (2, p2)]) == box
    # order-independent: packets given out of sequence still rebuild correctly
    assert cv._reassemble([(2, p2), (1, p1)]) == box
