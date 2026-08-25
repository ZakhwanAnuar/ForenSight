"""Cryptographic verification of C2PA "Content Credentials".

This goes beyond *detecting* that a C2PA manifest is present (see
``provenance_analyzer``): it actually parses the JUMBF manifest, extracts the
signer's X.509 certificate chain and the COSE_Sign1 claim signature, and
**cryptographically verifies**:

  1. **Signature validity** - the claim was signed by the private key matching
     the embedded certificate, and has not been altered since (COSE_Sign1 over
     the claim bytes).
  2. **Signer identity / trust** - the leaf certificate's subject and issuer,
     and whether it is self-signed (i.e. not attributable to a real CA).
  3. **Assertion binding** - each assertion referenced by the claim still hashes
     to the value the claim committed to (so assertions cannot be swapped).
  4. **Asset integrity (tamper check)** - the ``c2pa.hash.data`` assertion holds
     a hash of the asset's own bytes (minus the manifest region). Recomputing it
     over the actual file bytes proves whether the *pixels were modified after
     the credential was signed* - the single most decisive provenance finding a
     forensic tool can make about a C2PA image.

Forensic reading of the outcome:
  * signature VALID + asset hash MATCH  -> the image is bit-for-bit what the
    signer attested (authentic to that signer; trust then hinges on WHO signed).
  * signature VALID + asset hash MISMATCH -> the credential is genuine but the
    image was edited AFTER signing: definitive evidence of post-signing tampering.
  * signature INVALID -> the manifest was forged or corrupted; the credential
    cannot be trusted at all.
  * self-signed signer -> even a valid signature is not independently
    attributable; anyone could have produced it.

Dependencies (``cryptography`` + ``cbor2``) are OPTIONAL and imported lazily -
like pytsk3/tensorflow elsewhere in ForenSight, the tool degrades gracefully:
if they are absent, verification is skipped and the caller falls back to the
string-based certificate inspection in ``provenance_analyzer``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# -- optional crypto stack -------------------------------------------------
try:
    import cbor2
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTO = True
except Exception:  # pragma: no cover - exercised only where deps are missing
    HAS_CRYPTO = False


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------
@dataclass
class C2paVerification:
    """Outcome of cryptographically verifying a C2PA manifest."""

    present: bool = False              # a C2PA/JUMBF manifest was located
    parsed: bool = False              # the manifest structure was parsed OK
    libraries_available: bool = True  # crypto deps were importable

    signature_valid: Optional[bool] = None   # COSE_Sign1 verified? None=unknown
    sig_alg: str = ""                         # e.g. "ES256"
    signer_subject: str = ""                  # leaf cert subject CN/O
    signer_issuer: str = ""                   # leaf cert issuer CN/O
    self_signed: bool = False                 # subject == issuer
    cert_count: int = 0                       # certs in the embedded chain

    assertions_bound: Optional[bool] = None   # claim's assertion hashes match
    asset_hash_present: bool = False          # a c2pa.hash.data assertion exists
    asset_hash_valid: Optional[bool] = None   # asset bytes match signed hash

    manifest_label: str = ""                  # active-manifest URN/label
    claim_generator: str = ""                 # tool that produced the claim
    error: str = ""                           # why verification stopped, if any
    notes: list = field(default_factory=list)

    # -- derived summaries -------------------------------------------------
    @property
    def tampered_after_signing(self) -> bool:
        """True iff the signature is valid but the asset bytes no longer match."""
        return bool(self.signature_valid) and self.asset_hash_valid is False

    @property
    def cryptographically_trustworthy(self) -> bool:
        """Signature valid, assertions bound, and asset bytes intact.

        (Says nothing about WHO signed - a self-signed manifest can be
        internally consistent yet not independently attributable.)"""
        return (self.signature_valid is True
                and self.assertions_bound is not False
                and self.asset_hash_valid is not False)

    def summary(self) -> str:
        """One-line human-readable verdict ('' if no manifest present)."""
        if not self.present:
            return ""
        if not self.libraries_available:
            return "C2PA manifest present (cryptographic verification unavailable)"
        if not self.parsed:
            return f"C2PA manifest present but could not be parsed ({self.error})"
        if self.signature_valid is None:
            return f"C2PA manifest present; signature not verifiable ({self.error})"
        if not self.signature_valid:
            return "C2PA signature INVALID - manifest forged or corrupted"
        # signature is valid from here on
        who = self.signer_subject or "unknown signer"
        trust = "self-signed" if self.self_signed else "CA-issued"
        if self.asset_hash_valid is False:
            return (f"C2PA signature valid ({who}, {trust}) but asset was EDITED "
                    f"after signing (hash mismatch) - post-signing tampering")
        if self.asset_hash_valid is True:
            return (f"C2PA signature valid and asset intact "
                    f"(signed by {who}, {trust})")
        return f"C2PA signature valid (signed by {who}, {trust})"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def verify_file(path) -> C2paVerification:
    """Read *path* and cryptographically verify any embedded C2PA manifest."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return C2paVerification(error=f"read error: {exc}")
    return verify_bytes(data)


def verify_bytes(data: bytes) -> C2paVerification:
    """Cryptographically verify any C2PA manifest embedded in *data*."""
    result = C2paVerification()
    if not HAS_CRYPTO:
        result.libraries_available = False

    manifest, embed_ranges = _extract_manifest(data)
    if manifest is None:
        return result                      # no C2PA present -> present=False
    result.present = True
    if not HAS_CRYPTO:
        result.notes.append("Install 'cryptography' and 'cbor2' to verify.")
        return result

    try:
        _verify_manifest(data, manifest, embed_ranges, result)
    except _ParseError as exc:
        result.error = str(exc)
    except Exception as exc:               # defensive: never crash analysis
        result.error = f"verification error: {type(exc).__name__}: {exc}"
    return result


# ---------------------------------------------------------------------------
# JUMBF / manifest extraction
# ---------------------------------------------------------------------------
class _ParseError(Exception):
    """Recoverable manifest-parsing failure (reported, never raised to caller)."""


# The 12-byte suffix shared by every C2PA JUMBF content-type UUID; the leading
# 4 bytes are the ASCII type ("c2pa", "c2ma", "c2cl", "c2cs", "c2as", "cbor"...).
_C2PA_UUID_SUFFIX = bytes.fromhex("00110010800000aa00389b71")


def _extract_manifest(data: bytes):
    """Locate and return the raw C2PA JUMBF superbox bytes.

    Returns ``(manifest_bytes, embed_ranges)`` where *embed_ranges* is the list
    of ``(start, length)`` byte spans the manifest occupies in *data* (used as
    the default exclusion when checking the asset hash), or ``(None, [])`` if no
    manifest is present.
    """
    if data[:3] == b"\xFF\xD8\xFF":
        return _extract_from_jpeg(data)
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return _extract_from_png(data)
    # Other containers (e.g. raw .c2pa sidecar) - treat the whole file as JUMBF
    # if it starts with a jumb box.
    if len(data) >= 8 and data[4:8] == b"jumb":
        return data, [(0, len(data))]
    return None, []


def _extract_from_jpeg(data: bytes):
    """Reassemble a C2PA manifest carried across JPEG APP11 (0xFFEB) segments.

    Each C2PA APP11 segment payload is: 2-byte common identifier (``0x4A50`` =
    'JP'), 2-byte box-instance number, 4-byte packet-sequence number, then a
    slice of the JUMBF box.  Segments with the same instance number are
    concatenated in packet-sequence order to rebuild the box.
    """
    segments: dict[int, list[tuple[int, bytes]]] = {}
    ranges: list[tuple[int, int]] = []
    pos = 2                                            # skip SOI
    n = len(data)
    while pos + 4 <= n:
        if data[pos] != 0xFF:
            break
        marker = data[pos + 1]
        if marker == 0xD9:                            # EOI
            break
        if 0xD0 <= marker <= 0xD7 or marker == 0x01:  # standalone markers
            pos += 2
            continue
        if marker == 0xDA:                            # start of scan -> no more metadata
            break
        seg_len = int.from_bytes(data[pos + 2:pos + 4], "big")
        seg_start, seg_end = pos, pos + 2 + seg_len
        if marker == 0xEB and seg_len >= 10:          # APP11
            payload = data[pos + 4:seg_end]
            if payload[:2] == b"\x4A\x50":            # 'JP' common identifier
                box_instance = int.from_bytes(payload[2:4], "big")
                packet_seq = int.from_bytes(payload[4:8], "big")
                segments.setdefault(box_instance, []).append(
                    (packet_seq, payload[8:]))
                ranges.append((seg_start, seg_end - seg_start))
        pos = seg_end

    if not segments:
        return None, []
    # Reassemble the box-instance that carries the c2pa manifest store.
    for instance in sorted(segments):
        blob = _reassemble(segments[instance])
        if b"jumb" in blob[:64] or b"c2pa" in blob[:128]:
            return blob, ranges
    # Fall back to the first instance.
    first = sorted(segments)[0]
    return _reassemble(segments[first]), ranges


def _reassemble(chunks: list) -> bytes:
    """Rebuild one JUMBF box from its APP11 packets.

    Per the JPEG/JUMBF embedding (ISO/IEC 19566-5), every APP11 packet of a box
    repeats the box header (LBox+TBox) after the CI/En/Z fields; only the box
    *content* is fragmented across packets.  So the first packet contributes the
    header plus its content, and each continuation packet contributes only its
    content (its repeated header must be stripped) - otherwise the duplicated
    headers shift every subsequent box boundary and parsing derails.
    """
    ordered = [c for _, c in sorted(chunks)]
    if not ordered:
        return b""
    first = ordered[0]
    header = 16 if int.from_bytes(first[:4], "big") == 1 else 8  # XLBox vs LBox
    out = bytearray(first)
    for cont in ordered[1:]:
        out += cont[header:]                       # drop the repeated LBox+TBox
    return bytes(out)


def _extract_from_png(data: bytes):
    """Return the JUMBF box from a PNG ``caBX`` chunk (C2PA in PNG)."""
    pos = 8
    n = len(data)
    while pos + 8 <= n:
        length = int.from_bytes(data[pos:pos + 4], "big")
        ctype = data[pos + 4:pos + 8]
        chunk_start = pos
        data_start = pos + 8
        data_end = data_start + length
        if ctype == b"caBX":
            return data[data_start:data_end], [(chunk_start, data_end + 4 - chunk_start)]
        pos = data_end + 4                             # skip CRC
        if ctype == b"IEND":
            break
    return None, []


# ---------------------------------------------------------------------------
# JUMBF box tree
# ---------------------------------------------------------------------------
@dataclass
class _Box:
    type: bytes                    # 4-byte box type ('jumb','jumd','cbor',...)
    payload: bytes                 # box content (after the header)
    raw: bytes = b""               # the entire box (header + payload)
    uuid_type: bytes = b""         # for a jumb superbox: its jumd content UUID
    label: str = ""                # for a jumb superbox: its jumd label
    children: list = field(default_factory=list)


def _parse_boxes(blob: bytes) -> list:
    """Parse a sequence of ISOBMFF-style boxes into ``_Box`` objects."""
    boxes = []
    pos, n = 0, len(blob)
    while pos + 8 <= n:
        lbox = int.from_bytes(blob[pos:pos + 4], "big")
        tbox = blob[pos + 4:pos + 8]
        header = 8
        if lbox == 1:                                 # 64-bit extended length
            if pos + 16 > n:
                break
            lbox = int.from_bytes(blob[pos + 8:pos + 16], "big")
            header = 16
        elif lbox == 0:                               # extends to end of blob
            lbox = n - pos
        if lbox < header or pos + lbox > n:
            break
        payload = blob[pos + header:pos + lbox]
        box = _Box(type=tbox, payload=payload, raw=blob[pos:pos + lbox])
        if tbox == b"jumb":                           # superbox -> parse jumd + children
            _parse_superbox(box)
        boxes.append(box)
        pos += lbox
    return boxes


def _parse_superbox(box: _Box) -> None:
    """Fill in a jumb superbox's UUID type, label and child boxes from its jumd."""
    children = _parse_boxes(box.payload)
    box.children = children
    if children and children[0].type == b"jumd":
        jumd = children[0].payload
        if len(jumd) >= 17:
            box.uuid_type = jumd[:4]                   # ASCII content type
            toggles = jumd[16]
            rest = jumd[17:]
            if toggles & 0x02:                         # label present (null-terminated)
                end = rest.find(b"\x00")
                box.label = (rest if end == -1 else rest[:end]).decode(
                    "utf-8", "replace")


def _find(boxes: list, uuid4: bytes):
    """Depth-first: first jumb box whose jumd UUID starts with *uuid4*."""
    for b in boxes:
        if b.type == b"jumb" and b.uuid_type == uuid4:
            return b
        hit = _find(b.children, uuid4)
        if hit is not None:
            return hit
    return None


def _find_all(boxes: list, uuid4: bytes) -> list:
    out = []
    for b in boxes:
        if b.type == b"jumb" and b.uuid_type == uuid4:
            out.append(b)
        out.extend(_find_all(b.children, uuid4))
    return out


def _content_bytes(superbox: _Box) -> bytes:
    """Return the raw content box payload inside a c2cl/c2cs/assertion superbox
    (the box after the jumd - typically a 'cbor' or 'json' box)."""
    for child in superbox.children:
        if child.type in (b"cbor", b"json", b"bfdb", b"bidb", b"uuid"):
            return child.payload
    # fall back: first non-jumd child
    for child in superbox.children:
        if child.type != b"jumd":
            return child.payload
    return b""


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
def _verify_manifest(data: bytes, manifest: bytes, embed_ranges, result) -> None:
    boxes = _parse_boxes(manifest)
    store = _find(boxes, b"c2pa")                      # manifest store
    search_root = store.children if store is not None else boxes

    # Active manifest = last standard/update manifest in the store.
    manifests = _find_all(search_root, b"c2ma") + _find_all(search_root, b"c2ua")
    active = manifests[-1] if manifests else None
    root = active.children if active is not None else search_root
    if active is not None:
        result.manifest_label = active.label

    claim_box = _find(root, b"c2cl")
    sig_box = _find(root, b"c2cs")
    astore = _find(root, b"c2as")
    if claim_box is None or sig_box is None:
        raise _ParseError("claim or claim-signature box not found")
    result.parsed = True

    claim_bytes = _content_bytes(claim_box)
    cose_bytes = _content_bytes(sig_box)
    try:
        claim = cbor2.loads(claim_bytes)
    except Exception as exc:
        raise _ParseError(f"claim CBOR invalid: {exc}")
    claim = dict(claim) if hasattr(claim, "keys") else None
    if claim is not None:
        result.claim_generator = _generator_name(
            claim.get("claim_generator") or claim.get("claim_generator_info"))

    # (1) COSE_Sign1 signature over the claim ------------------------------
    _verify_cose(cose_bytes, claim_bytes, result)

    # (2) assertion binding + (3) asset-hash / tamper check ----------------
    if astore is not None and claim is not None:
        _verify_assertions(data, claim, astore, embed_ranges, result)


def _verify_cose(cose_bytes: bytes, claim_bytes: bytes, result) -> None:
    """Verify a COSE_Sign1 structure and extract the signer certificate."""
    try:
        obj = cbor2.loads(cose_bytes)
    except Exception as exc:
        raise _ParseError(f"COSE CBOR invalid: {exc}")
    if hasattr(obj, "value"):                          # CBORTag(18, [...])
        obj = obj.value
    if not (isinstance(obj, (list, tuple)) and len(obj) == 4):
        raise _ParseError("not a COSE_Sign1 structure")
    protected_bstr, unprotected, payload, signature = obj

    # COSE header maps decode as dict OR cbor2.frozendict; normalise to plain
    # dicts so lookups (alg, x5chain) work regardless of the decoder.
    protected = {}
    if protected_bstr:
        try:
            protected = dict(cbor2.loads(protected_bstr) or {})
        except Exception:
            protected = {}
    unprotected = dict(unprotected) if hasattr(unprotected, "keys") else {}

    alg = protected.get(1)
    if alg is None:
        alg = unprotected.get(1)

    # Certificate chain: registered COSE label 33, or the text label "x5chain"
    # used by earlier C2PA versions (Adobe 1.x).  Check protected then unprotected.
    x5 = None
    for hdr in (protected, unprotected):
        if 33 in hdr:
            x5 = hdr[33]; break
        if "x5chain" in hdr:
            x5 = hdr["x5chain"]; break
    certs = _load_certs(x5)
    result.cert_count = len(certs)
    if not certs:
        result.error = "no signer certificate in manifest"
        return
    leaf = certs[0]
    result.signer_subject = _name(leaf.subject)
    result.signer_issuer = _name(leaf.issuer)
    result.self_signed = (leaf.subject == leaf.issuer)

    # Detached payload -> use the claim bytes as the signed payload.
    signed_payload = payload if payload is not None else claim_bytes
    sig_structure = cbor2.dumps(
        ["Signature1", protected_bstr or b"", b"", signed_payload])

    result.sig_alg = _ALG_NAMES.get(alg, str(alg))
    try:
        _check_signature(leaf.public_key(), alg, signature, sig_structure)
        result.signature_valid = True
        result.notes.append(
            f"COSE_Sign1 signature verified ({result.sig_alg}) against embedded "
            f"certificate.")
    except InvalidSignature:
        result.signature_valid = False
        result.notes.append("COSE_Sign1 signature FAILED verification.")
    except Exception as exc:
        result.signature_valid = None
        result.error = f"signature check error: {exc}"


def _verify_assertions(data, claim, astore, embed_ranges, result) -> None:
    """Confirm each claim-referenced assertion hashes correctly, then verify the
    c2pa.hash.data assertion against the actual asset bytes (tamper check)."""
    # Map assertion label -> content bytes (the CBOR/JSON payload) and to the
    # full JUMBF box (what the claim's hashed-URI actually commits to).
    content_by_label: dict[str, bytes] = {}
    box_by_label: dict[str, bytes] = {}
    for a in astore.children:
        if a.type == b"jumb" and a.label:
            content_by_label[a.label] = _content_bytes(a)
            # C2PA hashes the assertion box PAYLOAD (its jumd + content boxes),
            # i.e. everything after the outer JUMBF header - which is a.payload.
            box_by_label[a.label] = a.payload

    # (2) Assertion binding: the claim commits to a hash of each assertion's
    # whole JUMBF box (C2PA hashed URI), so swapping an assertion is detected.
    # C2PA v1 uses "assertions"; v2 (specVersion 2.x) splits them into
    # "created_assertions" and "gathered_assertions".
    refs = list(claim.get("assertions") or [])
    refs += list(claim.get("created_assertions") or [])
    refs += list(claim.get("gathered_assertions") or [])
    claim_alg = _hash_name(claim.get("alg"))
    bound = True
    checked_any = False
    for ref in refs:
        if not hasattr(ref, "get"):
            continue
        url = str(ref.get("url", ""))
        want = ref.get("hash")
        label = url.rsplit("/", 1)[-1] if "/" in url else url
        box_bytes = box_by_label.get(label)
        if box_bytes is None or not isinstance(want, (bytes, bytearray)):
            continue
        checked_any = True
        alg = _hash_name(ref.get("alg")) or claim_alg or "sha256"
        if _digest(box_bytes, alg) != bytes(want):
            bound = False
    if checked_any:
        result.assertions_bound = bound
        result.notes.append(
            "Claim-to-assertion hash binding "
            + ("verified." if bound else "FAILED - an assertion was altered."))

    # (3) Asset integrity: c2pa.hash.data
    hd_label = next((lbl for lbl in content_by_label if lbl.endswith("hash.data")), "")
    if not hd_label:
        return
    result.asset_hash_present = True
    try:
        assertion = cbor2.loads(content_by_label[hd_label])
    except Exception as exc:
        result.notes.append(f"hash.data assertion unreadable: {exc}")
        return
    if not hasattr(assertion, "get"):
        return
    stored = assertion.get("hash")
    alg = _hash_name(assertion.get("alg")) or "sha256"
    exclusions = assertion.get("exclusions") or []
    ranges = [(int(e["start"]), int(e["length"])) for e in exclusions
              if hasattr(e, "get") and "start" in e and "length" in e]
    if not ranges:                                     # default to the embed spans
        ranges = embed_ranges
    computed = _digest(_apply_exclusions(data, ranges), alg)
    if isinstance(stored, (bytes, bytearray)):
        result.asset_hash_valid = (computed == bytes(stored))
        result.notes.append(
            "Asset-hash (c2pa.hash.data) "
            + ("matches - pixels intact since signing."
               if result.asset_hash_valid
               else "MISMATCH - asset bytes changed after signing."))


# ---------------------------------------------------------------------------
# crypto helpers
# ---------------------------------------------------------------------------
_ALG_NAMES = {-7: "ES256", -35: "ES384", -36: "ES512", -8: "EdDSA",
              -37: "PS256", -38: "PS384", -39: "PS512",
              -257: "RS256", -258: "RS384", -259: "RS512"}


def _load_certs(x5) -> list:
    """Load DER certificates from a COSE x5chain header value."""
    if x5 is None:
        return []
    items = list(x5) if isinstance(x5, (list, tuple)) else [x5]
    certs = []
    for der in items:
        if isinstance(der, (bytes, bytearray)):
            try:
                certs.append(x509.load_der_x509_certificate(bytes(der)))
            except Exception:
                pass
    return certs


def _check_signature(pubkey, alg, signature, sig_structure) -> None:
    """Verify *signature* over *sig_structure*; raise InvalidSignature on failure."""
    signature = bytes(signature)
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        hash_alg = {-7: hashes.SHA256(), -35: hashes.SHA384(),
                    -36: hashes.SHA512()}.get(alg, hashes.SHA256())
        # COSE ECDSA signatures are raw r||s; convert to DER for cryptography.
        half = len(signature) // 2
        r = int.from_bytes(signature[:half], "big")
        s = int.from_bytes(signature[half:], "big")
        pubkey.verify(encode_dss_signature(r, s), sig_structure,
                      ec.ECDSA(hash_alg))
    elif isinstance(pubkey, ed25519.Ed25519PublicKey):
        pubkey.verify(signature, sig_structure)
    elif isinstance(pubkey, rsa.RSAPublicKey):
        if alg in (-37, -38, -39):                     # PSS
            hash_alg = {-37: hashes.SHA256(), -38: hashes.SHA384(),
                        -39: hashes.SHA512()}.get(alg, hashes.SHA256())
            pubkey.verify(signature, sig_structure,
                          padding.PSS(mgf=padding.MGF1(hash_alg),
                                      salt_length=padding.PSS.DIGEST_LENGTH),
                          hash_alg)
        else:                                          # PKCS#1 v1.5
            hash_alg = {-257: hashes.SHA256(), -258: hashes.SHA384(),
                        -259: hashes.SHA512()}.get(alg, hashes.SHA256())
            pubkey.verify(signature, sig_structure, padding.PKCS1v15(), hash_alg)
    else:
        raise ValueError(f"unsupported key type: {type(pubkey).__name__}")


def _name(name) -> str:
    """Human-readable subject/issuer: 'CN=... , O=...' collapsed to CN or O."""
    try:
        cn = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        org = name.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
        parts = [a.value for a in (cn + org)]
        return ", ".join(dict.fromkeys(parts)) or name.rfc4514_string()
    except Exception:
        try:
            return name.rfc4514_string()
        except Exception:
            return ""


def _generator_name(gen) -> str:
    """Human-readable claim-generator name across C2PA v1 (string) and v2 (a
    map like {'name': 'OpenAI Media Service API', 'version': ...}, or a list)."""
    if gen is None:
        return ""
    if isinstance(gen, str):
        return gen
    if hasattr(gen, "get"):
        name = gen.get("name") or ""
        ver = gen.get("version") or ""
        return f"{name} {ver}".strip() if name else ""
    if isinstance(gen, (list, tuple)):
        names = [_generator_name(g) for g in gen]
        return ", ".join(n for n in names if n)
    return str(gen)


def _hash_name(alg) -> str:
    if isinstance(alg, str):
        return alg.lower().replace("-", "")
    return ""


def _digest(data: bytes, alg: str) -> bytes:
    import hashlib
    alg = (alg or "sha256").lower().replace("-", "")
    func = {"sha256": hashlib.sha256, "sha384": hashlib.sha384,
            "sha512": hashlib.sha512}.get(alg, hashlib.sha256)
    return func(data).digest()


def _apply_exclusions(data: bytes, ranges) -> bytes:
    """Return *data* with the given (start, length) byte ranges removed."""
    if not ranges:
        return data
    spans = sorted((max(0, s), max(0, s) + max(0, l)) for s, l in ranges)
    out = bytearray()
    cursor = 0
    for start, end in spans:
        if start > cursor:
            out += data[cursor:start]
        cursor = max(cursor, end)
    out += data[cursor:]
    return bytes(out)
