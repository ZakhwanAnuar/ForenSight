"""Content-provenance detection: C2PA / AI-generation metadata markers.

Transparent and rule-based - NO AI/ML.  This does NOT look at pixels to guess
whether an image is AI-generated (that would require a trained model, which is
deliberately out of scope).  Instead it reads *standardised provenance metadata*
that generative and editing tools embed in the file itself:

  * C2PA "Content Credentials" - a signed JUMBF manifest (markers: ``c2pa``,
    ``jumbf``/``jumd`` boxes, ``urn:c2pa``);
  * the IPTC/C2PA ``digitalSourceType`` value ``trainedAlgorithmicMedia`` (and
    ``compositeWithTrainedAlgorithmicMedia``), the official declaration that the
    media was produced or edited by a generative model;
  * known generator identifiers (Grok, Firefly, DALL-E, Midjourney, Stable
    Diffusion, Google/Gemini/SynthID, OpenAI, ...).

Forensic reading:
  * An explicit AI marker is an *authoritative self-declaration* that the image
    is AI-generated/edited - a strong manipulation indicator.
  * A C2PA manifest WITHOUT an AI marker is only informational: Content
    Credentials are also used to assert authenticity (e.g. by cameras), so mere
    presence is NOT treated as manipulation.
  * Absence proves nothing - provenance metadata is easily stripped.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import signatures
from . import c2pa_verifier

# How many bytes to scan.  C2PA manifests sit near the start, but some tools
# append them; images are small, so scanning the whole (bounded) file is cheap.
_MAX_SCAN = 32 * 1024 * 1024

# Definitive "this is AI-generated/edited" markers (C2PA digitalSourceType).
# Stored lower-case because matching is done against a lower-cased copy.
_AI_SOURCE_MARKERS = (
    b"trainedalgorithmicmedia",
    b"compositewithtrainedalgorithmicmedia",
    b"algorithmicmedia",
)

# C2PA container markers (provenance present; not by itself manipulation).
# Matched (lower-cased) but the short 'c2pa' token is only trusted alongside a
# JUMBF box, so a stray 4-byte match in binary noise is not mistaken for a
# manifest.
_C2PA_STRONG = (b"jumbf", b"urn:c2pa", b"contentcredentials", b"content_credentials")

# Known generative-tool signatures -> friendly name.  These are matched
# CASE-SENSITIVELY against the raw bytes and are specific multi-character strings
# (usually multi-word), so they do not collide with random binary data the way a
# bare token like b"grok" does (which matched a hash blob 'gRoKC...' and caused a
# Gemini image to be mislabelled as Grok).  Order = most specific first.
_GENERATOR_SIGNATURES = (
    (b"Grok Imagine", "xAI Grok Imagine"),
    (b"Adobe Firefly", "Adobe Firefly"),
    (b"Gemini", "Google Gemini"),
    (b"Google Generative", "Google Generative AI"),
    (b"Google C2PA", "Google Generative AI"),
    (b"SynthID", "Google (SynthID watermark)"),
    (b"Imagen", "Google Imagen"),
    (b"Made with Google AI", "Google Generative AI"),
    (b"gpt-image", "OpenAI GPT Image"),
    (b"DALL-E", "OpenAI DALL-E"),
    (b"DALL\xc2\xb7E", "OpenAI DALL-E"),
    (b"Midjourney", "Midjourney"),
    (b"Stable Diffusion", "Stable Diffusion"),
    (b"Stability AI", "Stability AI"),
    (b"Leonardo.Ai", "Leonardo.Ai"),
    (b"Firefly", "Adobe Firefly"),
)

# -- Credential trust (certificate inspection) -----------------------------
# NOTE: this INSPECTS the C2PA signing certificate's type and issuer; it does
# not (yet) cryptographically verify the signature against the C2PA trust list -
# that would need the full c2pa SDK (future work).  Even so, a self-signed /
# ephemeral / local certificate is a clear red flag that the claim is NOT
# independently verifiable and could have been produced by anyone.
TRUST_CA_ISSUED = "ca-issued"        # chains to a root CA (attributable issuer)
TRUST_SELF_SIGNED = "self-signed"    # self-signed / ephemeral - not verifiable
TRUST_UNKNOWN = "unknown"            # C2PA present but signer type unclear
TRUST_INVALID = "invalid"            # signature cryptographically FAILED

_SELF_SIGNED_MARKERS = (b"Self-signed", b"self-signed", b"ephemeral",
                        b"LOCAL USE", b"ephemeral-ca", b".local")

# Recognised C2PA signing issuers (certificate subject organisation).
_KNOWN_ISSUERS = (
    (b"Google LLC", "Google LLC"), (b"OpenAI", "OpenAI"),
    (b"Adobe", "Adobe"), (b"Truepic", "Truepic"), (b"Leica", "Leica"),
    (b"Sony", "Sony"), (b"Nikon", "Nikon"), (b"Microsoft", "Microsoft"),
    (b"Meta Platforms", "Meta"), (b"xAI", "xAI"),
)

# Photo/video EDITING apps (not necessarily AI) whose name is left in metadata.
# Detecting one means the image was processed by editing software - a manipulation
# *indicator*, not proof.  Matched CASE-SENSITIVELY, and ONLY within the file's
# metadata region (see _metadata_region) - never against pixel data, where short
# names like b"GIMP" collide with photo bytes by chance.  The list comes from the
# single shared source (see forensight/signatures.py) so it cannot drift from the
# EXIF Software check in exif_engine.
_EDITOR_SIGNATURES = signatures.editor_bytes()


@dataclass
class ProvenanceResult:
    detected: bool = False          # any provenance metadata found
    ai_generated: bool = False      # explicit AI-generation declaration
    standard: str = ""              # e.g. "C2PA Content Credentials"
    generator: str = ""             # e.g. "xAI Grok"
    editor: str = ""                # e.g. "Meitu" (editing app fingerprint)
    action: str = ""                # C2PA action: "created" / "edited" / both
    signer: str = ""                # signing issuer, e.g. "Google LLC"
    self_signed: bool = False       # self-signed / ephemeral certificate
    trust: str = ""                 # TRUST_CA_ISSUED / SELF_SIGNED / UNKNOWN / INVALID
    # Cryptographic verification (populated when the C2PA manifest is verified):
    signature_verified: bool = False        # a real signature check was performed
    signature_valid: bool = False           # COSE_Sign1 verified against the cert
    asset_tampered: bool = False            # valid signature but asset bytes changed
    verification_summary: str = ""          # one-line crypto verdict
    signals: list = field(default_factory=list)

    def trust_note(self) -> str:
        """Human-readable trust phrase for the credential ('' if no C2PA)."""
        if self.trust == TRUST_INVALID:
            return "signature INVALID - manifest forged or corrupted"
        verified = " (cryptographically verified)" if self.signature_verified else ""
        if self.trust == TRUST_CA_ISSUED:
            who = f": {self.signer}" if self.signer else ""
            return f"CA-issued{who}{verified}"
        if self.trust == TRUST_SELF_SIGNED:
            who = f" ({self.signer})" if self.signer else ""
            return f"self-signed / ephemeral{who} - NOT independently verifiable{verified}"
        if self.trust == TRUST_UNKNOWN:
            return "unverified signer"
        return ""

    def summary(self) -> str:
        """Short human-readable verdict for storage / display ('' if none)."""
        trust = f" - {self.trust_note()}" if self.trust_note() else ""
        # A cryptographic verdict about the credential itself takes precedence:
        # a forged manifest or post-signing edit is the headline finding.
        if self.trust == TRUST_INVALID:
            return "C2PA credential INVALID - signature failed (forged/corrupted)"
        if self.asset_tampered:
            who = f" ({self.signer})" if self.signer else ""
            return (f"C2PA credential valid but image EDITED after signing{who} "
                    f"- post-signing tampering")
        if self.ai_generated:
            who = f": {self.generator}" if self.generator else ""
            act = f" - {self.action}" if self.action else ""
            std = f" [{self.standard}{trust}]" if self.standard else ""
            return f"AI-GENERATED / EDITED{who}{act}{std}"
        if self.editor:
            return f"Edited with {self.editor} (editing-app metadata)"
        if self.detected:
            who = f": {self.generator}" if self.generator else ""
            return f"Content provenance present{who}{trust}"
        return ""


def _metadata_region(data: bytes) -> bytes:
    """Return only the part of the file where format metadata legitimately lives,
    excluding pixel/scan data.

    Short signatures (e.g. b"GIMP", b"xAI") searched over the *whole* file collide
    with pixel bytes - an uncompressed BMP of a photo will contain "GIMP" purely
    by chance.  Editor/generator names live in metadata (EXIF/XMP/ICC/text chunks)
    which precedes the image data, so we scan only that region.
    """
    if data[:3] == b"\xFF\xD8\xFF":                 # JPEG: before start-of-scan
        sos = data.find(b"\xFF\xDA")
        return data[:sos] if sos != -1 else data[:65536]
    if data[:8] == b"\x89PNG\r\n\x1a\n":            # PNG: before first IDAT
        idat = data.find(b"IDAT")
        return data[:idat] if idat != -1 else data[:65536]
    if data[:2] == b"BM":                           # BMP: header only (v3 has no metadata)
        pix = int.from_bytes(data[10:14], "little") if len(data) >= 14 else 0
        return data[:min(pix, 4096)] if pix else data[:512]
    return data[:65536]                             # GIF/other: bounded header window


def analyze_provenance(path: str | Path) -> ProvenanceResult:
    """Scan a file for C2PA / AI-generation provenance markers."""
    result = ProvenanceResult()
    try:
        with open(path, "rb") as fh:
            data = fh.read(_MAX_SCAN)
    except OSError:
        return result

    low = data.lower()
    # Short editor/generator names are matched only in the metadata region, never
    # against pixel data (which would collide with 3-4 byte names by chance).
    meta = _metadata_region(data)

    # C2PA container: trust a JUMBF/urn:c2pa box, or the short 'c2pa' token only
    # when a JUMBF box is also present (avoids a spurious 4-byte match).
    has_c2pa = any(m in low for m in _C2PA_STRONG) or \
        (b"c2pa" in low and b"jumb" in low)
    ai_markers = [m for m in _AI_SOURCE_MARKERS if m in low]

    # Generator / editor: case-sensitive signatures, searched ONLY in the
    # metadata region (not pixel data) to avoid coincidental collisions.
    generator = ""
    for needle, name in _GENERATOR_SIGNATURES:
        if needle in meta:
            generator = name
            break
    editor = ""
    for needle, name in _EDITOR_SIGNATURES:
        if needle in meta:
            editor = name
            break

    if has_c2pa:
        result.detected = True
        result.standard = "C2PA Content Credentials"
        result.signals.append("C2PA Content Credentials manifest present.")
        # Deeper parse: which C2PA action(s) does the manifest assert?
        created = b"c2pa.created" in low
        edited = b"c2pa.edited" in low
        if created and edited:
            result.action = "created + edited"
        elif created:
            result.action = "created"
        elif edited:
            result.action = "edited"
        if result.action:
            result.signals.append(f"C2PA action assertion: {result.action}.")

        # Credential trust.  Prefer a REAL cryptographic verification of the
        # COSE_Sign1 signature, the certificate chain and the asset hash; fall
        # back to string-based certificate inspection only if the crypto stack
        # is unavailable or the manifest cannot be parsed.
        _apply_verification(result, data)

    if ai_markers:
        result.detected = True
        result.ai_generated = True
        result.signals.append(
            "C2PA digitalSourceType declares generative media "
            "(trainedAlgorithmicMedia).")

    if generator:
        result.detected = True
        result.generator = generator
        result.signals.append(f"Generator identifier found: {generator}.")
        # A recognised generative tool is itself an AI-generation declaration.
        result.ai_generated = True

    if editor:
        result.detected = True
        result.editor = editor
        result.signals.append(f"Editing-app identifier found: {editor}.")

    if result.ai_generated and not result.standard:
        result.standard = "provenance metadata"

    return result


def _apply_verification(result: ProvenanceResult, data: bytes) -> None:
    """Cryptographically verify the C2PA manifest and set trust accordingly,
    or fall back to string-based certificate inspection if that is not possible."""
    ver = c2pa_verifier.verify_bytes(data)

    # Verification produced a real cryptographic verdict.
    if ver.parsed and ver.signature_valid is not None:
        result.signature_verified = True
        result.verification_summary = ver.summary()
        result.signer = ver.signer_subject or result.signer
        result.self_signed = ver.self_signed
        for note in ver.notes:
            result.signals.append(note)

        if not ver.signature_valid:
            result.trust = TRUST_INVALID
            result.signals.append(
                "C2PA signature is cryptographically INVALID - the manifest was "
                "forged or corrupted and must not be trusted.")
            return
        result.signature_valid = True
        if ver.asset_hash_valid is False:
            result.asset_tampered = True
            result.signals.append(
                "Asset bytes no longer match the signed C2PA hash - the image "
                "was EDITED after the credential was created (post-signing "
                "tampering).")
        result.trust = TRUST_SELF_SIGNED if ver.self_signed else TRUST_CA_ISSUED
        return

    # -- fall back to certificate string inspection (no crypto / unparsed) --
    if not ver.libraries_available:
        result.signals.append(
            "Cryptographic C2PA verification unavailable (install 'cryptography'"
            " and 'cbor2'); reporting certificate inspection only.")
    result.signer = next((name for needle, name in _KNOWN_ISSUERS
                          if needle in data), "")
    result.self_signed = any(m in data for m in _SELF_SIGNED_MARKERS)
    if result.self_signed:
        result.trust = TRUST_SELF_SIGNED
        result.signals.append(
            "Signing certificate is self-signed / ephemeral - the claim is "
            "NOT independently verifiable (anyone can produce this).")
    elif b"Root CA" in data:
        result.trust = TRUST_CA_ISSUED
        who = f" ({result.signer})" if result.signer else ""
        result.signals.append(
            f"Signing certificate chains to a root CA{who} - attributable "
            "issuer (certificate inspected, not cryptographically verified).")
    else:
        result.trust = TRUST_UNKNOWN
        result.signals.append("C2PA signer type could not be determined.")
