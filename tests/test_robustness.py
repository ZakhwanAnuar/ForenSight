"""Robustness / malformed-input hardening.

A forensic tool is routinely pointed at hostile or broken data: zero-byte files,
truncated images, garbage, files whose extension lies about their content, and
very large blobs.  None of that may crash the analysers, the carver, or the
end-to-end analysis pipeline - a crash mid-case would abort an examination and,
worse, could leave the audit chain inconsistent.

These tests feed deliberately malformed inputs through every layer and assert
that each one degrades gracefully (returns a result / records INSUFFICIENT_DATA)
rather than raising.
"""
from __future__ import annotations

import io
import os

import pytest
from PIL import Image

from forensight import (exif_engine, jpeg_analyzer, file_type_analyzer,
                        recompression_analyzer, provenance_analyzer,
                        c2pa_verifier, thumbnail_engine, file_validator,
                        integrity_analyzer, carver, carving_service,
                        analysis_service, evidence_manager)
from forensight.audit_manager import verify_audit_chain


def _real_jpeg() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (64, 64), (10, 20, 30)).save(buf, "JPEG")
    return buf.getvalue()


_REAL_JPEG = _real_jpeg()

# A spread of hostile inputs, each labelled for readable test IDs.
MALFORMED = {
    "empty": b"",
    "one_byte": b"\x00",
    "jpeg_soi_only": b"\xFF\xD8\xFF",
    "png_magic_only": b"\x89PNG\r\n\x1a\n",
    "bmp_header_only": b"BM" + b"\x00" * 10,
    "gif_magic_only": b"GIF89a",
    "random_garbage": os.urandom(4096),
    "text_as_image": b"this is plainly not an image\n" * 64,
    "huge_zeros": b"\x00" * (2 * 1024 * 1024),
    "jpeg_truncated": _REAL_JPEG[: len(_REAL_JPEG) // 2],
    "jpeg_no_eoi": _REAL_JPEG[:-2],
    "fake_c2pa_marker": b"\xFF\xD8\xFF" + b"jumbfc2pa urn:c2pa" + os.urandom(2048),
}


@pytest.fixture(params=list(MALFORMED), ids=list(MALFORMED))
def malformed_file(request, tmp_path):
    p = tmp_path / f"{request.param}.jpg"
    p.write_bytes(MALFORMED[request.param])
    return p


# -- individual analysers never raise --------------------------------------
def test_exif_engine_survives(malformed_file):
    exif_engine.extract_exif(malformed_file)


def test_jpeg_analyzer_survives(malformed_file):
    jpeg_analyzer.analyze_jpeg(malformed_file)


def test_file_type_analyzer_survives(malformed_file):
    result = file_type_analyzer.analyze_file_type(malformed_file)
    assert "result" in result


def test_recompression_survives(malformed_file):
    jr = jpeg_analyzer.analyze_jpeg(malformed_file)
    recompression_analyzer.analyze(jr)


def test_provenance_survives(malformed_file):
    provenance_analyzer.analyze_provenance(malformed_file)


def test_c2pa_verifier_survives(malformed_file):
    result = c2pa_verifier.verify_file(malformed_file)
    # A garbage "manifest" must never be reported as a valid signature.
    assert result.signature_valid in (None, False)


def test_thumbnail_survives(malformed_file):
    thumbnail_engine.compare_thumbnail(malformed_file)


def test_validator_survives(malformed_file):
    result = file_validator.validate_recovered_file(malformed_file, "jpg")
    assert result.is_valid in (True, False)


# -- carver never crashes / hangs / hallucinates ---------------------------
@pytest.mark.parametrize("blob", [
    b"", b"\x00", os.urandom(1024 * 1024), b"\x00" * (5 * 1024 * 1024),
    b"\xFF\xD8\xFF" * 2000,                      # many fake SOIs, no real images
], ids=["empty", "one_byte", "garbage_1mb", "zeros_5mb", "fake_headers"])
def test_carver_on_garbage_source(tmp_path, blob):
    src = tmp_path / "src.dd"
    src.write_bytes(blob)
    found = []
    n = carver.scan_source(src, {"JPEG", "PNG", "GIF", "BMP"},
                           on_file=found.append)
    assert n == len(found)
    # None of these blobs contain a decodable image, so nothing valid is carved.
    assert all(not cf.data or not carver._decodes_as_image(cf.data) for cf in found)


# -- full pipeline: undecodable carved file -> INSUFFICIENT_DATA, chain intact
def test_pipeline_on_undecodable_file(new_case, tmp_path):
    src = tmp_path / "garbage.dd"
    src.write_bytes(b"\xFF\xD8\xFF" + os.urandom(20000))     # looks JPEG-ish, isn't
    sha, size = evidence_manager.compute_source_hash(src)
    eid = evidence_manager.register_evidence(new_case, src, sha, size)

    # Force a carved record from garbage bytes and analyse it directly.
    res = carving_service.persist_carved_file(new_case, eid, {
        "file_format": "JPEG", "source_offset": 0, "source_offset_hex": "0x0",
        "data": b"\xFF\xD8\xFF" + os.urandom(20000), "file_name": "garbage.jpg"})
    analysis = analysis_service.analyze_carved_image(new_case, res.carved_id)
    assert analysis.assessment.outcome == integrity_analyzer.INSUFFICIENT_DATA
    # The audit chain must stay valid after processing hostile input.
    assert verify_audit_chain(new_case.db).valid


def test_pipeline_on_zero_byte_source(new_case, tmp_path):
    src = tmp_path / "empty.dd"
    src.write_bytes(b"")
    sha, size = evidence_manager.compute_source_hash(src)
    eid = evidence_manager.register_evidence(new_case, src, sha, size)
    n = carver.scan_source(src, {"JPEG", "PNG", "GIF", "BMP"},
                           on_file=lambda cf: carving_service.persist_carved_file(
                               new_case, eid, {
                                   "file_format": cf.file_format,
                                   "source_offset": cf.source_offset,
                                   "source_offset_hex": cf.source_offset_hex,
                                   "data": cf.data, "file_name": cf.file_name}))
    assert n == 0
    assert verify_audit_chain(new_case.db).valid
