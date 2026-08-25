"""Audit-chain and reporting tests (spec section 65)."""
from pathlib import Path

from forensight import evidence_manager, carver, carving_service, analysis_service
from forensight import reporter
from forensight.audit_manager import verify_audit_chain


def _populate(case, sample_image):
    sha, size = evidence_manager.compute_source_hash(sample_image)
    eid = evidence_manager.register_evidence(case, sample_image, sha, size)
    carver.scan_source(
        sample_image, {"JPEG", "PNG", "BMP", "GIF"},
        on_file=lambda cf: carving_service.persist_carved_file(case, eid, {
            "file_format": cf.file_format, "source_offset": cf.source_offset,
            "source_offset_hex": cf.source_offset_hex, "data": cf.data,
            "file_name": cf.file_name}))
    for row in case.db.get_all_carved():
        if row["is_valid"]:
            analysis_service.analyze_carved_image(case, row["id"])
    return eid


def test_valid_chain(new_case, sample_image):
    _populate(new_case, sample_image)
    result = verify_audit_chain(new_case.db)
    assert result.valid


def test_tampered_event_detected(new_case, sample_image):
    _populate(new_case, sample_image)
    # Tamper with an audit event's description directly in the DB.
    new_case.db.execute(
        "UPDATE audit_log SET description = ? WHERE id = "
        "(SELECT id FROM audit_log LIMIT 1 OFFSET 2)", ("TAMPERED",))
    new_case.db.commit()
    result = verify_audit_chain(new_case.db)
    assert not result.valid
    assert result.broken_event_id is not None


def test_report_generation_and_hash(new_case, sample_image, tmp_path):
    _populate(new_case, sample_image)
    out = tmp_path / "report.pdf"
    reporter.generate_report(new_case, out)
    assert out.exists() and out.stat().st_size > 0
    h1 = reporter.hash_report(out)
    h2 = reporter.hash_report(out)
    assert h1 == h2 and len(h1) == 64
