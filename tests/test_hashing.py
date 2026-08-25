"""Hashing and evidence-integrity tests (spec section 65)."""
import hashlib

from forensight import evidence_manager
from forensight.hash_utils import sha256_bytes, sha256_file


def test_known_file_hash(tmp_path):
    data = b"forensight-known-content"
    f = tmp_path / "known.bin"
    f.write_bytes(data)
    assert sha256_file(f) == hashlib.sha256(data).hexdigest()
    assert sha256_bytes(data) == hashlib.sha256(data).hexdigest()


def test_modified_evidence_produces_mismatch(new_case, sample_image):
    case = new_case
    sha, size = evidence_manager.compute_source_hash(sample_image)
    eid = evidence_manager.register_evidence(case, sample_image, sha, size)

    # Tamper with the source file after import.
    with sample_image.open("ab") as fh:
        fh.write(b"tampered")

    state, _, current = evidence_manager.verify_evidence_integrity(case, eid)
    assert state == "MISMATCH"
    assert current != sha


def test_match_when_unchanged(new_case, sample_image):
    case = new_case
    sha, size = evidence_manager.compute_source_hash(sample_image)
    eid = evidence_manager.register_evidence(case, sample_image, sha, size)
    state, stored, current = evidence_manager.verify_evidence_integrity(case, eid)
    assert state == "MATCH"
    assert stored == current == sha


def test_missing_source_reports_unavailable(new_case, tmp_path):
    """If the original source is gone at verification time, report UNAVAILABLE
    rather than crashing or silently claiming a match."""
    case = new_case
    src = tmp_path / "removable.dd"
    src.write_bytes(b"\x00" * 4096)
    sha, size = evidence_manager.compute_source_hash(src)
    eid = evidence_manager.register_evidence(case, src, sha, size)

    src.unlink()                                   # source no longer accessible
    state, stored, current = evidence_manager.verify_evidence_integrity(case, eid)
    assert state == "UNAVAILABLE"
    assert stored == sha and current == ""


def test_mismatch_is_recorded_in_audit_and_status(new_case, sample_image):
    """A failed integrity check must persist to the evidence status and leave the
    audit chain valid (an examiner must be able to prove the tamper was logged)."""
    from forensight.audit_manager import verify_audit_chain
    case = new_case
    sha, size = evidence_manager.compute_source_hash(sample_image)
    eid = evidence_manager.register_evidence(case, sample_image, sha, size)
    with sample_image.open("ab") as fh:
        fh.write(b"tampered")

    state, _, _ = evidence_manager.verify_evidence_integrity(case, eid)
    assert state == "MISMATCH"
    row = case.db.get_evidence_source(eid)
    assert row["integrity_status"] == evidence_manager.MISMATCH
    assert verify_audit_chain(case.db).valid
