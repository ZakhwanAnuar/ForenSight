"""Forensic evidence-image import and integrity verification (spec 17-18)."""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Callable, Optional

from .case_manager import Case
from .hash_utils import sha256_file
from .logging_config import get_logger
from .utils import utc_now_iso

SUPPORTED_SOURCE_EXTS = {".img", ".dd", ".raw", ".bin", ".iso", ".001",
                         ".e01", ".ex01", ".s01", ".vmdk", ".dmp"}

MATCH = "MATCH"
MISMATCH = "MISMATCH"
UNAVAILABLE = "UNAVAILABLE"
VERIFIED = "VERIFIED"


def import_evidence(
    case: Case,
    source_path: str | Path,
    description: str = "",
    copy_into_case: bool = False,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> int:
    """Import a disk image, hash it and record metadata.

    The original source is never modified.  When ``copy_into_case`` is True a
    read-only working copy is placed under ``Evidence/Original`` (the SHA-256 is
    computed from the source before copying).  Returns the evidence_id.
    """
    logger = get_logger()
    source_path = Path(source_path)
    if not source_path.exists():
        raise FileNotFoundError(f"Evidence source not found: {source_path}")
    if not source_path.is_file():
        raise ValueError("Evidence source must be a file (raw/dd/img).")

    size = source_path.stat().st_size
    sha256 = sha256_file(source_path, progress_cb)

    stored_source = str(source_path.resolve())
    if copy_into_case:
        dest = case.path("Evidence/Original") / source_path.name
        if not dest.exists():
            shutil.copy2(source_path, dest)
        stored_source = str(dest.resolve())

    evidence_id = case.db.insert_evidence_source(
        {
            "evidence_name": source_path.name,
            "source_path": stored_source,
            "source_type": source_path.suffix.lower().lstrip(".") or "raw",
            "file_size_bytes": size,
            "sha256_hash": sha256,
            "imported_utc": utc_now_iso(),
            "description": description,
            "integrity_status": VERIFIED,
        }
    )
    case.audit.record(
        "EVIDENCE_IMPORTED",
        f"Imported '{source_path.name}' ({size} bytes).",
        evidence_id=None,
    )
    case.audit.record(
        "EVIDENCE_HASHED",
        f"SHA-256 of '{source_path.name}' = {sha256}",
        evidence_id=None,
    )
    logger.info("Evidence imported id=%s name=%s sha256=%s", evidence_id,
                source_path.name, sha256)
    return evidence_id


def compute_source_hash(
    source_path: str | Path,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> tuple[str, int]:
    """Hash a source file (no database access - safe to run in a worker thread).

    Returns ``(sha256, size_bytes)``.
    """
    source_path = Path(source_path)
    if not source_path.exists():
        raise FileNotFoundError(f"Evidence source not found: {source_path}")
    if not source_path.is_file():
        raise ValueError("Evidence source must be a file (raw/dd/img).")
    size = source_path.stat().st_size
    sha256 = sha256_file(source_path, progress_cb)
    return sha256, size


def register_evidence(
    case: Case,
    source_path: str | Path,
    sha256: str,
    size: int,
    description: str = "",
) -> int:
    """Insert pre-hashed evidence metadata + audit events (main-thread/DB only)."""
    logger = get_logger()
    source_path = Path(source_path)
    evidence_id = case.db.insert_evidence_source(
        {
            "evidence_name": source_path.name,
            "source_path": str(source_path.resolve()),
            "source_type": source_path.suffix.lower().lstrip(".") or "raw",
            "file_size_bytes": size,
            "sha256_hash": sha256,
            "imported_utc": utc_now_iso(),
            "description": description,
            "integrity_status": VERIFIED,
        }
    )
    case.audit.record("EVIDENCE_IMPORTED", f"Imported '{source_path.name}' ({size} bytes).")
    case.audit.record("EVIDENCE_HASHED", f"SHA-256 of '{source_path.name}' = {sha256}")
    logger.info("Evidence registered id=%s name=%s sha256=%s", evidence_id,
                source_path.name, sha256)
    return evidence_id


def apply_integrity_result(case: Case, evidence_id: int, current_sha: str) -> tuple[str, str]:
    """Compare a freshly computed hash with the stored value (DB/main-thread).

    Returns ``(state, stored_sha256)``.
    """
    row = case.db.get_evidence_source(evidence_id)
    if row is None:
        return UNAVAILABLE, ""
    stored = row["sha256_hash"]
    state = MATCH if current_sha == stored else MISMATCH
    case.db.update_evidence_integrity(evidence_id, VERIFIED if state == MATCH else MISMATCH)
    case.audit.record(
        "EVIDENCE_INTEGRITY_VERIFIED",
        f"Integrity check for '{row['evidence_name']}': {state}.",
    )
    return state, stored


def verify_evidence_integrity(
    case: Case,
    evidence_id: int,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> tuple[str, str, str]:
    """Recompute the source hash and compare with the stored value.

    Returns ``(state, stored_sha256, current_sha256)`` where state is one of
    MATCH / MISMATCH / UNAVAILABLE.
    """
    logger = get_logger()
    row = case.db.get_evidence_source(evidence_id)
    if row is None:
        return UNAVAILABLE, "", ""

    stored = row["sha256_hash"]
    source = Path(row["source_path"])
    if not source.exists():
        case.db.update_evidence_integrity(evidence_id, UNAVAILABLE)
        return UNAVAILABLE, stored, ""

    current = sha256_file(source, progress_cb)
    state = MATCH if current == stored else MISMATCH
    case.db.update_evidence_integrity(evidence_id, VERIFIED if state == MATCH else MISMATCH)
    case.audit.record(
        "EVIDENCE_INTEGRITY_VERIFIED",
        f"Integrity check for '{row['evidence_name']}': {state}.",
    )
    logger.info("Integrity check evidence=%s state=%s", evidence_id, state)
    return state, stored, current
