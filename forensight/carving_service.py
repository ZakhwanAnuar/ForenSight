"""Persist carved candidates: write bytes, validate, quarantine, record.

Called on the GUI thread (which owns the SQLite connection) for each candidate
emitted by :class:`~forensight.carver.CarverWorker`, keeping all database
writes single-threaded and safe (spec section 59).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import config, allocation
from .case_manager import Case
from .file_validator import validate_recovered_file
from .hash_utils import sha256_bytes
from .logging_config import get_logger
from .utils import utc_now_iso


@dataclass
class PersistResult:
    carved_id: int
    is_valid: bool
    is_suspicious: bool
    message: str
    is_duplicate: bool = False


def persist_carved_file(
    case: Case,
    evidence_id: Optional[int],
    payload: dict,
    suspicious_threshold: int = config.SUSPICIOUS_SIZE_THRESHOLD,
    recovery_method: str = "Signature-based carving (raw/unallocated space)",
    allocation_map: Optional[dict] = None,
    allocation_status: Optional[str] = None,
) -> PersistResult:
    """Write one carved file to disk, validate it and store its record.

    Allocation: the carved file is classified Allocated (live) / Deleted /
    Unallocated / Unknown by matching the byte OFFSET at which it was carved
    against ``allocation_map`` (the filesystem's data extents), or by an explicit
    ``allocation_status`` (used by the loose-file import path).  Idempotent on
    (offset, hash).
    """
    logger = get_logger()
    fmt = payload["file_format"]
    data = payload["data"]
    file_name = payload["file_name"]
    sha256 = sha256_bytes(data)

    status = allocation_status or allocation.classify(
        payload["source_offset"], allocation_map)
    is_deleted = 0 if status == allocation.ALLOCATED else 1

    # Skip if this exact carve already exists (re-scan is idempotent).
    if case.db.carved_exists(evidence_id, payload["source_offset"], sha256):
        return PersistResult(-1, False, False,
                             "Already carved from this source — skipped.",
                             is_duplicate=True)

    # Write to the format's carved directory first.
    target_dir = case.carved_dir(fmt)
    target_dir.mkdir(parents=True, exist_ok=True)
    dest = target_dir / file_name
    dest = _unique_path(dest)
    with dest.open("wb") as fh:
        fh.write(data)

    # Validate (spec sections 23-24).
    validation = validate_recovered_file(dest, fmt, suspicious_threshold)

    # Quarantine suspicious / invalid files without discarding bytes.
    if validation.is_suspicious or not validation.is_valid:
        quarantine = case.suspicious_dir() / dest.name
        quarantine = _unique_path(quarantine)
        dest.replace(quarantine)
        dest = quarantine

    # Allocation status only makes sense for a validated recovered file. An
    # invalid candidate (e.g. an over-carved / corrupt blob) is not a real file,
    # so do not attribute it to allocated/deleted space - report it Unknown.
    if not validation.is_valid:
        status = allocation.UNKNOWN
        is_deleted = 1

    carved_id = case.db.insert_carved(
        {
            "evidence_id": evidence_id,
            "file_name": dest.name,
            "file_format": fmt,
            "file_path": str(dest),
            "source_offset": payload["source_offset"],
            "source_offset_hex": payload["source_offset_hex"],
            "file_size_bytes": len(data),
            "sha256_hash": sha256,
            "recovery_method": recovery_method,
            "is_deleted": is_deleted,
            "allocation_status": status,
            "is_suspicious": 1 if validation.is_suspicious else 0,
            "is_valid": 1 if validation.is_valid else 0,
            "validation_message": validation.message
            + (f" [{validation.reason}]" if validation.reason else ""),
            "created_utc": utc_now_iso(),
        }
    )

    case.audit.record(
        "FILE_RECOVERED",
        f"Recovered {fmt} @ {payload['source_offset_hex']} -> {dest.name}",
        evidence_id=carved_id,
    )
    case.audit.record(
        "FILE_VALIDATED",
        f"Validation of {dest.name}: "
        f"{'VALID' if validation.is_valid else 'SUSPICIOUS'} - {validation.message}",
        evidence_id=carved_id,
    )
    logger.info("Persisted carved id=%s name=%s valid=%s", carved_id, dest.name,
                validation.is_valid)
    return PersistResult(carved_id, validation.is_valid, validation.is_suspicious,
                         validation.message)


def _unique_path(path: Path) -> Path:
    """Return a non-clashing path by appending _1, _2 ... if needed."""
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    counter = 1
    while True:
        candidate = path.with_name(f"{stem}_{counter}{suffix}")
        if not candidate.exists():
            return candidate
        counter += 1
