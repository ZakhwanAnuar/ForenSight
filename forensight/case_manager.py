"""Case lifecycle: create, open, close (spec sections 9-14).

A ``Case`` object bundles the open database connection, the audit manager, the
parsed configuration and the workspace paths so the GUI has a single handle to
the currently open investigation.
"""
from __future__ import annotations

import getpass
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import config
from . import recent_cases
from .audit_manager import AuditManager
from .database import Database
from .logging_config import configure_logging, get_logger
from .utils import sanitize_filename, utc_now_iso


def _actor_label(name: str, examiner_id: str = "") -> str:
    """Chain-of-custody actor string: identify the examiner by name and, when
    available, ID/badge, so every audit event attributes an action to a specific
    person rather than an anonymous 'Unknown'."""
    name = (name or "").strip() or "Unknown examiner"
    examiner_id = (examiner_id or "").strip()
    return f"{name} ({examiner_id})" if examiner_id and examiner_id != "N/A" else name


def _os_account() -> str:
    """The operating-system login account for this session - a second, harder-
    to-forge identity anchor recorded alongside the typed examiner identity."""
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return "unknown-account"


class CaseError(Exception):
    """Raised for recoverable case-management problems (shown to the user)."""


@dataclass
class Case:
    """A currently open forensic case."""

    root: Path
    config_data: dict
    db: Database
    audit: AuditManager
    read_only: bool = False
    _paths: dict = field(default_factory=dict)

    # -- convenience accessors --------------------------------------------
    @property
    def case_id(self) -> str:
        return self.config_data["case_id"]

    @property
    def case_name(self) -> str:
        return self.config_data["case_name"]

    @property
    def examiner_name(self) -> str:
        return self.config_data.get("examiner_name", "")

    @property
    def status(self) -> str:
        info = self.db.get_case_info()
        return info["case_status"] if info else self.config_data.get("case_status", "OPEN")

    def path(self, relative: str) -> Path:
        return self.root / relative

    def carved_dir(self, fmt: str) -> Path:
        return self.root / config.CARVED_DIRS[fmt]

    def suspicious_dir(self) -> Path:
        return self.root / config.SUSPICIOUS_DIR

    def close_db(self) -> None:
        self.db.close()


def _write_config(case_root: Path, data: dict) -> None:
    cfg_path = case_root / config.CASE_DATA_DIR / config.CONFIG_FILENAME
    with cfg_path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def _read_config(case_root: Path) -> dict:
    cfg_path = case_root / config.CASE_DATA_DIR / config.CONFIG_FILENAME
    with cfg_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _create_workspace(case_root: Path) -> None:
    for rel in config.WORKSPACE_DIRS:
        (case_root / rel).mkdir(parents=True, exist_ok=True)


def create_case(
    case_name: str,
    case_id: str,
    examiner_name: str,
    examiner_id: str,
    organization: str,
    save_location: str | Path,
    examiner_phone: str = "",
    examiner_email: str = "",
    notes: str = "",
) -> Case:
    """Create a brand new case (spec section 9).

    Raises :class:`CaseError` for validation failures.  The optional Autopsy-style
    fields (phone, email, notes) are stored in the case configuration file.
    """
    # -- validation -------------------------------------------------------
    for label, value in (
        ("Case Name", case_name), ("Case ID", case_id),
        ("Examiner Name", examiner_name), ("Examiner ID", examiner_id),
        ("Save Location", str(save_location)),
    ):
        if not str(value).strip():
            raise CaseError(f"{label} is required and cannot be empty.")

    save_location = Path(save_location)
    if not save_location.exists():
        raise CaseError(f"Save location does not exist:\n{save_location}")

    folder_name = sanitize_filename(case_name, fallback=sanitize_filename(case_id))
    case_root = save_location / folder_name
    if case_root.exists():
        raise CaseError(
            f"A folder named '{folder_name}' already exists at the save "
            f"location.\nRefusing to overwrite an existing case."
        )

    # -- build workspace --------------------------------------------------
    _create_workspace(case_root)
    logger = configure_logging(case_root / "Logs")

    db_path = case_root / config.CASE_DATA_DIR / config.DB_FILENAME
    db = Database(db_path)
    db.initialize_schema()

    created_utc = utc_now_iso()
    config_data = {
        "application": config.APP_NAME,
        "schema_version": config.SCHEMA_VERSION,
        "case_name": case_name,               # original, human-readable name
        "case_id": case_id,
        "examiner_name": examiner_name,
        "examiner_id": examiner_id,
        "organization": organization,
        "created_utc": created_utc,
        "closed_utc": None,
        "case_status": config.CASE_STATUS_OPEN,
        "case_root_path": str(case_root),
        "examiner_phone": examiner_phone,
        "examiner_email": examiner_email,
        "notes": notes,
    }

    # Uniqueness of case_id is enforced by the PRIMARY KEY as well.
    db.insert_case_info(
        {
            "case_id": case_id,
            "case_name": case_name,
            "examiner_name": examiner_name,
            "examiner_id": examiner_id,
            "organization": organization,
            "created_utc": created_utc,
            "closed_utc": None,
            "case_root_path": str(case_root),
            "case_status": config.CASE_STATUS_OPEN,
            "final_report_path": None,
            "final_report_sha256": None,
        }
    )
    _write_config(case_root, config_data)

    audit = AuditManager(db, actor=_actor_label(examiner_name, examiner_id))
    audit.record("CASE_CREATED",
                 f"Case '{case_name}' ({case_id}) created by examiner "
                 f"{_actor_label(examiner_name, examiner_id)} on system account "
                 f"'{_os_account()}'.")

    recent_cases.add_recent_case(case_name, case_id, case_root, config.CASE_STATUS_OPEN)
    logger.info("Case created: %s (%s) at %s", case_name, case_id, case_root)

    return Case(root=case_root, config_data=config_data, db=db, audit=audit,
                read_only=False)


def open_case(case_path: str | Path) -> Case:
    """Open an existing case from a directory or its case_config.json.

    Validates workspace integrity (spec section 12) without ever recreating
    evidence.
    """
    case_path = Path(case_path)
    if case_path.is_file() and case_path.name == config.CONFIG_FILENAME:
        case_root = case_path.parent.parent
    else:
        case_root = case_path

    case_data_dir = case_root / config.CASE_DATA_DIR
    cfg_path = case_data_dir / config.CONFIG_FILENAME
    db_path = case_data_dir / config.DB_FILENAME

    if not case_data_dir.exists():
        raise CaseError(f"CaseData directory not found in:\n{case_root}")
    if not cfg_path.exists():
        raise CaseError("case_config.json is missing - not a valid ForenSight case.")
    if not db_path.exists():
        raise CaseError("crime_lens_case.db is missing - case database not found.")

    config_data = _read_config(case_root)
    schema_version = config_data.get("schema_version")
    if schema_version != config.SCHEMA_VERSION:
        raise CaseError(
            f"Unsupported schema version {schema_version}. "
            f"This build supports version {config.SCHEMA_VERSION}."
        )

    # Recreate only missing *structural* directories, never evidence.
    for rel in config.WORKSPACE_DIRS:
        (case_root / rel).mkdir(parents=True, exist_ok=True)

    logger = configure_logging(case_root / "Logs")
    try:
        db = Database(db_path)
        info = db.get_case_info()
    except Exception as exc:  # noqa: BLE001 - surface a friendly message
        raise CaseError(f"Case database could not be read:\n{exc}") from exc

    if info is None:
        raise CaseError("Case database has no case_info record.")

    read_only = info["case_status"] == config.CASE_STATUS_CLOSED
    audit = AuditManager(db, actor=_actor_label(
        config_data.get("examiner_name", ""), config_data.get("examiner_id", "")))
    if not read_only:
        audit.record("CASE_OPENED",
                     f"Case '{config_data['case_name']}' opened by examiner "
                     f"{audit.actor} on system account '{_os_account()}'.")

    recent_cases.add_recent_case(
        config_data["case_name"], config_data["case_id"], case_root, info["case_status"]
    )
    logger.info("Case opened: %s (%s)", config_data["case_name"], config_data["case_id"])

    return Case(root=case_root, config_data=config_data, db=db, audit=audit,
                read_only=read_only)


def close_case(case: Case, report_path: str, report_sha256: str,
               closed_utc: str | None = None) -> None:
    """Finalise and lock a case (spec section 13).

    The report must already be generated and hashed by the caller; this records
    the closure events, flips status to CLOSED and flushes the database.

    ``closed_utc`` should be the same timestamp shown in the report (so the DB
    and the report agree); if omitted, the current time is used.
    """
    logger = get_logger()
    closed_utc = closed_utc or utc_now_iso()

    case.db.set_final_report(case.case_id, report_path, report_sha256)
    case.audit.record(
        "REPORT_GENERATED",
        f"Final report generated. SHA-256={report_sha256}",
    )
    case.audit.record("CASE_CLOSED", f"Case '{case.case_name}' closed.")
    case.db.update_case_status(case.case_id, config.CASE_STATUS_CLOSED, closed_utc)

    case.config_data["case_status"] = config.CASE_STATUS_CLOSED
    case.config_data["closed_utc"] = closed_utc
    _write_config(case.root, case.config_data)

    recent_cases.update_status(case.case_id, config.CASE_STATUS_CLOSED)
    case.read_only = True
    case.db.commit()
    logger.info("Case closed: %s (%s)", case.case_name, case.case_id)
