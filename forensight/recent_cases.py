"""Application-level recent-cases list (spec section 11).

Stores only lightweight pointers - never raw or sensitive evidence content.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from .utils import utc_now_iso

# Stored next to the ForenSight package under the user's home directory.
_STORE = Path.home() / ".forensight" / "recent_cases.json"
_MAX_RECENT = 15

# Cases created inside the system temp directory are throwaway/test cases (e.g.
# pytest's temp dirs), never real evidence cases, so they are hidden from the
# recent list and pruned on load.
try:
    _TEMP_ROOT = Path(tempfile.gettempdir()).resolve()
except OSError:  # pragma: no cover
    _TEMP_ROOT = None


def _under_temp(path_str: str) -> bool:
    if _TEMP_ROOT is None or not path_str:
        return False
    try:
        return Path(path_str).resolve().is_relative_to(_TEMP_ROOT)
    except (OSError, ValueError):
        return False


def _load_raw() -> list[dict]:
    if not _STORE.exists():
        return []
    try:
        with _STORE.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _save_raw(entries: list[dict]) -> None:
    _STORE.parent.mkdir(parents=True, exist_ok=True)
    with _STORE.open("w", encoding="utf-8") as fh:
        json.dump(entries, fh, indent=2)


def get_recent_cases() -> list[dict]:
    """Return recent cases, most recently opened first, dropping entries whose
    path is missing or lives in the system temp directory (throwaway/test cases).
    Stale entries are pruned from the store as a side effect."""
    entries = _load_raw()
    valid = [e for e in entries
             if Path(e.get("case_path", "")).exists()
             and not _under_temp(e.get("case_path", ""))]
    if len(valid) != len(entries):
        _save_raw(valid)
    return valid


def add_recent_case(case_name: str, case_id: str, case_path: str, status: str) -> None:
    """Insert or refresh a recent-case pointer."""
    entries = [e for e in _load_raw() if e.get("case_id") != case_id]
    entries.insert(
        0,
        {
            "case_name": case_name,
            "case_id": case_id,
            "case_path": str(case_path),
            "last_opened_utc": utc_now_iso(),
            "status": status,
        },
    )
    _save_raw(entries[:_MAX_RECENT])


def update_status(case_id: str, status: str) -> None:
    entries = _load_raw()
    for entry in entries:
        if entry.get("case_id") == case_id:
            entry["status"] = status
    _save_raw(entries)
