"""Small shared helpers: UTC time, filename sanitising, human sizes."""
from __future__ import annotations

import re
from datetime import datetime, timezone


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with a trailing Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_now_compact() -> str:
    """UTC timestamp safe for use inside file names (no colons)."""
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


_DISALLOWED = re.compile(r"[^\w\s.-]", re.UNICODE)


def sanitize_filename(name: str, fallback: str = "unnamed") -> str:
    """Turn an arbitrary string into a safe file-system folder/file name.

    Characters other than letters, digits, underscore, dash, dot and spaces are
    removed; spaces become underscores and runs are collapsed (matching the
    spec example "Laptop / Phone Investigation #1" -> "Laptop_Phone_Investigation_1").
    The original human-readable value is always preserved in metadata (spec
    section 9).
    """
    cleaned = _DISALLOWED.sub("", name).strip()
    cleaned = re.sub(r"\s+", "_", cleaned)
    cleaned = re.sub(r"_+", "_", cleaned)
    cleaned = cleaned.strip("._")
    return cleaned or fallback


def human_size(num_bytes: int) -> str:
    """Human readable byte count, retaining exact bytes elsewhere."""
    if num_bytes is None:
        return "Not Available"
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"


def format_hex_offset(offset: int) -> str:
    """Format an absolute byte offset as a zero-padded hex string."""
    return f"0x{offset:08X}"
