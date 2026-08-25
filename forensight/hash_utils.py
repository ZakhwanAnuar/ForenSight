"""SHA-256 helpers for evidence and report integrity (spec sections 3, 53)."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Callable, Optional

_READ_CHUNK = 1024 * 1024  # 1 MiB


def sha256_bytes(data: bytes) -> str:
    """SHA-256 of an in-memory byte string."""
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    """SHA-256 of a UTF-8 string (used by the audit chain)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(
    path: str | Path,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> str:
    """Stream a file through SHA-256 using 1 MiB reads.

    ``progress_cb(bytes_done, total_bytes)`` is called periodically so a GUI
    worker can report progress while hashing large disk images.
    """
    path = Path(path)
    total = path.stat().st_size
    done = 0
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_READ_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            done += len(chunk)
            if progress_cb is not None:
                progress_cb(done, total)
    return digest.hexdigest()
