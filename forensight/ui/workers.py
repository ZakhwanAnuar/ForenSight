"""Generic QThread workers for hashing (keeps the GUI responsive, spec 58).

These workers deliberately perform NO database access so the single-threaded
SQLite connection is never touched from a background thread (spec section 59).
Results are returned to the main thread, which performs any DB writes.
"""
from __future__ import annotations

from typing import Callable

from PyQt6.QtCore import QThread, pyqtSignal

from ..evidence_manager import compute_source_hash


class HashWorker(QThread):
    """Compute a file's SHA-256 off the GUI thread."""

    progress = pyqtSignal(int, int)   # done, total (bytes)
    finished_ok = pyqtSignal(str, int)  # sha256, size
    failed = pyqtSignal(str)

    def __init__(self, source_path: str, parent=None):
        super().__init__(parent)
        self.source_path = source_path

    def run(self) -> None:  # noqa: D401 - QThread entry point
        try:
            sha, size = compute_source_hash(
                self.source_path, progress_cb=lambda d, t: self.progress.emit(d, t)
            )
            self.finished_ok.emit(sha, size)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))
