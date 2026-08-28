"""ForenSight application entry point.

Run:  python main.py
"""
from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtCore import QTimer, QSharedMemory
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication, QMessageBox

from forensight.main_gui import MainWindow

# Keep a module-level reference so the shared-memory lock lives for the whole
# process lifetime (released automatically when the process exits).
_SINGLE_INSTANCE_LOCK = None


def _app_icon() -> QIcon:
    """The ForenSight shield icon, resolved from source or the frozen bundle."""
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", "."))
    else:
        base = Path(__file__).resolve().parent
    return QIcon(str(base / "forensight.ico"))


def main() -> int:
    global _SINGLE_INSTANCE_LOCK
    # Give Windows an explicit app id so the taskbar shows our window icon
    # (instead of grouping under a generic Python/host icon).
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "ForenSight.ForensicTool")
        except Exception:
            pass
    app = QApplication(sys.argv)
    app.setApplicationName("ForenSight")
    app.setWindowIcon(_app_icon())   # taskbar + title-bar icon while running

    # Single-instance guard: if ForenSight is already running, do not open a
    # second window - just tell the user and exit.
    _SINGLE_INSTANCE_LOCK = QSharedMemory("ForenSight-SingleInstance-Lock")
    if not _SINGLE_INSTANCE_LOCK.create(1):
        QMessageBox.information(None, "ForenSight",
                                "ForenSight is already running.\n"
                                "Please use the window that is already open.")
        return 0

    window = MainWindow()
    window.showMaximized()
    # Show the Welcome dialog over the (maximized) main window once the event
    # loop starts (the "two windows on launch" Autopsy-style flow).
    QTimer.singleShot(0, window.show_welcome)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
