"""ForenSight main window: navigation, view stack and case lifecycle."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, QObject, QEvent
from PyQt6.QtWidgets import (QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
                             QFrame, QLabel, QPushButton, QStackedWidget,
                             QButtonGroup, QFileDialog, QMessageBox, QProgressDialog,
                             QApplication)

from . import config
from . import case_manager, evidence_manager, reporter, ewf
from .case_manager import Case, CaseError
from .utils import utc_now_iso
from .logging_config import configure_logging, get_logger
from .ui import style
from .ui.dialogs import CreateCaseDialog
from .ui.wizards import WelcomeDialog, NewCaseWizard, AddDataSourceWizard
from .ui.workers import HashWorker
from .ui.views import (HomeView, EvidenceView, CarvingDialog,
                       TimelineView, ChainView, BookmarksView, ReportView)

# Navigation follows the original project: a media-manipulation analysis tool.
# Carving lives inside the Evidence tab (opened as a console), not as its own tab.
NAV_ITEMS = ["Home", "Evidence", "Timeline",
             "Chain of Custody", "Bookmarks", "Report"]


class _OverlayFit(QObject):
    """Keeps a dim overlay resized to fill its target widget (which may be
    maximised or resized after the overlay is first shown)."""

    def __init__(self, target, overlay):
        super().__init__(overlay)
        self._target = target
        self._overlay = overlay

    def eventFilter(self, obj, event):  # noqa: N802 - Qt override
        if event.type() == QEvent.Type.Resize:
            self._overlay.setGeometry(self._target.rect())
        return False


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.case: Optional[Case] = None
        self._scanning = False
        self._hash_worker: Optional[HashWorker] = None
        self._ingest_worker = None
        self.disk = None                       # active DiskImage handle
        self.active_disk_evidence_id = None    # evidence_id being disk-analysed
        configure_logging()
        self.setWindowTitle(f"{config.APP_NAME} — {config.APP_TAGLINE}")
        self.resize(1180, 760)
        self.setStyleSheet(style.STYLESHEET)
        self._build()
        self._update_case_controls()

    def show_welcome(self):
        """Display the Autopsy-style Welcome dialog over the main window.

        The main window is greyed out (a translucent dim overlay) while the
        dialog is open, so it is visually clear the user should interact with
        the wizard, not the app behind it."""
        if self.case is not None:
            return
        central = self.centralWidget()
        overlay = QWidget(central)
        overlay.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        overlay.setStyleSheet("background: rgba(60, 64, 72, 45);")
        overlay.setGeometry(central.rect())
        overlay.show()
        overlay.raise_()
        # Keep the overlay covering the whole window even after the window is
        # maximised or resized while the dialog is open.
        fit = _OverlayFit(central, overlay)
        central.installEventFilter(fit)
        QApplication.processEvents()
        overlay.setGeometry(central.rect())
        overlay.raise_()
        try:
            WelcomeDialog(self, self).exec()
        finally:
            central.removeEventFilter(fit)
            overlay.hide()
            overlay.deleteLater()   # restore the normal UI

    # -- construction -----------------------------------------------------
    def _build(self):
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ---- Top bar: brand (left) + case controls (right) --------------
        topbar = QFrame(); topbar.setObjectName("TopBar")
        tb = QHBoxLayout(topbar)
        tb.setContentsMargins(0, 6, 12, 6)
        tb.setSpacing(6)
        brand = QLabel('<span style="color:#FFFFFF;">Foren</span>'
                       '<span style="color:#235882;">Sight</span>')
        brand.setObjectName("TopBrand")
        sub = QLabel("Media Forensics"); sub.setObjectName("TopBrandSub")
        tb.addWidget(brand)
        tb.addWidget(sub)
        tb.addStretch(1)
        self.new_btn = QPushButton("＋ New Case")
        self.new_btn.setObjectName("NewCase")
        self.new_btn.clicked.connect(self.create_case_flow)
        self.open_btn = QPushButton("Open Case")
        self.open_btn.setObjectName("Secondary")
        self.open_btn.clicked.connect(self.open_case_flow)
        self.close_btn = QPushButton("Close Case")
        self.close_btn.setObjectName("Danger")   # red: finalising / read-only lock (HCI)
        self.close_btn.clicked.connect(self.close_case_flow)
        for b in (self.new_btn, self.open_btn, self.close_btn):
            tb.addWidget(b)
        root.addWidget(topbar)

        # ---- Nav bar: horizontal tabs -----------------------------------
        navbar = QFrame(); navbar.setObjectName("NavBar")
        nav = QHBoxLayout(navbar)
        nav.setContentsMargins(8, 0, 8, 0)
        nav.setSpacing(0)
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        self.nav_buttons = []
        for i, name in enumerate(NAV_ITEMS):
            btn = QPushButton(name)
            btn.setObjectName("TopNavButton")
            btn.setCheckable(True)
            btn.clicked.connect(lambda _=False, idx=i: self.go_to(idx))
            self.nav_group.addButton(btn, i)
            self.nav_buttons.append(btn)
            nav.addWidget(btn)
        nav.addStretch(1)
        root.addWidget(navbar)

        # Stacked views
        self.stack = QStackedWidget()
        self.home = HomeView(self)
        self.evidence = EvidenceView(self)
        self.timeline = TimelineView(self)
        self.chain = ChainView(self)
        self.bookmarks = BookmarksView(self)
        self.report = ReportView(self)
        # Order MUST match NAV_ITEMS.
        self.views = [self.home, self.evidence, self.timeline,
                      self.chain, self.bookmarks, self.report]
        # Carving is a console dialog launched from Evidence (not a nav tab).
        self.carving = CarvingDialog(self)
        for v in self.views:
            self.stack.addWidget(v)
        root.addWidget(self.stack, 1)

        self.setCentralWidget(central)
        self.status = self.statusBar()
        self.status.showMessage("No case open.")
        # Land on the Evidence tab as the launch backdrop behind the Welcome
        # dialog (the Home tab stays blank until a case is open).
        start = NAV_ITEMS.index("Evidence")
        self.nav_buttons[start].setChecked(True)
        self.stack.setCurrentIndex(start)
        self.views[start].refresh()

    # -- navigation -------------------------------------------------------
    def go_to(self, index: int):
        if self.case is None and index != 0:
            # Only Home is available without an open case.
            self.nav_buttons[0].setChecked(True)
            index = 0
        self.nav_buttons[index].setChecked(True)
        self.stack.setCurrentIndex(index)
        view = self.views[index]
        if hasattr(view, "refresh"):
            view.refresh()

    def go_to_view(self, view):
        self.go_to(self.views.index(view))

    def open_carving_console(self):
        """Open the deleted-image recovery (carving) console from Evidence."""
        if self.case is None:
            QMessageBox.information(self, "Recover Images",
                                    "Open a case and add a data source first.")
            return
        if self.case.read_only:
            QMessageBox.information(self, "Recover Images",
                                    "This case is CLOSED (read-only). Recovery is "
                                    "not available.")
            return
        self.carving.refresh()
        self.carving.show()
        self.carving.raise_()
        self.carving.activateWindow()

    def set_scanning(self, scanning: bool):
        # Lock case controls while a scan is running (the carving console keeps
        # its own controls). Navigation stays available - carving is a dialog.
        self._scanning = scanning
        for b in (self.new_btn, self.open_btn, self.close_btn):
            b.setEnabled(not scanning)

    def close_disk(self):
        if self.disk is not None:
            try:
                self.disk.close()
            except Exception:  # noqa: BLE001
                pass
        self.disk = None
        self.active_disk_evidence_id = None

    # -- refresh helpers --------------------------------------------------
    def refresh_all(self):
        for v in self.views:
            if hasattr(v, "refresh"):
                v.refresh()

    def refresh_dashboard(self):
        self.home.refresh()

    def _update_case_controls(self):
        has_case = self.case is not None
        read_only = has_case and self.case.read_only
        self.close_btn.setEnabled(has_case and not read_only)
        for i, b in enumerate(self.nav_buttons):
            b.setEnabled(has_case or i == 0)
        if has_case:
            info = self.case.db.get_case_info()
            state = "CLOSED (read-only)" if read_only else "OPEN"
            self.status.showMessage(
                f"{info['case_name']} ({info['case_id']}) — {state}")
        else:
            self.status.showMessage("No case open.")

    # ====================================================================
    # Case lifecycle flows
    # ====================================================================
    def create_case_flow(self):
        if not self._confirm_switch():
            return
        wizard = NewCaseWizard(self)
        if not wizard.exec():
            return
        d = wizard.data()
        try:
            case = case_manager.create_case(
                d["case_name"], d["case_id"], d["examiner_name"],
                d["examiner_id"], d["organization"], d["save_location"],
                examiner_phone=d["examiner_phone"], examiner_email=d["examiner_email"],
                notes=d["notes"])
        except CaseError as exc:
            QMessageBox.warning(self, "Create Case", str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Create Case", f"Unexpected error:\n{exc}")
            return
        self._activate_case(case)
        # Autopsy flow: immediately offer to add a data source.
        resp = QMessageBox.question(
            self, "Add Data Source",
            "Case created. Would you like to add a data source (disk image) now?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if resp == QMessageBox.StandardButton.Yes:
            self.add_data_source_flow()

    def open_case_flow(self):
        if not self._confirm_switch():
            return
        path = QFileDialog.getExistingDirectory(self, "Select Case Folder")
        if path:
            self.open_case_path(path)

    def open_case_path(self, path: str):
        if not self._confirm_switch():
            return
        try:
            case = case_manager.open_case(path)
        except CaseError as exc:
            QMessageBox.warning(self, "Open Case", str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Open Case", f"Unexpected error:\n{exc}")
            return
        self._activate_case(case)

    def _activate_case(self, case: Case):
        self.close_disk()  # release any open image before switching
        if self.case is not None:
            self.case.close_db()
        self.case = case
        self._update_case_controls()
        self.refresh_all()
        # Land on the Evidence tab once a case is open (not the blank Home).
        self.go_to(NAV_ITEMS.index("Evidence"))
        if case.read_only:
            QMessageBox.information(
                self, "Case Opened",
                "This case is CLOSED and has been opened in read-only mode.")

    # -- evidence flows ---------------------------------------------------
    def import_evidence_flow(self, path: str):
        if self.case is None or self.case.read_only:
            return
        dlg = QProgressDialog("Hashing evidence (SHA-256)…", "Cancel", 0, 100, self)
        dlg.setWindowTitle("Import Evidence")
        dlg.setWindowModality(Qt.WindowModality.WindowModal)
        dlg.setMinimumDuration(0)
        dlg.setValue(0)

        worker = HashWorker(path)
        self._hash_worker = worker

        def on_progress(done, total):
            dlg.setValue(int(done * 100 / total) if total else 100)

        def on_ok(sha, size):
            dlg.close()
            try:
                evidence_manager.register_evidence(self.case, path, sha, size)
            except Exception as exc:  # noqa: BLE001
                QMessageBox.critical(self, "Import", f"Could not register evidence:\n{exc}")
                return
            self.refresh_all()
            QMessageBox.information(
                self, "Evidence Imported",
                f"Imported {Path(path).name}\nSize: {size:,} bytes\nSHA-256: {sha}")

        def on_fail(msg):
            dlg.close()
            QMessageBox.critical(self, "Import Failed", msg)

        worker.progress.connect(on_progress)
        worker.finished_ok.connect(on_ok)
        worker.failed.connect(on_fail)
        dlg.canceled.connect(worker.requestInterruption)
        worker.start()

    def add_data_source_flow(self):
        """Add Data Source wizard: pick image, hash, register, then (optionally)
        start deleted-image carving - the original project workflow."""
        if self.case is None or self.case.read_only:
            QMessageBox.information(self, "Add Data Source",
                                    "Open a writable case first.")
            return
        wizard = AddDataSourceWizard(self)
        if not wizard.exec():
            return
        d = wizard.data()
        path = d["path"]
        run_carve = d["run_carve"]

        # E01/EWF is a container, not a raw disk. ForenSight reads RAW images, so
        # warn that it will raw-carve the E01 bytes but cannot parse the
        # filesystem (allocation degrades to "Unallocated"), then let the examiner
        # decide. Converting to raw first (ewfexport) is the recommended path.
        if ewf.is_ewf(path):
            resp = QMessageBox.warning(
                self, "EnCase / EWF image (.E01) detected",
                f"'{Path(path).name}' is an EnCase/EWF image (.E01).\n\n"
                "ForenSight reads RAW (dd/img/raw) images. It will carve from the "
                "E01 bytes, but it CANNOT parse the E01 as a filesystem, so:\n"
                "  • live-vs-deleted allocation will show 'Unallocated' for every "
                "file, and\n"
                "  • carving may find nothing if the E01 is compressed.\n\n"
                "For full results (including deleted-file classification), convert "
                "to raw first:\n"
                "    ewfexport -u -f raw -t output image.E01\n"
                "then add the resulting raw image instead.\n\n"
                "Proceed with the E01 anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if resp != QMessageBox.StandardButton.Yes:
                return

        self._ingest_source(path, run_carve)

    def _ingest_source(self, path, run_carve):
        """Hash, register, and (optionally) carve a raw data source."""
        dlg = QProgressDialog("Hashing data source (SHA-256)…", "Cancel", 0, 100, self)
        dlg.setWindowTitle("Add Data Source")
        dlg.setWindowModality(Qt.WindowModality.WindowModal)
        dlg.setMinimumDuration(0)
        dlg.setValue(0)

        worker = HashWorker(path)
        self._hash_worker = worker
        worker.progress.connect(lambda done, total: dlg.setValue(
            int(done * 100 / total) if total else 100))

        def on_ok(sha, size):
            dlg.close()
            # Warn if a byte-identical source (same SHA-256) is already in the
            # case - re-adding it duplicates every recovered file.
            dup = next((r for r in self.case.db.get_evidence_sources()
                        if r["sha256_hash"] == sha), None)
            if dup is not None:
                resp = QMessageBox.question(
                    self, "Duplicate Data Source",
                    f"A byte-identical data source (same SHA-256) is already in "
                    f"this case:\n\n    {dup['evidence_name']}\n\n"
                    "Adding it again will duplicate all of its recovered files. "
                    "Add it anyway?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No)
                if resp != QMessageBox.StandardButton.Yes:
                    return
            try:
                eid = evidence_manager.register_evidence(self.case, path, sha, size)
            except Exception as exc:  # noqa: BLE001
                QMessageBox.critical(self, "Add Data Source",
                                     f"Could not register data source:\n{exc}")
                return
            self.refresh_all()
            # Open the carving console with this source selected.
            self.open_carving_console()
            idx = self.carving.source_combo.findData(eid)
            if idx >= 0:
                self.carving.source_combo.setCurrentIndex(idx)
            if run_carve:
                self.carving._start()   # begin deleted-image recovery now
            else:
                QMessageBox.information(
                    self, "Data Source Added",
                    f"Added {Path(path).name}\nSHA-256: {sha}\n\n"
                    "Press START SCAN to recover deleted images.")

        worker.finished_ok.connect(on_ok)
        worker.failed.connect(lambda m: (dlg.close(),
                              QMessageBox.critical(self, "Add Data Source", m)))
        dlg.canceled.connect(worker.requestInterruption)
        worker.start()

    def verify_evidence_flow(self, evidence_id: int):
        if self.case is None:
            return
        row = self.case.db.get_evidence_source(evidence_id)
        if row is None:
            return
        source = Path(row["source_path"])
        if not source.exists():
            self.case.db.update_evidence_integrity(evidence_id, evidence_manager.UNAVAILABLE)
            QMessageBox.warning(self, "Integrity", "Evidence source is UNAVAILABLE.")
            self.refresh_all()
            return

        dlg = QProgressDialog("Recomputing SHA-256…", "Cancel", 0, 100, self)
        dlg.setWindowTitle("Verify Integrity")
        dlg.setWindowModality(Qt.WindowModality.WindowModal)
        dlg.setMinimumDuration(0)

        worker = HashWorker(str(source))
        self._hash_worker = worker
        worker.progress.connect(lambda d, t: dlg.setValue(int(d * 100 / t) if t else 100))

        def on_ok(sha, size):
            dlg.close()
            state, stored = evidence_manager.apply_integrity_result(
                self.case, evidence_id, sha)
            self.refresh_all()
            if state == evidence_manager.MATCH:
                QMessageBox.information(self, "Integrity Check", "SHA-256 MATCH — "
                                        "evidence integrity verified.")
            else:
                QMessageBox.critical(
                    self, "Integrity Check Failed",
                    f"EVIDENCE INTEGRITY CHECK FAILED\n\n"
                    f"Stored SHA-256:\n{stored}\n\nCurrent SHA-256:\n{sha}")

        worker.finished_ok.connect(on_ok)
        worker.failed.connect(lambda m: (dlg.close(),
                              QMessageBox.critical(self, "Integrity", m)))
        worker.start()

    # -- report flows -----------------------------------------------------
    def generate_draft_flow(self):
        if self.case is None:
            return
        out = self.case.path("Reports/Drafts") / f"{self.case.case_id}_Draft_Report.pdf"
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            reporter.generate_report(self.case, out, draft=True)
        except Exception as exc:  # noqa: BLE001
            QApplication.restoreOverrideCursor()
            QMessageBox.critical(self, "Draft Report", f"Report generation failed:\n{exc}")
            return
        QApplication.restoreOverrideCursor()
        QMessageBox.information(self, "Draft Report", f"Draft report generated:\n{out}")

    def close_case_flow(self):
        if self.case is None or self.case.read_only:
            return
        if self._scanning:
            QMessageBox.information(self, "Close Case",
                                    "Cannot close the case while a scan is running.")
            return
        confirm = QMessageBox.question(
            self, "Close Case",
            f"Case: {self.case.case_name}\n\n"
            "Before closing, ForenSight will:\n"
            "  • Commit database transactions\n"
            "  • Finalize chain of custody\n"
            "  • Generate the final forensic report\n"
            "  • Calculate the report SHA-256\n"
            "  • Lock the case as read-only\n\n"
            "Proceed?",
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Ok)
        if confirm != QMessageBox.StandardButton.Ok:
            return

        logger = get_logger()
        report_path = (self.case.path("Reports/Final")
                       / f"{self.case.case_id}_Final_Forensic_Report.pdf")
        # Decide the closure timestamp up front so the report can show it, then
        # commit the SAME value to the database only after the report succeeds.
        closed_utc = utc_now_iso()
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            reporter.generate_report(self.case, report_path, draft=False,
                                     closed_utc=closed_utc)
            if not report_path.exists():
                raise RuntimeError("Report file was not created.")
            report_sha = reporter.hash_report(report_path)
        except Exception as exc:  # noqa: BLE001
            QApplication.restoreOverrideCursor()
            logger.error("Report generation failed; case remains OPEN: %s", exc)
            QMessageBox.critical(
                self, "Close Case Aborted",
                f"Report generation failed. The case remains OPEN.\n\n{exc}")
            return

        try:
            case_manager.close_case(self.case, str(report_path), report_sha,
                                    closed_utc=closed_utc)
        except Exception as exc:  # noqa: BLE001
            QApplication.restoreOverrideCursor()
            QMessageBox.critical(self, "Close Case", f"Failed to finalise case:\n{exc}")
            return
        QApplication.restoreOverrideCursor()

        self._update_case_controls()
        self.refresh_all()
        self.go_to(0)
        QMessageBox.information(
            self, "Case Closed ",
            f"Case closed and locked as read-only.\n\n"
            f"Final report:\n{report_path}\n\nReport SHA-256:\n{report_sha}")

    # -- helpers ----------------------------------------------------------
    def _confirm_switch(self) -> bool:
        """Confirm before replacing an open case; block during a scan."""
        if self._scanning:
            QMessageBox.information(self, "Scan in progress",
                                    "Please wait for or cancel the active scan first.")
            return False
        return True

    def closeEvent(self, event):  # noqa: N802 - Qt override
        if self._scanning:
            resp = QMessageBox.question(
                self, "Quit", "A scan is running. Quit anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if resp != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            if self.carving.worker:
                self.carving.worker.cancel()
                self.carving.worker.wait(2000)
        self.close_disk()
        if self.case is not None:
            try:
                self.case.close_db()
            except Exception:  # noqa: BLE001
                pass
        event.accept()
