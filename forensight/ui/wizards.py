"""Autopsy-style application flow: Welcome screen and step wizards.

* :class:`WelcomeDialog` - the launch dialog (New / Open Recent / Open Case).
* :class:`NewCaseWizard` - two-step new-case wizard (Case Information +
  Optional Information).
* :class:`AddDataSourceWizard` - multi-step data-source wizard (type ->
  source -> configure ingest).
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtWidgets import (
    QDialog, QWizard, QWizardPage, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLabel, QLineEdit, QPushButton, QRadioButton, QButtonGroup, QComboBox,
    QCheckBox, QPlainTextEdit, QFileDialog, QListWidget, QListWidgetItem,
    QWidget, QFrame,
)

from .. import config, filesystem
from ..utils import sanitize_filename, utc_now_compact
from .common import h1, h2, muted
from . import style


def center_on_screen(widget):
    """Move a top-level widget to the centre of the screen it appears on."""
    screen = widget.screen() or QGuiApplication.primaryScreen()
    if screen is None:
        return
    geo = screen.availableGeometry()
    frame = widget.frameGeometry()
    frame.moveCenter(geo.center())
    widget.move(frame.topLeft())


# ===========================================================================
# Welcome dialog (the "two windows on launch" screen)
# ===========================================================================
class WelcomeDialog(QDialog):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("Welcome to ForenSight")
        self.setModal(True)
        self.setMinimumSize(640, 380)

        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Left: branding panel (logo placeholder — user will add a logo later).
        left = QFrame()
        left.setObjectName("Sidebar")
        left.setFixedWidth(260)
        lv = QVBoxLayout(left)
        lv.setContentsMargins(24, 40, 24, 24)
        logo = QLabel("🛡")
        logo.setStyleSheet("font-size:72px; color:white; background:transparent;")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name = QLabel(config.APP_NAME)
        name.setStyleSheet("color:white; font-size:28px; font-weight:800; background:transparent;")
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tag = QLabel("Image Manipulation &\nMedia Forensics")
        tag.setStyleSheet("color:#9AA1A9; font-size:12px; background:transparent;")
        tag.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lv.addStretch(1)
        lv.addWidget(logo)
        lv.addWidget(name)
        lv.addWidget(tag)
        lv.addStretch(1)
        ver = QLabel(f"Prototype • schema v{config.SCHEMA_VERSION}")
        ver.setStyleSheet("color:#7C818A; font-size:10px; background:transparent;")
        ver.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lv.addWidget(ver)
        root.addWidget(left)

        # Right: action buttons.
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(30, 30, 30, 30)
        rv.setSpacing(14)
        rv.addWidget(h2("Get Started"))
        rv.addSpacing(6)

        rv.addWidget(self._action("＋  New Case",
                                  "Create a new forensic investigation case.",
                                  self._new_case))
        rv.addWidget(self._action("🕘  Open Recent Case",
                                  "Reopen a recently used case.",
                                  self._open_recent))
        rv.addWidget(self._action("📂  Open Case",
                                  "Open an existing case from disk.",
                                  self._open_case))
        rv.addStretch(1)

        close = QPushButton("Close")
        close.setObjectName("Secondary")
        close.clicked.connect(self.reject)
        crow = QHBoxLayout(); crow.addStretch(1); crow.addWidget(close)
        rv.addLayout(crow)
        root.addWidget(right, 1)

    def showEvent(self, event):  # noqa: N802 - Qt override
        super().showEvent(event)
        center_on_screen(self)

    def _action(self, title, subtitle, handler):
        btn = QPushButton(f"{title}\n{subtitle}")
        btn.setMinimumHeight(64)
        btn.setStyleSheet(
            "text-align:left; padding:10px 16px; font-weight:600;")
        btn.clicked.connect(handler)
        return btn

    def _new_case(self):
        self.accept()
        # Defer until the Welcome dialog has fully closed (avoids nested-modal
        # glitches on Windows).
        QTimer.singleShot(0, self.controller.create_case_flow)

    def _open_case(self):
        self.accept()
        QTimer.singleShot(0, self.controller.open_case_flow)

    def _open_recent(self):
        from .. import recent_cases
        entries = recent_cases.get_recent_cases()
        if not entries:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.information(self, "Open Recent Case",
                                    "No recent cases yet. Use 'Open Case' or "
                                    "'New Case'.")
            return
        dlg = _RecentPicker(entries, self)
        if dlg.exec() and dlg.selected_path:
            path = dlg.selected_path
            self.accept()
            QTimer.singleShot(0, lambda: self.controller.open_case_path(path))


class _RecentPicker(QDialog):
    def __init__(self, entries, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Open Recent Case")
        self.setMinimumSize(520, 320)
        self.selected_path = None
        v = QVBoxLayout(self)
        v.addWidget(h2("Recent Cases"))
        self.list = QListWidget()
        for e in entries:
            item = QListWidgetItem(
                f"{e['case_id']}   |   {e['case_name']}   [{e.get('status','?')}]\n"
                f"{e['case_path']}")
            item.setData(Qt.ItemDataRole.UserRole, e["case_path"])
            self.list.addItem(item)
        self.list.itemDoubleClicked.connect(lambda _i: self._open())
        v.addWidget(self.list, 1)
        row = QHBoxLayout(); row.addStretch(1)
        cancel = QPushButton("Cancel"); cancel.setObjectName("Secondary")
        cancel.clicked.connect(self.reject)
        openb = QPushButton("Open"); openb.clicked.connect(self._open)
        row.addWidget(cancel); row.addWidget(openb)
        v.addLayout(row)

    def showEvent(self, event):  # noqa: N802 - Qt override
        super().showEvent(event)
        center_on_screen(self)

    def _open(self):
        item = self.list.currentItem()
        if item:
            self.selected_path = item.data(Qt.ItemDataRole.UserRole)
            self.accept()


# ===========================================================================
# New Case wizard
# ===========================================================================
class _CaseInfoPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Case Information")
        v = QVBoxLayout(self)
        form = QFormLayout()
        self.case_name = QLineEdit()
        self.case_name.textChanged.connect(self._update_preview)
        self.base_dir = QLineEdit()
        self.base_dir.textChanged.connect(self._update_preview)
        browse = QPushButton("Browse…"); browse.setObjectName("Secondary")
        browse.clicked.connect(self._browse)
        dir_row = QHBoxLayout(); dir_row.addWidget(self.base_dir); dir_row.addWidget(browse)
        dir_w = QWidget(); dir_w.setLayout(dir_row)

        form.addRow("Case Name *", self.case_name)
        form.addRow("Base Directory *", dir_w)
        v.addLayout(form)
        v.addSpacing(8)
        v.addWidget(QLabel("Case data will be stored in the following directory:"))
        self.preview = QLineEdit(); self.preview.setReadOnly(True)
        v.addWidget(self.preview)
        v.addStretch(1)

        self.registerField("caseName*", self.case_name)
        self.registerField("baseDir*", self.base_dir)

    def _browse(self):
        path = QFileDialog.getExistingDirectory(self, "Select Base Directory")
        if path:
            self.base_dir.setText(path)

    def _update_preview(self):
        base = self.base_dir.text().strip()
        name = sanitize_filename(self.case_name.text().strip(), fallback="case")
        self.preview.setText(str(Path(base) / name) if base else "")

    def validatePage(self):
        from PyQt6.QtWidgets import QMessageBox
        if not self.case_name.text().strip() or not self.base_dir.text().strip():
            QMessageBox.warning(self, "Case Information",
                                "Case Name and Base Directory are required.")
            return False
        if not Path(self.base_dir.text().strip()).exists():
            QMessageBox.warning(self, "Case Information",
                                "Base Directory does not exist.")
            return False
        return True


class _OptionalInfoPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Examiner & Case Details")
        v = QVBoxLayout(self)

        v.addWidget(h2("Case"))
        case_form = QFormLayout()
        self.number = QLineEdit()
        case_form.addRow("Number", self.number)
        v.addLayout(case_form)

        v.addWidget(h2("Examiner"))
        v.addWidget(muted("The examiner's Name and ID are recorded against every "
                          "action in the chain of custody, so both are required."))
        ex_form = QFormLayout()
        self.examiner = QLineEdit()
        self.examiner_id = QLineEdit()
        self.phone = QLineEdit()
        self.email = QLineEdit()
        self.notes = QPlainTextEdit(); self.notes.setFixedHeight(70)
        ex_form.addRow("Name *", self.examiner)
        ex_form.addRow("ID / Badge No. *", self.examiner_id)
        ex_form.addRow("Phone", self.phone)
        ex_form.addRow("Email", self.email)
        ex_form.addRow("Notes", self.notes)
        v.addLayout(ex_form)

        v.addWidget(h2("Organization"))
        org_form = QFormLayout()
        self.org = QLineEdit()
        org_form.addRow("Organization *", self.org)
        v.addLayout(org_form)
        v.addStretch(1)

    def validatePage(self):
        from PyQt6.QtWidgets import QMessageBox
        if (not self.examiner.text().strip()
                or not self.examiner_id.text().strip()
                or not self.org.text().strip()):
            QMessageBox.warning(
                self, "Examiner Details Required",
                "Examiner Name, ID and Organization are required: every action "
                "in the chain of custody is attributed to the examiner and the "
                "examining authority, so the case cannot be created anonymously.")
            return False
        return True


class NewCaseWizard(QWizard):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("New Case Information")
        self.setWizardStyle(QWizard.WizardStyle.ClassicStyle)
        self.setMinimumSize(700, 600)
        self.info_page = _CaseInfoPage()
        self.opt_page = _OptionalInfoPage()
        self.addPage(self.info_page)
        self.addPage(self.opt_page)

    def showEvent(self, event):  # noqa: N802 - Qt override
        super().showEvent(event)
        center_on_screen(self)

    def data(self) -> dict:
        name = self.info_page.case_name.text().strip()
        base = self.info_page.base_dir.text().strip()
        number = self.opt_page.number.text().strip()
        examiner = self.opt_page.examiner.text().strip()
        examiner_id = self.opt_page.examiner_id.text().strip()
        phone = self.opt_page.phone.text().strip()
        email = self.opt_page.email.text().strip()
        notes = self.opt_page.notes.toPlainText().strip()
        org = self.opt_page.org.text().strip()
        case_id = number or f"CASE-{utc_now_compact()}"
        return {
            "case_name": name, "save_location": base, "case_id": case_id,
            "examiner_name": examiner, "examiner_id": examiner_id,
            "organization": org, "examiner_phone": phone,
            "examiner_email": email, "notes": notes,
        }


# ===========================================================================
# Add Data Source wizard
# ===========================================================================
class _SourceTypePage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Select Data Source Type")
        v = QVBoxLayout(self)
        v.addSpacing(10)
        self.disk = QRadioButton("Disk Image or VM File")
        self.disk.setChecked(True)
        self.disk.setStyleSheet("font-size:14px; font-weight:600;")
        v.addWidget(self.disk)
        v.addWidget(muted("    Raw disk image (dd/img/raw/001), E01 (Expert "
                          "Witness) or VMDK virtual disk."))
        v.addStretch(1)


class _SelectSourcePage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Select Data Source")
        v = QVBoxLayout(self)
        form = QFormLayout()
        self.path = QLineEdit()
        browse = QPushButton("Browse…"); browse.setObjectName("Secondary")
        browse.clicked.connect(self._browse)
        row = QHBoxLayout(); row.addWidget(self.path); row.addWidget(browse)
        w = QWidget(); w.setLayout(row)
        form.addRow("Path *", w)
        self.timezone = QComboBox()
        self.timezone.addItems(["(GMT+0) UTC", "(GMT+8) Asia/Kuala_Lumpur",
                                "(GMT+0) Europe/London", "(GMT-5) America/New_York"])
        form.addRow("Time zone", self.timezone)
        v.addLayout(form)
        v.addStretch(1)
        self.registerField("sourcePath*", self.path)

    def _browse(self):
        exts = " ".join(f"*{e}" for e in sorted(filesystem.SUPPORTED_EXTS))
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Disk Image", "",
            f"Disk images ({exts});;All files (*.*)")
        if path:
            self.path.setText(path)

    def validatePage(self):
        from PyQt6.QtWidgets import QMessageBox
        if not Path(self.path.text().strip()).is_file():
            QMessageBox.warning(self, "Select Data Source",
                                "Please choose a valid disk-image file.")
            return False
        return True


class _IngestPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Configure Ingest")
        v = QVBoxLayout(self)
        v.addWidget(QLabel("Processing to run on the data source:"))
        self.hash = QCheckBox("Compute SHA-256 (source integrity)")
        self.hash.setChecked(True)
        self.carve = QCheckBox("Recover deleted images now (signature carving)")
        self.carve.setChecked(True)
        for c in (self.hash, self.carve):
            v.addWidget(c)
        v.addWidget(muted("    Carving scans the image for deleted JPEG/PNG/BMP/GIF "
                          "files. You can also start it later from Image Carving."))
        v.addStretch(1)


class AddDataSourceWizard(QWizard):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Data Source")
        self.setWizardStyle(QWizard.WizardStyle.ClassicStyle)
        self.setMinimumSize(680, 460)
        # Only one source type is supported, so the type-selection page is
        # skipped and the wizard starts at "Select Data Source".
        self.src_page = _SelectSourcePage()
        self.ingest_page = _IngestPage()
        self.addPage(self.src_page)
        self.addPage(self.ingest_page)

    def showEvent(self, event):  # noqa: N802 - Qt override
        super().showEvent(event)
        center_on_screen(self)

    def data(self) -> dict:
        return {
            "path": self.src_page.path.text().strip(),
            "run_hash": self.ingest_page.hash.isChecked(),
            "run_carve": self.ingest_page.carve.isChecked(),
        }
