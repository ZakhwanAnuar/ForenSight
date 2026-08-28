"""Modal dialogs: create case and bookmark evidence."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from PyQt6.QtWidgets import (QDialog, QFormLayout, QLineEdit, QComboBox,
                             QPlainTextEdit, QPushButton, QHBoxLayout,
                             QVBoxLayout, QFileDialog, QLabel, QWidget)

from .common import h2


class CreateCaseDialog(QDialog):
    """Collects the fields for a new forensic case (spec section 9)."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("Create New Forensic Case")
        self.setMinimumWidth(480)
        layout = QVBoxLayout(self)
        layout.addWidget(h2("Create New Forensic Case"))

        form = QFormLayout()
        form.setSpacing(8)
        self.case_name = QLineEdit()
        self.case_id = QLineEdit()
        self.examiner_name = QLineEdit()
        self.examiner_id = QLineEdit()
        self.organization = QLineEdit()

        self.save_location = QLineEdit()
        browse = QPushButton("Browse…")
        browse.setObjectName("Secondary")
        browse.clicked.connect(self._browse)
        loc_row = QHBoxLayout()
        loc_row.addWidget(self.save_location)
        loc_row.addWidget(browse)
        loc_widget = QWidget()
        loc_widget.setLayout(loc_row)

        form.addRow("Case Name *", self.case_name)
        form.addRow("Case ID / Reference *", self.case_id)
        form.addRow("Examiner Name *", self.examiner_name)
        form.addRow("Examiner ID / Badge *", self.examiner_id)
        form.addRow("Organization *", self.organization)
        form.addRow("Save Location *", loc_widget)
        layout.addLayout(form)

        self.error_lbl = QLabel("")
        self.error_lbl.setStyleSheet("color:#b02a2a; font-weight:600;")
        self.error_lbl.setWordWrap(True)
        layout.addWidget(self.error_lbl)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.setObjectName("Secondary")
        cancel.clicked.connect(self.reject)
        create = QPushButton("Create Case")
        create.clicked.connect(self._on_create)
        buttons.addWidget(cancel)
        buttons.addWidget(create)
        layout.addLayout(buttons)

        self.result_data: Optional[dict] = None

    def _browse(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select Save Location")
        if path:
            self.save_location.setText(path)

    def _on_create(self) -> None:
        data = {
            "case_name": self.case_name.text().strip(),
            "case_id": self.case_id.text().strip(),
            "examiner_name": self.examiner_name.text().strip(),
            "examiner_id": self.examiner_id.text().strip(),
            "organization": self.organization.text().strip(),
            "save_location": self.save_location.text().strip(),
        }
        missing = [k for k in ("case_name", "case_id", "examiner_name",
                               "examiner_id", "organization", "save_location")
                   if not data[k]]
        if missing:
            self.error_lbl.setText("Please fill all required (*) fields.")
            return
        if not Path(data["save_location"]).exists():
            self.error_lbl.setText("Save location does not exist.")
            return
        self.result_data = data
        self.accept()


class BookmarkDialog(QDialog):
    """Create or edit a forensic evidence bookmark (spec section 38)."""

    def __init__(self, file_name: str, existing: Optional[dict] = None,
                 parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("Bookmark Evidence")
        self.setMinimumWidth(440)
        layout = QVBoxLayout(self)
        layout.addWidget(h2(f"Bookmark: {file_name}"))

        form = QFormLayout()
        self.priority = QComboBox()
        self.priority.addItems(["LOW", "MEDIUM", "HIGH"])
        self.reason = QLineEdit()
        self.note = QPlainTextEdit()
        self.note.setFixedHeight(90)
        if existing:
            self.priority.setCurrentText(existing.get("priority", "LOW"))
            self.reason.setText(existing.get("reason", "") or "")
            self.note.setPlainText(existing.get("examiner_note", "") or "")
        form.addRow("Priority", self.priority)
        form.addRow("Reason", self.reason)
        form.addRow("Examiner Note", self.note)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.setObjectName("Secondary")
        cancel.clicked.connect(self.reject)
        save = QPushButton("Save Bookmark")
        save.clicked.connect(self.accept)
        buttons.addWidget(cancel)
        buttons.addWidget(save)
        layout.addLayout(buttons)

    def data(self) -> dict:
        return {
            "priority": self.priority.currentText(),
            "reason": self.reason.text().strip(),
            "examiner_note": self.note.toPlainText().strip(),
        }
