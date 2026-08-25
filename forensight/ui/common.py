"""Reusable UI widgets: stat cards, section headers, image viewers."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import (QFrame, QLabel, QVBoxLayout, QHBoxLayout, QWidget,
                             QSizePolicy)

from . import style


def h1(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("H1")
    return lbl


def h2(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("H2")
    return lbl


def muted(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("Muted")
    lbl.setWordWrap(True)
    return lbl


class StatCard(QFrame):
    """A dashboard statistic tile."""

    def __init__(self, label: str, value: str = "0"):
        super().__init__()
        self.setObjectName("Card")
        self.setMinimumWidth(140)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        self.value_lbl = QLabel(value)
        self.value_lbl.setObjectName("StatValue")
        self.label_lbl = QLabel(label)
        self.label_lbl.setObjectName("StatLabel")
        layout.addWidget(self.value_lbl)
        layout.addWidget(self.label_lbl)

    def set_value(self, value) -> None:
        self.value_lbl.setText(str(value))


class Panel(QFrame):
    """A bordered white content panel with a vertical layout."""

    def __init__(self, title: Optional[str] = None):
        super().__init__()
        self.setObjectName("Panel")
        self.vbox = QVBoxLayout(self)
        self.vbox.setContentsMargins(16, 14, 16, 16)
        self.vbox.setSpacing(8)
        if title:
            self.vbox.addWidget(h2(title))

    def add(self, widget: QWidget) -> None:
        self.vbox.addWidget(widget)


class ImageView(QFrame):
    """Displays an image scaled to fit with a caption; safe on bad files."""

    def __init__(self, caption: str = ""):
        super().__init__()
        self.setObjectName("Card")
        self.setMinimumSize(240, 220)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        self.caption = QLabel(caption)
        self.caption.setObjectName("StatLabel")
        self.image_lbl = QLabel("No image")
        self.image_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_lbl.setObjectName("Muted")
        self.image_lbl.setSizePolicy(QSizePolicy.Policy.Expanding,
                                     QSizePolicy.Policy.Expanding)
        layout.addWidget(self.caption)
        layout.addWidget(self.image_lbl, 1)
        self._pixmap: Optional[QPixmap] = None

    def set_image(self, path: Optional[str]) -> None:
        if not path or not Path(path).exists():
            self._pixmap = None
            self.image_lbl.setText("Not Available")
            self.image_lbl.setPixmap(QPixmap())
            return
        pixmap = QPixmap(path)
        if pixmap.isNull():
            self._pixmap = None
            self.image_lbl.setText("Preview unavailable")
            return
        self._pixmap = pixmap
        self._rescale()

    def set_image_bytes(self, data: Optional[bytes]) -> None:
        """Display an image from in-memory bytes (used for filesystem files)."""
        if not data:
            self.clear()
            return
        pixmap = QPixmap()
        if pixmap.loadFromData(data):
            self._pixmap = pixmap
            self._rescale()
        else:
            self._pixmap = None
            self.image_lbl.setText("No preview")
            self.image_lbl.setPixmap(QPixmap())

    def clear(self) -> None:
        self._pixmap = None
        self.image_lbl.setText("No image")
        self.image_lbl.setPixmap(QPixmap())

    def _rescale(self) -> None:
        if self._pixmap is None:
            return
        area = self.image_lbl.size()
        scaled = self._pixmap.scaled(
            area, Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation)
        self.image_lbl.setPixmap(scaled)

    def resizeEvent(self, event):  # noqa: N802 - Qt override
        super().resizeEvent(event)
        self._rescale()


def status_html(text: str, kind: str = "muted") -> str:
    color = {"ok": style.OK, "warn": style.WARN, "danger": style.DANGER,
             "muted": style.MUTED, "accent": style.ACCENT}.get(kind, style.MUTED)
    return f'<span style="color:{color}; font-weight:600;">{text}</span>'
