"""All primary investigation views (spec sections 36-48)."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont, QGuiApplication, QColor, QBrush
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QComboBox, QLineEdit, QSpinBox, QCheckBox,
    QPlainTextEdit, QProgressBar, QListWidget, QListWidgetItem, QFileDialog,
    QMessageBox, QAbstractItemView, QHeaderView, QSplitter, QScrollArea,
    QApplication, QTreeWidget, QTreeWidgetItem, QTabWidget, QDialog,
    QProgressDialog,
)

from .. import config
from ..carver import CarverWorker
from ..carving_service import persist_carved_file
from .. import analysis_service, evidence_manager, integrity_analyzer, ela
from ..stats import gather_stats
from ..utils import human_size, utc_now_iso
from ..audit_manager import verify_audit_chain
from .common import StatCard, Panel, ImageView, h1, h2, muted, status_html
from .style import MUTED, OK, WARN, DANGER
from .tree_assets import get_icon
from .dialogs import BookmarkDialog
from .workers import HashWorker


def _score_html(score, assessment) -> str:
    """A colored 0-100 Integrity & Provenance Score bar for the detail panel."""
    from .style import OK, WARN, DANGER, BORDER
    if assessment == "INSUFFICIENT_DATA" or score is None:
        return ('<div style="font-size:14px;"><b>Integrity &amp; Provenance Score:</b> '
                '<span style="color:#6a7788;">N/A (insufficient data)</span></div>')
    score = max(0, min(100, int(score)))
    color = DANGER if score >= 40 else (WARN if score >= 1 else OK)
    bar = (f'<table width="100%" cellspacing="0" cellpadding="0"><tr>'
           f'<td bgcolor="{color}" width="{score}%">&nbsp;</td>'
           f'<td bgcolor="{BORDER}" width="{100 - score}%">&nbsp;</td></tr></table>')
    return (f'<div style="font-size:15px;"><b>Integrity &amp; Provenance Score:</b> '
            f'<span style="color:{color}; font-weight:800; font-size:18px;">'
            f'{score}/100</span></div>{bar}')


def _fill_table(table: QTableWidget, headers, rows):
    table.clear()
    table.setColumnCount(len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, val in enumerate(row):
            item = QTableWidgetItem("" if val is None else str(val))
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            table.setItem(r, c, item)
    table.resizeColumnsToContents()


# ===========================================================================
# HOME / DASHBOARD
# ===========================================================================
class HomeView(QWidget):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.outer = QVBoxLayout(self)
        self.outer.setContentsMargins(24, 24, 24, 24)
        self.outer.setSpacing(14)
        self.refresh()

    def _clear(self):
        self._clear_layout(self.outer)

    def _clear_layout(self, layout):
        """Recursively remove widgets AND nested layouts (fixes duplicated
        buttons when the home view is refreshed more than once)."""
        while layout.count():
            item = layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.setParent(None)   # remove from display immediately
                w.deleteLater()
                continue
            child = item.layout()
            if child is not None:
                self._clear_layout(child)
                child.deleteLater()

    def refresh(self):
        self._clear()
        if self.controller.case is None:
            self._build_welcome()
        else:
            self._build_dashboard()

    # -- no active case ---------------------------------------------------
    def _build_welcome(self):
        # No case open: show nothing. Case creation/opening is driven by the
        # Welcome dialog on launch and the New Case / Open Case buttons in the
        # top bar, so the Home tab is deliberately empty here (no duplicate).
        self.outer.addStretch(1)

    def _load_recent(self):
        from .. import recent_cases
        self.recent_list.clear()
        entries = recent_cases.get_recent_cases()
        if not entries:
            self.recent_list.addItem("No recent cases yet.")
            return
        for e in entries:
            text = (f"{e['case_id']}   |   {e['case_name']}   "
                    f"[{e.get('status','?')}]   —   last opened "
                    f"{e.get('last_opened_utc','')}")
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, e["case_path"])
            self.recent_list.addItem(item)

    def _open_recent(self, item: QListWidgetItem):
        path = item.data(Qt.ItemDataRole.UserRole)
        if path:
            self.controller.open_case_path(path)

    # -- active case ------------------------------------------------------
    def _build_dashboard(self):
        case = self.controller.case
        info = case.db.get_case_info()
        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title_box.addWidget(h1(info["case_name"]))
        sub = QLabel(f"Case ID: {info['case_id']}    •    Examiner: {info['examiner_name']}")
        sub.setObjectName("Muted")
        title_box.addWidget(sub)
        header.addLayout(title_box)
        header.addStretch(1)
        status_kind = "danger" if case.read_only else "ok"
        status_txt = "CLOSED (READ ONLY)" if case.read_only else "● OPEN"
        status_lbl = QLabel(status_html(status_txt, status_kind))
        status_lbl.setStyleSheet("font-size:15px;")
        header.addWidget(status_lbl)
        self.outer.addLayout(header)

        stats = gather_stats(case)

        # Media-manipulation analysis overview.
        self.outer.addWidget(h2("Media Manipulation Analysis"))
        grid = QGridLayout()
        grid.setSpacing(12)
        media_cards = [
            ("Evidence Sources", stats.evidence_sources),
            ("Images Recovered", stats.files_recovered),
            ("Valid", stats.valid),
            ("Suspicious / Corrupt", stats.suspicious),
            ("Images Analysed", stats.images_analysed),
            ("Potential Anomalies", stats.potential_anomalies),
            ("Bookmarked", stats.bookmarked),
        ]
        for i, (label, value) in enumerate(media_cards):
            grid.addWidget(StatCard(label, str(value)), i // 4, i % 4)
        self.outer.addLayout(grid)

        if case.read_only:
            note = Panel("Case Status")
            note.add(muted("This case is CLOSED. Evidence, analysis and the "
                           "chain of custody are read-only. The final report is "
                           "available under Reports/Final."))
            self.outer.addWidget(note)

        quick = Panel("Next Steps")
        row = QHBoxLayout()
        quick_actions = [
            ("Evidence", lambda: self.controller.go_to_view(self.controller.evidence)),
            ("Recover Images", self.controller.open_carving_console),
            ("Report", lambda: self.controller.go_to_view(self.controller.report)),
        ]
        for label, handler in quick_actions:
            b = QPushButton(label)
            b.setObjectName("Secondary")
            b.clicked.connect(lambda _=False, h=handler: h())
            row.addWidget(b)
        row.addStretch(1)
        holder = QWidget()
        holder.setLayout(row)
        quick.add(holder)
        self.outer.addWidget(quick)
        self.outer.addStretch(1)


# ===========================================================================
# EVIDENCE
# ===========================================================================
class EvidenceView(QWidget):
    """Autopsy-style three-pane layout: navigation tree (left), results table
    (top-right) and a tabbed detail viewer (bottom-right)."""

    # Column layout for the results/listing table.
    _COLS = ["ID", "Filename", "Fmt", "Offset", "Size", "Status", "Recovery",
             "Assessment", "BM"]

    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self._carved_rows = []
        self._filter = ("all",)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(8)

        # -- top toolbar (Autopsy-style action row) --------------------
        bar = QHBoxLayout()
        self.import_btn = QPushButton("＋ Add Data Source")
        self.import_btn.setObjectName("AddSource")          # primary
        self.import_btn.clicked.connect(self._import)
        self.carve_btn = QPushButton("Recover Images")
        self.carve_btn.setObjectName("ToolbarSecondary")    # secondary
        self.carve_btn.clicked.connect(self._carve)
        self.verify_btn = QPushButton("Verify Integrity")
        self.verify_btn.setObjectName("ToolbarSecondary")   # normal button
        self.verify_btn.clicked.connect(self._verify)
        self.analyze_btn = QPushButton("Analyse Image")
        self.analyze_btn.setObjectName("Secondary")
        self.analyze_btn.setToolTip(
            "Run integrity & provenance analysis on the selected image.")
        self.analyze_btn.clicked.connect(self._analyze)
        self.analyze_btn.setEnabled(False)
        self.analyze_all_btn = QPushButton("Analyse All")
        self.analyze_all_btn.setObjectName("Secondary")
        self.analyze_all_btn.setToolTip(
            "Analyse every recovered image. Undecodable files return "
            "INSUFFICIENT_DATA.")
        self.analyze_all_btn.clicked.connect(self._analyze_all)
        self.bookmark_btn = QPushButton("Bookmark")
        self.bookmark_btn.setObjectName("BookmarkBtn")      # yellow utility
        self.bookmark_btn.clicked.connect(self._bookmark)
        self.bookmark_btn.setEnabled(False)
        bar.addWidget(self.import_btn)
        bar.addWidget(self.carve_btn)
        bar.addWidget(self.verify_btn)
        bar.addWidget(self.bookmark_btn)
        bar.addStretch(1)
        bar.addWidget(QLabel("Search:"))
        self.f_search = QLineEdit()
        self.f_search.setPlaceholderText("filename…")
        self.f_search.setFixedWidth(220)
        self.f_search.textChanged.connect(self._load_table)
        bar.addWidget(self.f_search)
        # Everything (toolbar + panes) lives in a container that is hidden when
        # no case is open, so the launch backdrop behind the wizard is blank.
        self._content = QWidget()
        content_v = QVBoxLayout(self._content)
        content_v.setContentsMargins(0, 0, 0, 0)
        content_v.setSpacing(8)
        content_v.addLayout(bar)

        # -- main three-pane splitter ----------------------------------
        main = QSplitter(Qt.Orientation.Horizontal)

        # Left: navigation tree with the analysis actions docked underneath.
        self.tree = QTreeWidget()
        self.tree.setColumnCount(2)
        self.tree.setHeaderHidden(True)
        self.tree.setIndentation(18)
        self.tree.setAnimated(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setRootIsDecorated(True)
        self.tree.setExpandsOnDoubleClick(False)
        self.tree.setIconSize(QSize(16, 16))
        hdr = self.tree.header()
        hdr.setStretchLastSection(False)
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.itemClicked.connect(self._on_tree_select)

        left_panel = QWidget()
        left_panel.setMinimumWidth(260)
        lp = QVBoxLayout(left_panel)
        lp.setContentsMargins(0, 0, 0, 0)
        lp.setSpacing(6)
        lp.addWidget(self.tree, 1)
        analysis_row = QHBoxLayout()
        analysis_row.setSpacing(6)
        analysis_row.addWidget(self.analyze_btn)
        analysis_row.addWidget(self.analyze_all_btn)
        lp.addLayout(analysis_row)
        main.addWidget(left_panel)

        # Right: vertical splitter of listing (top) + detail tabs (bottom).
        right = QSplitter(Qt.Orientation.Vertical)
        table_wrap = QWidget()
        tw = QVBoxLayout(table_wrap)
        tw.setContentsMargins(0, 0, 0, 0)
        tw.setSpacing(4)
        self.filter_status = QLabel("Showing: All recovered images")
        self.filter_status.setObjectName("FilterStatus")
        tw.addWidget(self.filter_status)
        self.table = QTableWidget()
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self._on_row_select)
        tw.addWidget(self.table, 1)
        right.addWidget(table_wrap)
        right.addWidget(self._build_detail_tabs())
        right.setSizes([360, 300])

        main.addWidget(right)
        main.setSizes([250, 760])
        content_v.addWidget(main, 1)
        outer.addWidget(self._content, 1)

    # -- detail viewer ----------------------------------------------------
    def _build_detail_tabs(self):
        """Persistent image preview on the LEFT; switchable info tabs on the
        RIGHT (File Metadata / EXIF / Integrity & Provenance / Hex)."""
        split = QSplitter(Qt.Orientation.Horizontal)

        # Left: fixed image preview.
        self.tab_preview = ImageView("Recovered Image")
        split.addWidget(self.tab_preview)

        # Right: switchable detail tabs. Integrity & Provenance leads, as it is
        # the primary forensic verdict for the selected file.
        tabs = QTabWidget()

        self.tab_assessment = QLabel("Not analysed.")
        self.tab_assessment.setWordWrap(True)
        self.tab_assessment.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.tab_assessment.setContentsMargins(10, 10, 10, 10)
        as_scroll = QScrollArea(); as_scroll.setWidgetResizable(True)
        as_scroll.setWidget(self.tab_assessment)
        tabs.addTab(as_scroll, "Integrity & Provenance")

        self.tab_meta = QLabel("Select a file to view its metadata.")
        self.tab_meta.setWordWrap(True)
        self.tab_meta.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.tab_meta.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.tab_meta.setContentsMargins(10, 10, 10, 10)
        meta_scroll = QScrollArea(); meta_scroll.setWidgetResizable(True)
        meta_scroll.setWidget(self.tab_meta)
        tabs.addTab(meta_scroll, "File Metadata")

        self.tab_exif = QTableWidget()
        self.tab_exif.setColumnCount(2)
        self.tab_exif.setHorizontalHeaderLabels(["Field", "Value"])
        self.tab_exif.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch)
        tabs.addTab(self.tab_exif, "EXIF")

        self.tab_hex = QPlainTextEdit(); self.tab_hex.setReadOnly(True)
        self.tab_hex.setFont(QFont("Consolas", 9))
        tabs.addTab(self.tab_hex, "Hex")

        split.addWidget(tabs)
        split.setStretchFactor(0, 1)   # preview
        split.setStretchFactor(1, 1)   # tabs
        split.setSizes([440, 520])
        return split

    # -- tree -------------------------------------------------------------
    def refresh(self):
        case = self.controller.case
        if case is None:
            self._content.setVisible(False)   # blank backdrop when no case
            self.tree.clear()
            self.table.setRowCount(0)
            return
        self._content.setVisible(True)
        # A closed (read-only) case blocks write actions; viewing/verifying stay.
        writable = not case.read_only
        self.import_btn.setEnabled(writable)
        self.carve_btn.setEnabled(writable)
        self.analyze_all_btn.setEnabled(writable)
        self._build_tree()
        self._load_table()

    def _count(self, where="", params=()):
        case = self.controller.case
        return case.db.count(
            f"SELECT COUNT(*) FROM carved_evidence c "
            f"LEFT JOIN image_analysis a ON a.carved_evidence_id = c.id "
            f"LEFT JOIN bookmarks b ON b.carved_evidence_id = c.id "
            + (f"WHERE {where}" if where else ""), params)

    def _section_header(self, text):
        """A top-level folder row (Data Sources / Views / Results).

        Rendered as a bold folder node; it carries no filter and is not
        selectable — clicking it toggles expansion.
        """
        item = QTreeWidgetItem([text, ""])
        item.setIcon(0, get_icon("folder"))
        f = item.font(0)
        f.setBold(True)
        item.setFont(0, f)
        item.setFlags(Qt.ItemFlag.ItemIsEnabled)
        self.tree.invisibleRootItem().addChild(item)
        return item

    def _add_node(self, parent, label, filt, count=None, icon="page"):
        item = QTreeWidgetItem([label, "" if count is None else str(count)])
        item.setData(0, Qt.ItemDataRole.UserRole, filt)
        if icon:
            item.setIcon(0, get_icon(icon))
        if count is not None:
            item.setTextAlignment(
                1, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            item.setForeground(1, QBrush(QColor(MUTED)))
            if count == 0:  # dim empty categories so populated ones stand out
                item.setForeground(0, QBrush(QColor(MUTED)))
        parent.addChild(item)
        return item

    def _build_tree(self):
        case = self.controller.case
        # remember current selection filter to restore after rebuild
        prev = self._filter
        self.tree.blockSignals(True)
        self.tree.clear()

        # Data Sources ---------------------------------------------------
        ds = self._section_header("Data Sources")
        for r in case.db.get_evidence_sources():
            n = self._count("c.evidence_id = ?", (r["evidence_id"],))
            self._add_node(ds, r["evidence_name"],
                           ("source", r["evidence_id"]), n, icon="disk")
        ds.setExpanded(True)

        # Views ----------------------------------------------------------
        views = self._section_header("Views")
        ft = self._add_node(views, "File Types", ("all",), icon="folder")
        for fmt in ("JPEG", "PNG", "BMP", "GIF"):
            n = self._count("c.file_format = ?", (fmt,))
            self._add_node(ft, fmt, ("format", fmt), n, icon="page")
        ft.setExpanded(True)
        # "All Recovered Images" is an expandable folder; clicking it shows all,
        # and its children break the set down by allocation / condition.
        allr = self._add_node(views, "All Recovered Images", ("all",),
                              self._count(), icon="folder")
        self._add_node(allr, "Live Files (Allocated)",
                       ("allocation", "Allocated"),
                       self._count("c.allocation_status = 'Allocated'"), icon="page")
        self._add_node(allr, "Deleted Files (Recovered)",
                       ("allocation", "Deleted"),
                       self._count("c.allocation_status = 'Deleted'"), icon="dot_red")
        self._add_node(allr, "Suspicious / Quarantined", ("suspicious",),
                       self._count("c.is_suspicious = 1"), icon="dot_amber")
        allr.setExpanded(True)
        views.setExpanded(True)

        # Results --------------------------------------------------------
        results = self._section_header("Results")
        self._add_node(results, "Bookmarks", ("bookmarked",),
                       self._count("b.id IS NOT NULL"), icon="star")
        self._add_node(results, "Strong Indicators",
                       ("assessment", "STRONG_INDICATORS"),
                       self._count("a.assessment = ?", ("STRONG_INDICATORS",)),
                       icon="dot_red")
        self._add_node(results, "Processing Detected",
                       ("assessment", "POTENTIAL_MANIPULATION"),
                       self._count("a.assessment = ?", ("POTENTIAL_MANIPULATION",)),
                       icon="dot_amber")
        self._add_node(results, "No Anomalies",
                       ("assessment", "NO_SIGNIFICANT_ANOMALIES"),
                       self._count("a.assessment = ?", ("NO_SIGNIFICANT_ANOMALIES",)),
                       icon="dot_green")
        results.setExpanded(True)

        self.tree.blockSignals(False)
        self._filter = prev

    def _on_tree_select(self, item, _col=0):
        filt = item.data(0, Qt.ItemDataRole.UserRole)
        if filt is None:  # section header — clicking toggles its group
            item.setExpanded(not item.isExpanded())
            return
        self._filter = tuple(filt)
        self._load_table()

    # -- listing table ----------------------------------------------------
    def _filter_clause(self):
        kind = self._filter[0]
        if kind == "format":
            return "c.file_format = ?", [self._filter[1]]
        if kind == "suspicious":
            return "c.is_suspicious = 1", []
        if kind == "allocation":
            return "c.allocation_status = ?", [self._filter[1]]
        if kind == "bookmarked":
            return "b.id IS NOT NULL", []
        if kind == "assessment":
            return "a.assessment = ?", [self._filter[1]]
        if kind == "source":
            return "c.evidence_id = ?", [self._filter[1]]
        return "", []

    def _load_table(self):
        case = self.controller.case
        if case is None:
            return
        clause, params = self._filter_clause()
        clauses = [clause] if clause else []
        if self.f_search.text().strip():
            clauses.append("c.file_name LIKE ?")
            params.append(f"%{self.f_search.text().strip()}%")
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"""
            SELECT c.id, c.file_name, c.file_format, c.source_offset_hex,
                   c.file_size_bytes, c.is_valid, c.is_suspicious,
                   c.sha256_hash, c.file_path, c.validation_message,
                   c.recovery_method, c.evidence_id,
                   c.allocation_status,
                   (b.id IS NOT NULL) AS bookmarked,
                   a.assessment AS assessment
              FROM carved_evidence c
              LEFT JOIN bookmarks b ON b.carved_evidence_id = c.id
              LEFT JOIN image_analysis a ON a.carved_evidence_id = c.id
              {where}
             ORDER BY c.id
        """
        self._carved_rows = case.db.query_all(sql, params)
        display = []
        for r in self._carved_rows:
            state = "Valid" if r["is_valid"] else ("Suspicious" if r["is_suspicious"] else "Invalid")
            alloc = r["allocation_status"] if "allocation_status" in r.keys() else "Unknown"
            assess = integrity_analyzer.label(r["assessment"]) if r["assessment"] else "—"
            display.append([r["id"], r["file_name"], r["file_format"],
                            r["source_offset_hex"], human_size(r["file_size_bytes"]),
                            state, alloc or "Unknown", assess,
                            "★" if r["bookmarked"] else ""])
        _fill_table(self.table, self._COLS, display)
        self._colorize_rows()
        self.table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch)
        # Active-filter indicator so the dynamic tree filtering is visible.
        label = self._filter_label()
        search = self.f_search.text().strip()
        if search:
            label += f'  (search: "{search}")'
        n = len(self._carved_rows)
        self.filter_status.setText(
            f"Showing: <b>{label}</b> — {n} file{'s' if n != 1 else ''}")
        self._clear_details()

    # Triage colours: green = clean, amber = processing, red = strong indicators.
    _ASSESS_COLOR = {
        "NO_SIGNIFICANT_ANOMALIES": OK,
        "POTENTIAL_MANIPULATION": WARN,
        "STRONG_INDICATORS": DANGER,
    }

    def _colorize_rows(self):
        """Tint each analysed row's Filename + Assessment cells by outcome so the
        investigator can triage at a glance (red/amber/green)."""
        name_col = self._COLS.index("Filename")
        assess_col = self._COLS.index("Assessment")
        for i, r in enumerate(self._carved_rows):
            color = self._ASSESS_COLOR.get(r["assessment"])
            if not color:
                continue
            brush = QBrush(QColor(color))
            strong = r["assessment"] == "STRONG_INDICATORS"
            for col in (name_col, assess_col):
                item = self.table.item(i, col)
                if item is None:
                    continue
                item.setForeground(brush)
                if strong:
                    f = item.font(); f.setBold(True); item.setFont(f)

    def _filter_label(self) -> str:
        kind = self._filter[0]
        if kind == "format":
            return f"File type · {self._filter[1]}"
        if kind == "suspicious":
            return "Suspicious / quarantined"
        if kind == "allocation":
            return f"Allocation · {self._filter[1]}"
        if kind == "bookmarked":
            return "Bookmarked"
        if kind == "assessment":
            return f"Assessment · {integrity_analyzer.label(self._filter[1])}"
        if kind == "source":
            case = self.controller.case
            row = case.db.get_evidence_source(self._filter[1]) if case else None
            return f"Data source · {row['evidence_name']}" if row else "Data source"
        return "All recovered images"

    def _selected_row(self):
        idx = self.table.currentRow()
        if idx < 0 or idx >= len(self._carved_rows):
            return None
        return self._carved_rows[idx]

    # -- detail population ------------------------------------------------
    def _clear_details(self):
        self.tab_preview.clear()
        self.tab_meta.setText("Select a file to view its metadata.")
        self.tab_assessment.setText("Not analysed.")
        self.tab_exif.setRowCount(0)
        self.tab_hex.setPlainText("")
        self.bookmark_btn.setEnabled(False)
        self.analyze_btn.setEnabled(False)

    def _on_row_select(self):
        row = self._selected_row()
        case = self.controller.case
        if row is None or case is None:
            return
        analysis = case.db.get_image_analysis(row["id"])
        exif = case.db.get_exif(row["id"])
        assessment = analysis["assessment"] if analysis else "Not analysed"
        ftype = "Match" if (analysis and analysis["file_type_match"]) else \
                ("Mismatch / Unknown" if analysis else "Not analysed")

        # Preview
        self.tab_preview.set_image(row["file_path"])

        # File Metadata tab
        self.tab_meta.setText(
            f"<b>Evidence ID:</b> {row['id']}<br>"
            f"<b>Filename:</b> {row['file_name']}<br>"
            f"<b>Format:</b> {row['file_format']}<br>"
            f"<b>Source Offset:</b> {row['source_offset_hex']}<br>"
            f"<b>Recovery Method:</b> {row['recovery_method']}<br>"
            f"<b>Allocation:</b> "
            f"{row['allocation_status'] if 'allocation_status' in row.keys() else 'Unknown'}"
            "<br>"
            f"<b>File Size:</b> {human_size(row['file_size_bytes'])} "
            f"({row['file_size_bytes']:,} bytes)<br>"
            f"<b>SHA-256:</b><br><span style='font-family:Consolas;font-size:10px'>"
            f"{row['sha256_hash']}</span><br>"
            f"<b>Validation:</b> {row['validation_message']}<br>"
            f"<b>Suspicious:</b> {'Yes' if row['is_suspicious'] else 'No'}<br>"
            f"<b>File-Type Match:</b> {ftype}<br>"
            f"<b>File Path:</b> {row['file_path']}"
        )

        # EXIF tab
        if exif:
            fields = [("Camera Make", exif["camera_make"]),
                      ("Camera Model", exif["camera_model"]),
                      ("Capture DateTime", exif["capture_datetime"]),
                      ("Software", exif["software"]),
                      ("Orientation", exif["orientation"]),
                      ("GPS Latitude", exif["gps_latitude"]),
                      ("GPS Longitude", exif["gps_longitude"])]
            self.tab_exif.setRowCount(len(fields))
            for i, (k, v) in enumerate(fields):
                ki = QTableWidgetItem(k); vi = QTableWidgetItem(str(v))
                ki.setFlags(ki.flags() & ~Qt.ItemFlag.ItemIsEditable)
                vi.setFlags(vi.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.tab_exif.setItem(i, 0, ki)
                self.tab_exif.setItem(i, 1, vi)
        else:
            self.tab_exif.setRowCount(1)
            self.tab_exif.setItem(0, 0, QTableWidgetItem("EXIF"))
            self.tab_exif.setItem(0, 1, QTableWidgetItem("Not analysed / Not Available"))

        # Integrity & Provenance tab
        if analysis:
            kind = {"NO_SIGNIFICANT_ANOMALIES": "ok", "POTENTIAL_MANIPULATION": "warn",
                    "STRONG_INDICATORS": "danger"}.get(assessment, "muted")
            label = integrity_analyzer.label(assessment)
            prov = analysis["provenance"] if "provenance" in analysis.keys() else None
            prov_up = prov.upper() if prov else ""
            if prov and ("INVALID" in prov_up or "TAMPERING" in prov_up
                         or "EDITED AFTER SIGNING" in prov_up):
                note = ("C2PA signature failed cryptographic verification."
                        if "INVALID" in prov_up else
                        "C2PA signature is valid but the image bytes changed "
                        "after signing (cryptographically proven).")
                prov_html = (f"<div style='background:#fbeaea;border:1px solid #d99;"
                             f"padding:6px 8px;border-radius:4px;margin-bottom:6px;'>"
                             f"<b>Content Provenance (FACT):</b> {prov}<br>"
                             f"<span style='font-size:11px;color:#666'>{note}</span></div>")
            elif prov and "AI-GENERATED" in prov_up:
                prov_html = (f"<div style='background:#fbeaea;border:1px solid #d99;"
                             f"padding:6px 8px;border-radius:4px;margin-bottom:6px;'>"
                             f"<b>Content Provenance (FACT):</b> {prov}<br>"
                             f"<span style='font-size:11px;color:#666'>Metadata "
                             f"self-declares generative/AI origin (C2PA).</span></div>")
            elif prov:
                prov_html = f"<b>Content Provenance:</b> {prov}<br>"
            else:
                prov_html = "<b>Content Provenance:</b> None detected<br>"
            score = analysis["manipulation_score"]
            self.tab_assessment.setText(
                f"<h3>Assessment: {status_html(label, kind)}</h3>"
                f"<b>Integrity &amp; Provenance Score:</b> "
                f"{score if score is not None else 'N/A'}/100<br>"
                f"{prov_html}"
                f"<b>JPEG Quality:</b> {analysis['jpeg_quality_estimate']}<br>"
                f"<b>JPEG Analysis:</b> {analysis['jpeg_quantization_summary'] or 'N/A'}<br>"
                f"<b>File-Type:</b> {ftype}<br>"
                f"<b>Thumbnail:</b> {'Recovered' if analysis['thumbnail_path'] else 'None'}<br>"
                f"<hr><i>{integrity_analyzer.CAUTION}</i>")
        else:
            self.tab_assessment.setText("This image has not been analysed yet. "
                                        "Select it and click <b>Analyse Image</b> in "
                                        "the toolbar above.")

        # Hex tab (first 512 bytes)
        self.tab_hex.setPlainText(self._hex_dump(row["file_path"]))

        self.bookmark_btn.setEnabled(not case.read_only)
        self.analyze_btn.setEnabled(not case.read_only)

    @staticmethod
    def _hex_dump(path, length=512):
        try:
            with open(path, "rb") as fh:
                data = fh.read(length)
        except OSError:
            return "(file not accessible)"
        lines = []
        for off in range(0, len(data), 16):
            chunk = data[off:off + 16]
            hexpart = " ".join(f"{b:02X}" for b in chunk).ljust(47)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{off:08X}  {hexpart}  {ascii_part}")
        return "\n".join(lines)

    # -- actions ----------------------------------------------------------
    def _import(self):
        case = self.controller.case
        if case is None or case.read_only:
            QMessageBox.information(self, "Add Data Source",
                                    "Open a writable case first.")
            return
        # Autopsy-style Add Data Source wizard (type -> source -> ingest).
        self.controller.add_data_source_flow()

    def _carve(self):
        case = self.controller.case
        if case is None:
            QMessageBox.information(self, "Recover Images",
                                    "Open a case and add a data source first.")
            return
        self.controller.open_carving_console()

    def _verify(self):
        case = self.controller.case
        if case is None:
            return
        # Verify the data source selected in the tree, else the first source.
        evidence_id = None
        if self._filter[0] == "source":
            evidence_id = self._filter[1]
        else:
            sources = case.db.get_evidence_sources()
            if len(sources) == 1:
                evidence_id = sources[0]["evidence_id"]
        if evidence_id is None:
            QMessageBox.information(self, "Verify Integrity",
                                    "Select a data source in the tree first "
                                    "(under 'Data Sources').")
            return
        self.controller.verify_evidence_flow(evidence_id)

    def _bookmark(self):
        row = self._selected_row()
        case = self.controller.case
        if row is None or case is None or case.read_only:
            return
        existing = case.db.get_bookmark(row["id"])
        existing_d = dict(existing) if existing else None
        dlg = BookmarkDialog(row["file_name"], existing_d, self)
        if dlg.exec():
            d = dlg.data()
            now = utc_now_iso()
            case.db.upsert_bookmark({
                "carved_evidence_id": row["id"], "priority": d["priority"],
                "reason": d["reason"], "examiner_note": d["examiner_note"],
                "created_utc": now, "updated_utc": now,
            })
            case.audit.record("BOOKMARK_CREATED",
                              f"Bookmarked {row['file_name']} ({d['priority']}).",
                              evidence_id=row["id"])
            self.controller.refresh_all()

    # -- analysis (integrity & provenance) --------------------------------
    def _select_row_by_id(self, cid):
        """Re-select a row by evidence id after the table is rebuilt."""
        for i, r in enumerate(self._carved_rows):
            if r["id"] == cid:
                self.table.selectRow(i)
                return

    def _analyze(self):
        """Run integrity & provenance analysis on the selected image."""
        case = self.controller.case
        row = self._selected_row()
        if case is None or row is None or case.read_only:
            return
        cid = row["id"]
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            analysis_service.analyze_carved_image(case, cid)
        except Exception as exc:  # noqa: BLE001
            QApplication.restoreOverrideCursor()
            QMessageBox.critical(self, "Analysis Error", str(exc))
            return
        QApplication.restoreOverrideCursor()
        self.refresh()                 # rebuild tree counts + recolour the table
        self._select_row_by_id(cid)    # keep the user on the image they analysed
        self.controller.refresh_dashboard()

    def _analyze_all(self):
        """Analyse every recovered image, including suspicious ones. Undecodable
        files return INSUFFICIENT_DATA rather than failing the batch."""
        case = self.controller.case
        if case is None or case.read_only:
            return
        targets = [r["id"] for r in case.db.get_all_carved()]
        if not targets:
            QMessageBox.information(self, "Analysis",
                                    "No recovered images to analyse.")
            return
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        errors = 0
        for cid in targets:
            try:
                analysis_service.analyze_carved_image(case, cid)
            except Exception:  # noqa: BLE001
                errors += 1
        QApplication.restoreOverrideCursor()
        self.refresh()
        self.controller.refresh_dashboard()
        QMessageBox.information(self, "Analysis",
                                f"Analysed {len(targets) - errors} image(s)."
                                + (f" {errors} failed." if errors else ""))


# ===========================================================================
# DRIVE CARVING
# ===========================================================================
class CarvingDialog(QDialog):
    """Deleted-image recovery console, opened from the Evidence tab."""

    def __init__(self, controller):
        super().__init__(controller)   # parented to the main window (no taskbar entry)
        self.controller = controller
        self.worker: Optional[CarverWorker] = None
        self._start_time = 0.0
        self._recovered = 0
        self._suspicious = 0
        self._duplicate = 0
        self._evidence_id = None
        self._alloc_map = None

        self.setWindowTitle("Recover Images — Signature Carving")
        self.setModal(False)
        self.setMinimumSize(720, 640)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 16, 16, 16)
        outer.setSpacing(10)
        outer.addWidget(h1("Recover Images"))
        outer.addWidget(muted(
            "Signature-based carving extracts every image matching a known "
            "signature from the raw source — existing, deleted and fragments. "
            "Re-running is safe: images already recovered are skipped."))

        cfg = Panel("Scan Configuration")
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Evidence Source:"))
        self.source_combo = QComboBox()
        row1.addWidget(self.source_combo, 1)
        holder1 = QWidget(); holder1.setLayout(row1)
        cfg.add(holder1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Scan Formats:"))
        self.chk = {}
        for fmt in ("JPEG", "PNG", "BMP", "GIF"):
            box = QCheckBox(fmt); box.setChecked(True)
            self.chk[fmt] = box
            row2.addWidget(box)
        row2.addSpacing(20)
        row2.addWidget(QLabel("Suspicious Threshold (KB):"))
        self.threshold = QSpinBox(); self.threshold.setRange(1, 10240)
        self.threshold.setValue(config.SUSPICIOUS_SIZE_THRESHOLD // 1024)
        row2.addWidget(self.threshold)
        row2.addStretch(1)
        holder2 = QWidget(); holder2.setLayout(row2)
        cfg.add(holder2)
        outer.addWidget(cfg)

        ctrl = QHBoxLayout()
        self.start_btn = QPushButton("START SCAN")
        self.start_btn.clicked.connect(self._start)
        self.pause_btn = QPushButton("⏸ Pause"); self.pause_btn.setObjectName("Secondary")
        self.pause_btn.clicked.connect(self._pause)
        self.resume_btn = QPushButton("⏵ Resume"); self.resume_btn.setObjectName("Secondary")
        self.resume_btn.clicked.connect(self._resume)
        self.cancel_btn = QPushButton("⏹ Cancel"); self.cancel_btn.setObjectName("Danger")
        self.cancel_btn.clicked.connect(self._cancel)
        for b in (self.pause_btn, self.resume_btn, self.cancel_btn):
            b.setEnabled(False)
        ctrl.addWidget(self.start_btn); ctrl.addWidget(self.pause_btn)
        ctrl.addWidget(self.resume_btn); ctrl.addWidget(self.cancel_btn)
        ctrl.addStretch(1)
        outer.addLayout(ctrl)

        prog = Panel("Progress")
        self.progress = QProgressBar()
        prog.add(self.progress)
        self.prog_label = QLabel("Idle.")
        self.prog_label.setObjectName("Muted")
        prog.add(self.prog_label)
        outer.addWidget(prog)

        log_panel = Panel("Execution Log")
        self.log = QPlainTextEdit(); self.log.setReadOnly(True)
        log_panel.add(self.log)
        outer.addWidget(log_panel, 1)

        close_row = QHBoxLayout()
        close_row.addStretch(1)
        self.close_btn = QPushButton("Close")
        self.close_btn.setObjectName("Secondary")
        self.close_btn.clicked.connect(self.close)
        close_row.addWidget(self.close_btn)
        outer.addLayout(close_row)

    def showEvent(self, event):  # noqa: N802 - Qt override
        super().showEvent(event)
        screen = self.screen() or QGuiApplication.primaryScreen()
        if screen is not None:
            frame = self.frameGeometry()
            frame.moveCenter(screen.availableGeometry().center())
            self.move(frame.topLeft())

    def closeEvent(self, event):  # noqa: N802 - Qt override
        if self.has_active_scan():
            resp = QMessageBox.question(
                self, "Carving", "A scan is running. Cancel it and close?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if resp != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            if self.worker:
                self.worker.cancel()
                self.worker.wait(2000)
        event.accept()

    def refresh(self):
        case = self.controller.case
        self.source_combo.clear()
        if case is None:
            return
        for r in case.db.get_evidence_sources():
            self.source_combo.addItem(f"{r['evidence_id']}: {r['evidence_name']}",
                                      r["evidence_id"])
        scanning = self.worker is not None and self.worker.isRunning()
        editable = not case.read_only and not scanning
        self.start_btn.setEnabled(editable and self.source_combo.count() > 0)

    # -- lifecycle --------------------------------------------------------
    def _set_scanning(self, scanning: bool):
        self.start_btn.setEnabled(not scanning)
        self.pause_btn.setEnabled(scanning)
        self.resume_btn.setEnabled(False)
        self.cancel_btn.setEnabled(scanning)
        self.source_combo.setEnabled(not scanning)
        for b in self.chk.values():
            b.setEnabled(not scanning)
        self.threshold.setEnabled(not scanning)
        self.controller.set_scanning(scanning)

    def _start(self):
        case = self.controller.case
        if case is None or case.read_only:
            return
        row = case.db.get_evidence_source(self.source_combo.currentData())
        if row is None:
            QMessageBox.information(self, "Carving", "Import an evidence source first.")
            return
        if not Path(row["source_path"]).exists():
            QMessageBox.warning(self, "Carving",
                                "Evidence source file is not accessible.")
            return
        formats = {f for f, b in self.chk.items() if b.isChecked()}
        if not formats:
            QMessageBox.information(self, "Carving", "Select at least one format.")
            return

        self._evidence_id = row["evidence_id"]
        self._threshold_bytes = self.threshold.value() * 1024
        self._recovered = 0
        self._suspicious = 0
        self._duplicate = 0
        self._start_time = time.time()
        self.progress.setValue(0)
        self.log.clear()
        self.log.appendPlainText(f"Scanning {row['evidence_name']} for {sorted(formats)}…")
        case.audit.record("CARVING_STARTED",
                          f"Carving started on '{row['evidence_name']}'.")

        # Build a filesystem allocation map so recovered images can be tagged
        # Allocated (live) / Deleted / Unallocated (None if no parseable FS).
        from .. import allocation as _alloc
        self.log.appendPlainText("Parsing filesystem for allocation status…")
        QApplication.processEvents()
        self._alloc_map = _alloc.build_allocation_map(row["source_path"])
        self.log.appendPlainText(
            "Filesystem parsed: live/deleted classification enabled."
            if self._alloc_map is not None else
            "No parseable filesystem — allocation status will be 'Unknown'.")

        self.worker = CarverWorker(row["source_path"], formats)
        self.worker.file_carved.connect(self._on_file)
        self.worker.offset_updated.connect(self._on_offset)
        self.worker.progress_updated.connect(self.progress.setValue)
        self.worker.log_message.connect(self.log.appendPlainText)
        self.worker.scan_completed.connect(self._on_complete)
        self.worker.scan_cancelled.connect(self._on_cancelled)
        self.worker.scan_error.connect(self._on_error)
        self._set_scanning(True)
        self.worker.start()

    def _on_file(self, payload: dict):
        case = self.controller.case
        try:
            res = persist_carved_file(case, self._evidence_id, payload,
                                      self._threshold_bytes,
                                      allocation_map=self._alloc_map)
            if res.is_duplicate:
                self._duplicate += 1
                return
            self._recovered += 1
            if res.is_suspicious:
                self._suspicious += 1
        except Exception as exc:  # noqa: BLE001
            self.log.appendPlainText(f"! Failed to store carved file: {exc}")

    def _on_offset(self, done: int, total: int):
        elapsed = time.time() - self._start_time
        self.prog_label.setText(
            f"Offset {done:,} / {total:,} bytes    •    New: {self._recovered}"
            f"    •    Suspicious: {self._suspicious}    •    "
            f"Already had: {self._duplicate}    •    "
            f"Elapsed: {time.strftime('%M:%S', time.gmtime(elapsed))}")

    def _on_complete(self, total: int):
        dup = (f" {self._duplicate} were already recovered (skipped)."
               if self._duplicate else "")
        self.log.appendPlainText(
            f"Scan complete. {self._recovered} new image(s) recovered "
            f"({self._suspicious} suspicious).{dup}")
        self._set_scanning(False)
        self.worker = None
        self.controller.refresh_all()

    def _on_cancelled(self):
        self.log.appendPlainText("⏹ Scan cancelled. Completed results preserved.")
        self._set_scanning(False)
        self.worker = None
        self.controller.refresh_all()

    def _on_error(self, msg: str):
        self.log.appendPlainText(f"Scan error: {msg}")
        QMessageBox.critical(self, "Carving Error", msg)
        self._set_scanning(False)
        self.worker = None

    def _pause(self):
        if self.worker:
            self.worker.pause()
            self.pause_btn.setEnabled(False)
            self.resume_btn.setEnabled(True)

    def _resume(self):
        if self.worker:
            self.worker.resume()
            self.pause_btn.setEnabled(True)
            self.resume_btn.setEnabled(False)

    def _cancel(self):
        if self.worker:
            self.worker.cancel()
            self.cancel_btn.setEnabled(False)

    def has_active_scan(self) -> bool:
        return self.worker is not None and self.worker.isRunning()


# ===========================================================================
# TIMELINE
# ===========================================================================
class ELAView(QWidget):
    """Full-page Error Level Analysis comparison (NON-SCORING visual aid).

    Left: every recovered image, tinted by its triage assessment (green/amber/
    red).  Right: the selected image shown side by side with its ELA heatmap.
    ELA never contributes to the forensic score; this page is an investigator
    aid only, and the caveat is shown alongside every comparison.
    """

    _ASSESS_COLOR = {
        "NO_SIGNIFICANT_ANOMALIES": OK,
        "POTENTIAL_MANIPULATION": WARN,
        "STRONG_INDICATORS": DANGER,
    }

    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self._rows = []
        self._ela_cache = {}          # path -> (png_bytes_or_None, hint_text)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 20, 20, 20)
        outer.setSpacing(8)
        outer.addWidget(h1("Error Level Analysis — Comparison"))
        outer.addWidget(muted(
            "Non-scoring visual aid. Select a recovered image to compare it "
            "with its ELA heatmap. ELA is excluded from the forensic score."))

        split = QSplitter(Qt.Orientation.Horizontal)

        # Left: colour-coded file list.
        self.list = QListWidget()
        self.list.itemSelectionChanged.connect(self._on_pick)
        split.addWidget(self.list)

        # Right: original vs ELA, side by side, with hint + caveat below.
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(6)
        compare = QSplitter(Qt.Orientation.Horizontal)
        self.orig_view = ImageView("Recovered Image")
        self.heat_view = ImageView("ELA Heatmap")
        compare.addWidget(self.orig_view)
        compare.addWidget(self.heat_view)
        compare.setSizes([440, 440])
        rl.addWidget(compare, 1)
        self.hint = QLabel("")
        self.hint.setObjectName("Muted")
        self.hint.setWordWrap(True)
        rl.addWidget(self.hint, 0)
        caveat = QLabel(ela.CAVEAT)
        caveat.setWordWrap(True)
        caveat.setStyleSheet(
            "background:#FBF6E9; border:1px solid #E0C97A; border-radius:4px; "
            "padding:6px 8px; color:#6E5A17; font-size:11px;")
        rl.addWidget(caveat, 0)
        split.addWidget(right)

        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 1)
        split.setSizes([300, 820])
        outer.addWidget(split, 1)

    def refresh(self):
        case = self.controller.case
        self.list.clear()
        self.orig_view.clear()
        self.heat_view.clear()
        self.hint.setText("")
        self._ela_cache.clear()
        if case is None:
            return
        self._rows = case.db.query_all(
            """
            SELECT c.id, c.file_name, c.file_path, a.assessment AS assessment
              FROM carved_evidence c
              LEFT JOIN image_analysis a ON a.carved_evidence_id = c.id
             ORDER BY c.id
            """, [])
        for r in self._rows:
            item = QListWidgetItem(r["file_name"])
            color = self._ASSESS_COLOR.get(r["assessment"])
            if color:
                item.setForeground(QBrush(QColor(color)))
            item.setData(Qt.ItemDataRole.UserRole, r["file_path"])
            self.list.addItem(item)
        if self.list.count():
            self.list.setCurrentRow(0)

    def _on_pick(self):
        items = self.list.selectedItems()
        if not items:
            return
        path = items[0].data(Qt.ItemDataRole.UserRole)
        self.orig_view.set_image(path)
        # Cached result -> instant on revisit; otherwise compute once (heatmap +
        # hint in a single pass) on the downscaled image.
        if path in self._ela_cache:
            png, hint_text = self._ela_cache[path]
        else:
            self.hint.setText("Computing ELA...")
            QApplication.processEvents()
            png, hint_text = ela.analyze(path)
            self._ela_cache[path] = (png, hint_text)
        if png:
            self.heat_view.set_image_bytes(png)
            self.hint.setText(hint_text)
        else:
            self.heat_view.clear()
            self.hint.setText("ELA could not be computed for this file "
                              "(unsupported or unreadable image).")


class TimelineView(QWidget):
    """Chronological case audit / investigation timeline (spec section 41)."""

    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 20, 20, 20)
        outer.setSpacing(8)
        outer.addWidget(h1("Investigation Timeline"))
        self.info = QLabel("")
        self.info.setObjectName("Muted")
        outer.addWidget(self.info)
        self.table = QTableWidget()
        outer.addWidget(self.table, 1)

    def refresh(self):
        case = self.controller.case
        if case is None:
            return
        rows = [[r["event_utc"], r["event_type"], r["actor"], r["description"]]
                for r in case.db.get_all_audit()]
        _fill_table(self.table, ["Time (UTC)", "Event", "Actor", "Description"], rows)
        self.table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch)
        self.info.setText(f"{len(rows)} case events (chronological). "
                          "All times in UTC (ISO 8601).")


# ===========================================================================
# CHAIN OF CUSTODY
# ===========================================================================
class ChainView(QWidget):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 20, 20, 20)
        outer.setSpacing(12)
        head = QHBoxLayout()
        head.addWidget(h1("Chain of Custody"))
        head.addStretch(1)
        self.verify_btn = QPushButton("Verify Chain")
        self.verify_btn.clicked.connect(self._verify)
        head.addWidget(self.verify_btn)
        outer.addLayout(head)
        self.result = QLabel("")
        self.result.setStyleSheet("font-size:14px; font-weight:600;")
        outer.addWidget(self.result)
        self.table = QTableWidget()
        outer.addWidget(self.table, 1)

    def refresh(self):
        case = self.controller.case
        if case is None:
            return
        rows = []
        for r in case.db.get_all_audit():
            rows.append([r["event_utc"], r["actor"], r["event_type"],
                         r["description"],
                         (r["previous_event_hash"] or "")[:16] + "…",
                         r["event_hash"][:16] + "…"])
        _fill_table(self.table, ["Timestamp (UTC)", "Actor", "Action",
                                 "Description", "Prev Hash", "Event Hash"], rows)
        self.result.setText("")

    def _verify(self):
        case = self.controller.case
        if case is None:
            return
        res = verify_audit_chain(case.db)
        if res.valid:
            self.result.setText(status_html("Audit Chain Valid", "ok"))
        else:
            self.result.setText(status_html(
                f"Audit Chain Integrity Failure — Event {res.broken_event_id}: "
                f"{res.message}", "danger"))


# ===========================================================================
# BOOKMARKS
# ===========================================================================
class BookmarksView(QWidget):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 20, 20, 20)
        outer.addWidget(h1("Bookmarked Evidence"))
        self.table = QTableWidget()
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        outer.addWidget(self.table, 1)
        btns = QHBoxLayout()
        self.remove_btn = QPushButton("Remove Bookmark")
        self.remove_btn.setObjectName("Danger")
        self.remove_btn.clicked.connect(self._remove)
        btns.addStretch(1)
        btns.addWidget(self.remove_btn)
        outer.addLayout(btns)
        self._rows = []

    def refresh(self):
        case = self.controller.case
        if case is None:
            return
        self._rows = case.db.get_all_bookmarks()
        rows = [[r["priority"], r["file_name"], r["file_format"], r["reason"] or "",
                 r["examiner_note"] or "", r["created_utc"]] for r in self._rows]
        _fill_table(self.table, ["Priority", "Filename", "Fmt", "Reason", "Note",
                                 "Created (UTC)"], rows)
        self.table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch)
        self.remove_btn.setEnabled(case is not None and not case.read_only)

    def _remove(self):
        case = self.controller.case
        idx = self.table.currentRow()
        if case is None or case.read_only or idx < 0 or idx >= len(self._rows):
            return
        row = self._rows[idx]
        case.db.remove_bookmark(row["carved_evidence_id"])
        case.audit.record("NOTE_ADDED",
                          f"Bookmark removed from {row['file_name']}.",
                          evidence_id=row["carved_evidence_id"])
        self.controller.refresh_all()


# ===========================================================================
# REPORT
# ===========================================================================
class ReportView(QWidget):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 20, 20, 20)
        outer.setSpacing(12)
        outer.addWidget(h1("Final Report"))

        checklist = Panel("Final Report Preview")
        items = ["Case Information", "Evidence Summary", "Hashes",
                 "Recovery Results", "Integrity & Provenance", "EXIF",
                 "JPEG Analysis", "Bookmarks", "Timeline", "Chain of Custody",
                 "Report Integrity Hash", "Examiner Declaration"]
        for it in items:
            checklist.add(QLabel(f"•  {it}"))
        outer.addWidget(checklist)

        self.info = QLabel("")
        self.info.setWordWrap(True)
        self.info.setObjectName("Muted")
        outer.addWidget(self.info)

        btns = QHBoxLayout()
        self.draft_btn = QPushButton("Generate Draft Report")
        self.draft_btn.setObjectName("Secondary")
        self.draft_btn.clicked.connect(self._draft)
        self.close_btn = QPushButton("Close & Generate Final Report")
        self.close_btn.setObjectName("Danger")
        self.close_btn.clicked.connect(self.controller.close_case_flow)
        btns.addWidget(self.draft_btn)
        btns.addWidget(self.close_btn)
        btns.addStretch(1)
        outer.addLayout(btns)
        outer.addStretch(1)

    def refresh(self):
        case = self.controller.case
        if case is None:
            return
        info = case.db.get_case_info()
        if case.read_only:
            self.draft_btn.setEnabled(True)
            self.close_btn.setEnabled(False)
            self.info.setText(
                f"This case is CLOSED.<br><b>Final report:</b> "
                f"{info['final_report_path']}<br>"
                f"<b>Report SHA-256:</b> {info['final_report_sha256']}")
        else:
            self.draft_btn.setEnabled(True)
            self.close_btn.setEnabled(True)
            self.info.setText("Generate a draft to preview, or close the case to "
                              "produce the finalised, hashed report.")

    def _draft(self):
        self.controller.generate_draft_flow()
