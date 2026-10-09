"""PDF forensic report generation with ReportLab (spec sections 48-53)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas as _canvas
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, Image as RLImage, PageBreak,
                                KeepTogether, CondPageBreak)

from . import config
from .audit_manager import verify_audit_chain
from .case_manager import Case
from .hash_utils import sha256_file
from .stats import gather_stats
from .utils import human_size, utc_now_iso

_ACCENT = colors.HexColor("#1f3a5f")
_LIGHT = colors.HexColor("#e8edf3")
_FOOTER_GREY = colors.HexColor("#6a7788")
_FOOTER_LINE = colors.HexColor("#c9d3df")


def _numbered_canvas(footer_left: str):
    """Factory for a canvas that prints a consistent 'Page X of Y' footer.

    The total page count is only known at save time, so page states are
    buffered and the footer drawn on every page during save.
    """
    class NumberedCanvas(_canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._pages = []

        def showPage(self):
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._pages)
            for state in self._pages:
                self.__dict__.update(state)
                self._footer(total)
                super().showPage()
            super().save()

        def _footer(self, total):
            self.setStrokeColor(_FOOTER_LINE)
            self.setLineWidth(0.5)
            self.line(1.6 * cm, 1.2 * cm, A4[0] - 1.6 * cm, 1.2 * cm)
            self.setFont("Helvetica", 7)
            self.setFillColor(_FOOTER_GREY)
            self.drawString(1.6 * cm, 0.85 * cm, footer_left)
            self.drawRightString(A4[0] - 1.6 * cm, 0.85 * cm,
                                 f"Page {self._pageNumber} of {total}")
    return NumberedCanvas


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("CoverTitle", parent=styles["Title"],
                              fontSize=30, textColor=_ACCENT, spaceAfter=10,
                              alignment=TA_CENTER))
    styles.add(ParagraphStyle("CoverSub", parent=styles["Heading2"],
                              alignment=TA_CENTER, textColor=colors.HexColor("#3b4a5a"),
                              spaceAfter=6))
    styles.add(ParagraphStyle("CoverCaution", parent=styles["BodyText"], fontSize=8.5,
                              alignment=TA_CENTER, textColor=colors.HexColor("#7a3b00"),
                              leading=12))
    # keepWithNext keeps a section heading glued to the content that follows it,
    # so a header is never left orphaned at the bottom of a page.
    styles.add(ParagraphStyle("SectionH", parent=styles["Heading2"],
                              textColor=_ACCENT, spaceBefore=14, spaceAfter=6,
                              keepWithNext=1))
    styles.add(ParagraphStyle("Mono", parent=styles["BodyText"],
                              fontName="Courier", fontSize=8, leading=10))
    # Character-wrapping monospace for full SHA-256 hashes in table cells: a hash
    # has no spaces, so wordWrap='CJK' is needed to break it across lines.
    styles.add(ParagraphStyle("MonoWrap", parent=styles["BodyText"],
                              fontName="Courier", fontSize=6, leading=7.5,
                              wordWrap="CJK"))
    styles.add(ParagraphStyle("Small", parent=styles["BodyText"], fontSize=8,
                              leading=10))
    styles.add(ParagraphStyle("SmallKeep", parent=styles["BodyText"], fontSize=8,
                              leading=10, keepWithNext=1))
    styles.add(ParagraphStyle("Caution", parent=styles["BodyText"], fontSize=8,
                              textColor=colors.HexColor("#7a3b00"), leading=10))
    # Indented list item with a hanging indent so the (i)/(ii)/(iii) markers
    # line up and wrapped text aligns under the first word.
    styles.add(ParagraphStyle("ListItem", parent=styles["BodyText"], fontSize=8,
                              leading=11, leftIndent=34, firstLineIndent=-22,
                              spaceBefore=2, spaceAfter=2))
    # Same 8pt body size as the rest of the report (only the line spacing is
    # generous, to leave physical room to sign) - keeps the last page consistent.
    styles.add(ParagraphStyle("SigLine", parent=styles["BodyText"], fontSize=8,
                              leading=26))
    return styles


def _na(value) -> str:
    """Render empty / None / placeholder values as 'N/A' for report cells."""
    s = "" if value is None else str(value).strip()
    if not s or s in ("Not Available", "None", "-"):
        return "N/A"
    return s


def _kv_table(rows, styles, col0=5 * cm, col1=11 * cm):
    data = [[Paragraph(f"<b>{k}</b>", styles["Small"]), Paragraph(_na(v), styles["Small"])]
            for k, v in rows]
    table = Table(data, colWidths=[col0, col1])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), _LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d3df")),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return table


def generate_report(case: Case, output_path: str | Path, draft: bool = False,
                    closed_utc: str | None = None) -> str:
    """Generate the forensic PDF report and return its path.

    Raises on failure so the caller can keep a case OPEN (spec section 13).

    ``closed_utc`` lets the final-report caller show the closure timestamp that
    is about to be committed, without writing to the database first (so a report
    failure still leaves the case OPEN).  When given, the report also shows the
    case status as CLOSED.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    styles = _styles()
    story: list = []
    db = case.db
    info = db.get_case_info()
    stats = gather_stats(case)
    eff_closed = closed_utc or info["closed_utc"]
    eff_status = config.CASE_STATUS_CLOSED if eff_closed else info["case_status"]

    # -- 1. Cover (centred, both axes) -----------------------------------
    story.append(Spacer(1, 6.5 * cm))
    story.append(Paragraph(config.APP_NAME, styles["CoverTitle"]))
    story.append(Paragraph("Digital Forensic Investigation Report", styles["CoverSub"]))
    if draft:
        story.append(Paragraph("<b>*** DRAFT ***</b>", styles["CoverSub"]))
    story.append(Spacer(1, 1.2 * cm))
    cover_tbl = _kv_table([
        ("Case Name", info["case_name"]),
        ("Case ID", info["case_id"]),
        ("Examiner", info["examiner_name"]),
        ("Organization", info["organization"] or "Not Available"),
        ("Report Generated (UTC)", utc_now_iso()),
        ("Case Status", eff_status),
    ], styles, col0=4.5 * cm, col1=7 * cm)
    cover_tbl.hAlign = "CENTER"          # centre the info table horizontally
    story.append(cover_tbl)
    story.append(Spacer(1, 1.2 * cm))
    story.append(Paragraph(
        "This report documents processing performed by ForenSight, a forensic "
        "image-recovery and provenance-analysis tool. ForenSight is not a "
        "certified forensic suite. Indicators reported here do not constitute "
        "legal determination of authenticity.", styles["CoverCaution"]))
    story.append(PageBreak())

    # -- 2/3. Case & examiner info ---------------------------------------
    story.append(Paragraph("1. Case &amp; Examiner Information", styles["SectionH"]))
    story.append(_kv_table([
        ("Case Name", info["case_name"]),
        ("Case ID", info["case_id"]),
        ("Examiner Name", info["examiner_name"]),
        ("Examiner ID", info["examiner_id"]),
        ("Organization", info["organization"] or "Not Available"),
        ("Created (UTC)", info["created_utc"]),
        ("Closed (UTC)", eff_closed or "Not closed"),
        ("Case Root", info["case_root_path"]),
    ], styles))

    # -- 4. Evidence sources (complete SHA-256) --------------------------
    story.append(Paragraph("2. Evidence Source Summary", styles["SectionH"]))
    sources = db.get_evidence_sources()
    if not sources:
        story.append(Paragraph("No evidence sources imported.", styles["Small"]))
    for row in sources:
        block = [_kv_table([
            ("Evidence ID", row["evidence_id"]),
            ("Name", row["evidence_name"]),
            ("Type", row["source_type"]),
            ("Size", f"{human_size(row['file_size_bytes'])} "
                     f"({row['file_size_bytes']:,} bytes)"),
            ("Integrity", row["integrity_status"]),
        ], styles, col0=4 * cm, col1=12 * cm)]
        block.append(Spacer(1, 0.1 * cm))
        block.append(Paragraph("<b>SHA-256 (complete):</b>", styles["Small"]))
        block.append(Paragraph(row["sha256_hash"], styles["Mono"]))
        block.append(Spacer(1, 0.25 * cm))
        story.append(KeepTogether(block))

    # -- 5. Recovery statistics ------------------------------------------
    story.append(Paragraph("3. Carving Recovery Statistics", styles["SectionH"]))
    story.append(_kv_table([
        ("Carved candidates (total)", stats.files_recovered),
        ("Genuine (validated) recoveries", stats.valid),
        ("Quarantined / unverified candidates", stats.suspicious),
        ("Images Analysed", stats.images_analysed),
        ("Potential Integrity Anomalies", stats.potential_anomalies),
        ("Bookmarked", stats.bookmarked),
    ], styles))
    story.append(Paragraph(
        "Only validated recoveries are treated as recovered evidence; carved "
        "candidates that failed validation are listed separately as quarantined "
        "and are not counted as recovered files. Recovered files were obtained "
        "from raw/unallocated image space by signature-based carving.",
        styles["Small"]))

    # -- 6. Evidence table (validated recoveries only) --------------------
    story.append(Paragraph("4. Recovered Evidence (Validated)", styles["SectionH"]))
    validated = db.query_all(
        "SELECT * FROM carved_evidence WHERE is_valid = 1 ORDER BY id")
    ev_rows = [["ID", "Filename", "Fmt", "Recovery", "Offset", "Size"]]
    for row in validated:
        alloc = row["allocation_status"] if "allocation_status" in row.keys() else "Unknown"
        ev_rows.append([
            str(row["id"]), row["file_name"], row["file_format"], alloc,
            row["source_offset_hex"], human_size(row["file_size_bytes"]),
        ])
    if len(ev_rows) == 1:
        ev_rows.append(["-", "No validated recoveries", "-", "-", "-", "-"])
    story.append(_table(ev_rows, styles,
                        [1.0 * cm, 5.2 * cm, 1.3 * cm, 2.4 * cm, 2.8 * cm, 2.1 * cm]))
    # Complete SHA-256 for every validated recovery (formal reports need the
    # full hash, not a truncated one).
    if validated:
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph("<b>Complete SHA-256 values:</b>", styles["Small"]))
        for row in validated:
            story.append(Paragraph(
                f"ID {row['id']} &mdash; {row['file_name']}", styles["Small"]))
            story.append(Paragraph(row["sha256_hash"], styles["Mono"]))

    # -- 7. Suspicious evidence ------------------------------------------
    story.append(Paragraph("5. Suspicious / Quarantined Evidence", styles["SectionH"]))
    sus_rows = [["ID", "Filename", "Reason"]]
    for row in db.query_all(
        "SELECT id, file_name, validation_message FROM carved_evidence WHERE is_suspicious = 1"
    ):
        sus_rows.append([str(row["id"]), row["file_name"], row["validation_message"] or ""])
    if len(sus_rows) == 1:
        sus_rows.append(["-", "None", "-"])
    story.append(_table(sus_rows, styles, [1.2 * cm, 5 * cm, 9.6 * cm]))

    # -- 8. Image integrity analysis (with visuals) ----------------------
    story.append(PageBreak())
    story.append(Paragraph("6. Image Integrity Analysis", styles["SectionH"]))
    _append_analysis_visuals(story, case, styles)

    # -- 9. Bookmarks -----------------------------------------------------
    story.append(Paragraph("7. Bookmarked Evidence", styles["SectionH"]))
    bm_rows = [["Priority", "Filename", "Reason", "Note"]]
    for row in db.get_all_bookmarks():
        bm_rows.append([row["priority"], row["file_name"], row["reason"] or "",
                        row["examiner_note"] or ""])
    if len(bm_rows) == 1:
        bm_rows.append(["-", "None", "-", "-"])
    story.append(_table(bm_rows, styles, [2 * cm, 4 * cm, 4.8 * cm, 5 * cm]))

    # -- 10. Timeline -----------------------------------------------------
    story.append(Paragraph("8. Investigation Timeline", styles["SectionH"]))
    story.append(Paragraph(
        "All timestamps in this report are recorded and reported in UTC "
        "(ISO 8601), per forensic best practice, to avoid timezone and "
        "daylight-saving ambiguity.", styles["Small"]))
    tl_rows = [["Time (UTC)", "Event", "Description"]]
    for row in db.get_all_audit():
        tl_rows.append([row["event_utc"], row["event_type"], row["description"]])
    story.append(_table(tl_rows, styles, [3.6 * cm, 3.8 * cm, 8.4 * cm], small=True))

    # -- 11. Chain of custody --------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("9. Chain of Custody (Hash-Linked Audit)", styles["SectionH"]))
    chain = verify_audit_chain(db)
    verdict = "VALID" if chain.valid else f"INTEGRITY FAILURE (event {chain.broken_event_id})"
    story.append(Paragraph(f"<b>Audit chain verification: {verdict}</b>", styles["Small"]))
    story.append(Paragraph(
        "Full SHA-256 hashes are shown so the chain can be independently "
        "verified: each event's hash is computed over its content and the "
        "previous event's hash, linking the log tamper-evidently.", styles["Small"]))
    # Full previous + event hashes (not truncated) so a third party can verify
    # the chain from the report itself.  Actor is omitted (not yet captured;
    # always 'Unknown') to make room for the complete hashes.
    coc_header = ["Time (UTC)", "Event", "Previous Hash", "Event Hash"]
    coc_data = [[Paragraph(f"<b>{h}</b>", styles["Small"]) for h in coc_header]]
    for row in db.get_all_audit():
        coc_data.append([
            Paragraph(row["event_utc"], styles["Small"]),
            Paragraph(row["event_type"], styles["Small"]),
            Paragraph(row["previous_event_hash"] or "(genesis - no previous)",
                      styles["MonoWrap"]),
            Paragraph(row["event_hash"], styles["MonoWrap"]),
        ])
    coc_tbl = Table(coc_data, colWidths=[3.0 * cm, 3.1 * cm, 5.15 * cm, 5.15 * cm],
                    repeatRows=1)
    coc_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d3df")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _LIGHT]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.append(coc_tbl)

    # -- 10. Report integrity hash ---------------------------------------
    story.append(Paragraph("10. Report Integrity", styles["SectionH"]))
    sidecar_name = output_path.stem + "_SHA256.txt"
    story.append(Paragraph(
        "The integrity of this report is protected by a cryptographic hash. As a "
        "file cannot mathematically contain a digest of its own finalised state, "
        "the SHA-256 digest of this report is recorded externally in three "
        "independent locations:", styles["Small"]))
    for marker, text in (
        ("(i)", f"a companion verification file, <b>{sidecar_name}</b>, stored "
                "alongside this document;"),
        ("(ii)", "the case database; and"),
        ("(iii)", "the hash-linked chain-of-custody audit log, which is sealed "
                  "at the time of case closure."),
    ):
        story.append(Paragraph(
            f'<font face="Helvetica"><b>{marker}</b></font>&nbsp;&nbsp;{text}',
            styles["ListItem"]))
    story.append(Spacer(1, 0.15 * cm))
    story.append(Paragraph(
        "To confirm that this report has not been altered after issuance, the "
        "examiner may compute the SHA-256 digest of this document and verify "
        "that it matches the value recorded in the companion verification file.",
        styles["Small"]))
    if info["final_report_sha256"]:
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph("<b>Finalised Report SHA-256 (complete):</b>",
                               styles["Small"]))
        story.append(Paragraph(info["final_report_sha256"], styles["Mono"]))

    # -- 11. Examiner declaration (LAST section: the sign-off closes the
    #        report, so nothing appears after the signature) --------------
    decl = [
        Paragraph("11. Examiner Declaration", styles["SectionH"]),
        Paragraph(
            "I declare that this report documents the automated and manual "
            "processing performed using ForenSight on the evidence described "
            "above. This document does not constitute a legal certification of "
            "authenticity.", styles["Small"]),
        Spacer(1, 1.2 * cm),
        Paragraph(f"Examiner Name: {info['examiner_name']}", styles["SigLine"]),
        Paragraph(f"Examiner ID: {info['examiner_id']}", styles["SigLine"]),
        Spacer(1, 1.4 * cm),
        Paragraph("Signature: ______________________________________________",
                  styles["SigLine"]),
        Spacer(1, 1.0 * cm),
        Paragraph("Date: __________________________________________________",
                  styles["SigLine"]),
    ]
    story.append(KeepTogether(decl))

    doc = SimpleDocTemplate(str(output_path), pagesize=A4,
                            topMargin=1.6 * cm, bottomMargin=1.9 * cm,
                            leftMargin=1.6 * cm, rightMargin=1.6 * cm,
                            title=f"{info['case_id']} Forensic Report")
    footer_left = (f"{config.APP_NAME}  |  Case {info['case_id']}  |  "
                   f"{info['case_name']}")
    doc.build(story, canvasmaker=_numbered_canvas(footer_left))

    # Write the companion SHA-256 file so the report's own complete hash is
    # verifiable right next to it (a file cannot embed its own hash).
    try:
        digest = sha256_file(output_path)
        sidecar = output_path.with_name(sidecar_name)
        sidecar.write_text(
            f"SHA-256 ({output_path.name}) = {digest}\n", encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass
    return str(output_path)


def _table(rows, styles, col_widths, small=False):
    style_name = "Small" if not small else "Small"
    # Header row (index 0) kept verbatim; body cells show N/A when empty.
    data = [[Paragraph(str(c) if ri == 0 else _na(c), styles[style_name])
             for c in row] for ri, row in enumerate(rows)]
    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d3df")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _LIGHT]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return table


def _append_analysis_visuals(story, case: Case, styles):
    db = case.db
    analysed = db.query_all(
        """
        SELECT c.id, c.file_name, c.file_path, c.file_format, c.is_valid,
               c.sha256_hash, c.source_offset_hex, c.allocation_status,
               a.jpeg_quality_estimate,
               a.jpeg_quantization_summary, a.assessment, a.manipulation_score,
               a.thumbnail_path, a.provenance
          FROM carved_evidence c
          JOIN image_analysis a ON a.carved_evidence_id = c.id
         ORDER BY c.id
        """
    )
    if not analysed:
        story.append(Paragraph("No images have been analysed.", styles["Small"]))
        return

    for row in analysed:
        story.append(Spacer(1, 0.4 * cm))
        story.append(KeepTogether(_analysis_card(row, db, styles)))


_SCORE_RED = colors.HexColor("#b02a2a")
_SCORE_AMBER = colors.HexColor("#b26a00")
_SCORE_GREEN = colors.HexColor("#1f7a3d")


def _analysis_card(row, db, styles):
    """A bordered card: header + score + side-by-side images + stats grid."""
    score = row["manipulation_score"]
    if score is None:
        score_txt, score_hex = "N/A", "#6a7788"
    else:
        score_txt = f"{score}/100"
        score_hex = ("#b02a2a" if score >= 40 else
                     ("#b26a00" if score >= 1 else "#1f7a3d"))
    score_col = colors.HexColor(score_hex)

    # Header band: filename (left) + colored score (right).
    header = Table([[
        Paragraph(f"<b>{row['file_name']}</b> &nbsp;({row['file_format']})",
                  styles["Small"]),
        Paragraph(f'<b>Score:</b> <font color="{score_hex}"><b>{score_txt}'
                  f'</b></font> &nbsp;|&nbsp; {row["assessment"]}', styles["Small"]),
    ]], colWidths=[7 * cm, 9.4 * cm])
    header.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _LIGHT),
        ("LINEBELOW", (0, 0), (-1, -1), 2, score_col),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ]))
    content = [header, Spacer(1, 0.25 * cm)]

    # Recovered image, captioned. Centre it with a full-width wrapper table whose
    # cell ALIGN=CENTER reliably centres the image across the whole card (a
    # flowable's own hAlign is not honoured inside the card's cell).
    content.append(Paragraph("<b>Recovered Image</b>", styles["Small"]))
    content.append(Spacer(1, 0.1 * cm))
    img = _safe_image(row["file_path"], 7.0 * cm)
    img_cell = img if img is not None else Paragraph("(not available)", styles["Small"])
    img_block = Table([[img_cell]], colWidths=[16.0 * cm])
    img_block.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    content.append(img_block)
    content.append(Spacer(1, 0.25 * cm))

    exif = db.get_exif(row["id"])
    provenance = row["provenance"] if "provenance" in row.keys() else None
    content.append(_kv_table([
        ("Content Provenance", provenance or "None detected"),
        ("JPEG Quality", row["jpeg_quality_estimate"] if row["jpeg_quality_estimate"]
            is not None else "N/A"),
        ("JPEG Summary", row["jpeg_quantization_summary"] or "N/A"),
        ("EXIF Software", (exif["software"] if exif else "Not Available")),
        ("Thumbnail", "Recovered" if row["thumbnail_path"] else "None"),
        ("Recovery / Allocation",
         row["allocation_status"] if "allocation_status" in row.keys() else "Unknown"),
        ("Source Offset", row["source_offset_hex"]),
    ], styles, col0=4 * cm, col1=11.6 * cm))
    # Complete SHA-256 of the analysed image — every artefact in a forensic
    # report must be individually traceable to its hash.
    content.append(Spacer(1, 0.12 * cm))
    content.append(Paragraph(
        f"<b>SHA-256:</b> <font face='Courier' size='7.5'>{row['sha256_hash']}</font>",
        styles["Small"]))
    content.append(Paragraph(
        "<i>Indicators above do not independently prove image manipulation.</i>",
        styles["Caution"]))

    # Wrap the whole thing in a bordered card.
    card = Table([[content]], colWidths=[16.8 * cm])
    card.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#c9d3df")),
        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return card


def _safe_image(path: Optional[str], max_w: float):
    """Return a ReportLab image scaled to ``max_w`` or None if it cannot load."""
    if not path or not Path(path).exists():
        return None
    try:
        from PIL import Image as PILImage
        with PILImage.open(path) as im:
            w, h = im.size
        if w <= 0 or h <= 0:
            return None
        ratio = h / w
        return RLImage(path, width=max_w, height=max_w * ratio)
    except Exception:  # noqa: BLE001
        return None


def hash_report(report_path: str | Path) -> str:
    """SHA-256 of the finalised report (spec section 53)."""
    return sha256_file(report_path)
