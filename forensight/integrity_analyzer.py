"""Combined, explainable image integrity & provenance assessment.

Transparent rule-based logic - NO AI/ML.  The score measures how much an image
has been *processed* and what *provenance* it carries; it is NOT a probability
of malicious intent.  Every finding is tagged as a FACT (the metadata declares
it) or an INDICATOR (derived, suggestive only), and the assessment carries an
explicit caution that indicators require examiner interpretation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import (config, exif_engine, jpeg_analyzer, file_type_analyzer,
               provenance_analyzer)

NO_SIGNIFICANT_ANOMALIES = "NO_SIGNIFICANT_ANOMALIES"
POTENTIAL_MANIPULATION = "POTENTIAL_MANIPULATION"
STRONG_INDICATORS = "STRONG_INDICATORS"
INSUFFICIENT_DATA = "INSUFFICIENT_DATA"

# Non-accusatory display labels (the stored constants above stay stable so
# database rows, tree filters and reports keep working).
LABELS = {
    NO_SIGNIFICANT_ANOMALIES: "No Anomalies",
    POTENTIAL_MANIPULATION: "Processing Detected",
    STRONG_INDICATORS: "Strong Indicators",
    INSUFFICIENT_DATA: "Insufficient Data",
}


def label(outcome: str) -> str:
    """Friendly display label for an outcome constant."""
    return LABELS.get(outcome, outcome)


CAUTION = ("This score reflects processing and provenance evidence, not proof "
           "of malicious manipulation. FACT findings are declared by the file's "
           "metadata; INDICATOR findings are suggestive only and require "
           "examiner interpretation.")

FACT = "Fact"
INDICATOR = "Indicator"


@dataclass
class AnalysisBundle:
    """All per-image analysis results collected together."""

    exif: Optional[exif_engine.ExifResult] = None
    jpeg: Optional[jpeg_analyzer.JpegResult] = None
    file_type: Optional[dict] = None
    thumbnail_state: Optional[str] = None
    provenance: Optional[provenance_analyzer.ProvenanceResult] = None
    # Recompression (JPEG re-save) evidence.
    recompressed: Optional[bool] = None
    recompression_quality: Optional[float] = None
    # Embedded-thumbnail vs full-image consistency.
    thumbnail_mismatch: Optional[bool] = None
    thumbnail_difference: Optional[float] = None


@dataclass
class Assessment:
    outcome: str
    indicators: list = field(default_factory=list)
    caution: str = CAUTION
    score: int = 0                     # Integrity & Provenance Score, 0-100

    def outcome_label(self) -> str:
        return label(self.outcome)

    def score_label(self) -> str:
        if self.outcome == INSUFFICIENT_DATA:
            return "N/A"
        return f"{self.score}/100"

    def as_text(self) -> str:
        lines = [f"Integrity & Provenance Score: {self.score_label()}",
                 f"Assessment: {self.outcome_label()}", "", "Findings:"]
        if self.indicators:
            lines += [f"- {i}" for i in self.indicators]
        else:
            lines.append("- None of the evaluated indicators were triggered.")
        lines += ["", "Caution:", self.caution]
        return "\n".join(lines)


def assess(bundle: AnalysisBundle) -> Assessment:
    """Combine findings into an explainable 0-100 score and outcome.

    Each triggered finding contributes a documented weight (see config.py) and a
    FACT/INDICATOR class; the total is capped at 100 to form the Integrity &
    Provenance Score, then mapped to a categorical outcome.  NO AI/ML.
    """
    indicators: list[str] = []
    score = 0
    data_points = 0
    software_scored = False   # editing-software fact must be counted only once

    def add(cls: str, text: str, weight: int):
        nonlocal score
        indicators.append(f"[{cls}] {text} [+{weight}].")
        score += weight

    # EXIF ----------------------------------------------------------------
    if bundle.exif is not None:
        if bundle.exif.has_exif:
            data_points += 1
        for note in bundle.exif.indicators:
            if "software" in note.lower():
                weight = config.SCORE_EXIF_SOFTWARE
                software_scored = True
            else:
                weight = config.SCORE_EXIF_TIMESTAMP
            add(INDICATOR, note, weight)

    # JPEG compression characteristics: INFORMATIONAL ONLY, not scored.  Quality
    # extremes (very high or very low) are not discriminative - professional
    # exports/scans are high quality and web/messaging images are low quality -
    # so scoring them false-flagged ordinary images.  The quality/summary is
    # reported for the examiner but does not drive the band.
    if bundle.jpeg is not None and bundle.jpeg.is_jpeg:
        data_points += 1
        if "no significant" not in bundle.jpeg.assessment.lower():
            indicators.append(
                f"[Fact] JPEG characteristics: {bundle.jpeg.assessment} "
                f"(informational, not scored) [+0].")

    # Recompression (JPEG re-save): INFORMATIONAL ONLY, deliberately unscored.
    # It reports that the image is a software-encoded copy (standard quantization
    # tables), not a camera original.  But that is true of almost every image in
    # circulation - downloads, screenshots, exports, and every messaging-app
    # transfer re-encode with standard tables - so its base rate is ~100% and it
    # has near-zero discriminative value.  Scoring it would flag nearly every
    # image "Processing Detected" and destroy the meaning of the triage bands, so
    # it is reported as context (weight 0) while the bands are driven only by
    # discriminative signals (provenance, file-type/thumbnail mismatch, EXIF
    # anomalies).
    if bundle.recompressed is not None:
        data_points += 1
        if bundle.recompressed:
            q = bundle.recompression_quality
            qtxt = f", est. quality {q:.0f}" if q is not None else ""
            indicators.append(
                f"[Fact] Software-processed copy - JPEG re-compression detected "
                f"(standard tables, not a camera original){qtxt}. Informational: "
                f"common to almost all processed images, not evidence of "
                f"manipulation [+0].")

    # Embedded-thumbnail vs full-image mismatch ---------------------------
    if bundle.thumbnail_mismatch is not None:
        data_points += 1
        if bundle.thumbnail_mismatch:
            d = bundle.thumbnail_difference
            dtxt = f" (difference {d:.0%})" if d is not None else ""
            add(INDICATOR,
                f"Embedded thumbnail differs from the full image{dtxt} - "
                f"suggests later editing", config.SCORE_THUMBNAIL_MISMATCH)

    # File-type mismatch --------------------------------------------------
    if bundle.file_type is not None:
        data_points += 1
        if bundle.file_type.get("result") == file_type_analyzer.MISMATCH:
            add(INDICATOR,
                f"File-type mismatch: extension {bundle.file_type['extension']} "
                f"but detected {bundle.file_type['detected_type']}",
                config.SCORE_FILETYPE_MISMATCH)

    # Content provenance (C2PA / AI-generation / editing-app metadata) ----
    if bundle.provenance is not None and bundle.provenance.detected:
        data_points += 1
        prov = bundle.provenance
        # Cryptographic C2PA verdicts first - these are proven by public-key
        # cryptography, so they are FACTS with decisive weight.
        if prov.asset_tampered:
            who = f" ({prov.signer})" if prov.signer else ""
            add(FACT,
                f"C2PA signature is valid but the image bytes no longer match the "
                f"signed hash{who} - the image was EDITED after the credential "
                f"was created (post-signing tampering)",
                config.SCORE_C2PA_TAMPERED)
        elif prov.trust == provenance_analyzer.TRUST_INVALID:
            add(FACT,
                "C2PA signature is cryptographically INVALID - the provenance "
                "manifest was forged or corrupted",
                config.SCORE_C2PA_INVALID)

        if bundle.provenance.ai_generated:
            who = (f" ({bundle.provenance.generator})"
                   if bundle.provenance.generator else "")
            add(FACT,
                f"Content-provenance metadata declares AI-generated / edited "
                f"media{who} via {bundle.provenance.standard}",
                config.SCORE_AI_PROVENANCE)
        elif bundle.provenance.editor:
            # The same editing-software fact may already be scored from the EXIF
            # Software tag; don't double-count it (that would wrongly push a
            # single "edited" finding up to Strong Indicators).
            if software_scored:
                indicators.append(
                    f"[Fact] Metadata identifies editing software "
                    f"({bundle.provenance.editor}) [+0, already counted].")
            else:
                add(FACT,
                    f"Metadata identifies editing software "
                    f"({bundle.provenance.editor})", config.SCORE_EXIF_SOFTWARE)
                software_scored = True
        else:
            indicators.append(
                "[Fact] Content-provenance metadata (C2PA Content Credentials) "
                "is present; no generative-source declaration found [+0].")

    score = min(score, 100)

    # Outcome -------------------------------------------------------------
    if data_points == 0:
        return Assessment(INSUFFICIENT_DATA, indicators, score=0)
    if score >= config.SCORE_BAND_STRONG:
        outcome = STRONG_INDICATORS
    elif score >= config.SCORE_BAND_POTENTIAL:
        outcome = POTENTIAL_MANIPULATION
    else:
        outcome = NO_SIGNIFICANT_ANOMALIES
    return Assessment(outcome, indicators, score=score)
