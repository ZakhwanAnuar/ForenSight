"""Aggregate case statistics used by the dashboard and the report."""
from __future__ import annotations

from dataclasses import dataclass

from .case_manager import Case
from .integrity_analyzer import (NO_SIGNIFICANT_ANOMALIES, POTENTIAL_MANIPULATION,
                                 STRONG_INDICATORS)


@dataclass
class CaseStats:
    evidence_sources: int = 0
    files_recovered: int = 0
    valid: int = 0
    suspicious: int = 0
    images_analysed: int = 0
    potential_anomalies: int = 0
    bookmarked: int = 0


def gather_stats(case: Case) -> CaseStats:
    db = case.db
    stats = CaseStats()
    stats.evidence_sources = db.count("SELECT COUNT(*) FROM evidence_sources")
    stats.files_recovered = db.count("SELECT COUNT(*) FROM carved_evidence")
    stats.valid = db.count("SELECT COUNT(*) FROM carved_evidence WHERE is_valid = 1")
    stats.suspicious = db.count("SELECT COUNT(*) FROM carved_evidence WHERE is_suspicious = 1")
    stats.images_analysed = db.count("SELECT COUNT(*) FROM image_analysis")
    stats.potential_anomalies = db.count(
        "SELECT COUNT(*) FROM image_analysis WHERE assessment IN (?, ?)",
        (POTENTIAL_MANIPULATION, STRONG_INDICATORS),
    )
    stats.bookmarked = db.count("SELECT COUNT(*) FROM bookmarks")
    return stats
