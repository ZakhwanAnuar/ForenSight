"""Central configuration: constants, carving signatures and thresholds.

Keeping these values in one documented place satisfies the requirement that
all thresholds be configurable and documented (spec sections 23, 30, 58).
"""
from __future__ import annotations

APP_NAME = "ForenSight"
APP_TAGLINE = "Digital Forensic Investigation Platform"
SCHEMA_VERSION = 1

# ---------------------------------------------------------------------------
# Case workspace layout
# ---------------------------------------------------------------------------
CASE_DATA_DIR = "CaseData"
DB_FILENAME = "forensight_case.db"
DB_FILENAME_LEGACY = "crime_lens_case.db"   # older cases; opened for compatibility
CONFIG_FILENAME = "case_config.json"

WORKSPACE_DIRS = [
    "CaseData",
    "Evidence/Original",
    "Evidence/Carved_JPEGs",
    "Evidence/Carved_PNGs",
    "Evidence/Carved_BMPs",
    "Evidence/Carved_GIFs",
    "Evidence/Suspicious",
    "Analysis/EXIF_Dumps",
    "Analysis/JPEG_Analysis",
    "Analysis/Thumbnails",
    "Reports/Drafts",
    "Reports/Final",
    "Logs",
]

# Where carved files of each format are written (relative to case root).
CARVED_DIRS = {
    "JPEG": "Evidence/Carved_JPEGs",
    "PNG": "Evidence/Carved_PNGs",
    "BMP": "Evidence/Carved_BMPs",
    "GIF": "Evidence/Carved_GIFs",
}
SUSPICIOUS_DIR = "Evidence/Suspicious"

# ---------------------------------------------------------------------------
# Carving parameters
# ---------------------------------------------------------------------------
CHUNK_SIZE = 1024 * 1024          # 1 MiB chunked reads (spec section 21)
OVERLAP_SIZE = 32                 # bytes retained between chunks for split signatures
MAX_CARVE_BYTES = 30 * 1024 * 1024  # ceiling for a single carved file (30 MiB)
SUSPICIOUS_SIZE_THRESHOLD = 5 * 1024  # 5 KB (spec section 23)

# File signatures (header / footer byte sequences).
JPEG_HEADER = b"\xFF\xD8\xFF"
JPEG_FOOTER = b"\xFF\xD9"
PNG_HEADER = b"\x89PNG\r\n\x1a\n"
PNG_IEND = b"IEND\xAE\x42\x60\x82"
BMP_HEADER = b"BM"
GIF_HEADERS = (b"GIF87a", b"GIF89a")
GIF_TRAILER = b"\x00\x3B"

# ---------------------------------------------------------------------------
# Recompression / structural analysis thresholds (documented, not proof).
# ---------------------------------------------------------------------------
# A JPEG whose estimated quality sits below this is very likely a re-saved
# (re-compressed) image rather than a camera original at capture quality.
RECOMPRESSION_QUALITY_CEILING = 90
# Normalised difference (0-1) above which an embedded EXIF thumbnail is treated
# as inconsistent with the full image (evidence of later editing).
THUMBNAIL_MISMATCH_THRESHOLD = 0.18

# ---------------------------------------------------------------------------
# Integrity & Provenance Score (0-100, higher = more processing/provenance).
# The score measures how much the image has been PROCESSED and what PROVENANCE
# it carries - not a probability of malicious intent.  Transparent, documented,
# tunable weights; the assessment sums triggered indicators and caps at 100.
# ---------------------------------------------------------------------------
SCORE_EXIF_SOFTWARE = 20        # image-processing / editing software in metadata
SCORE_EXIF_TIMESTAMP = 10       # timestamp inconsistency
# JPEG quality (very high or very low) is INFORMATIONAL ONLY (weight 0): quality
# alone is not discriminative - professional exports/scans are high quality and
# web/messaging images are low quality - so scoring it false-flagged ordinary
# images.  Reported as context; see integrity_analyzer.assess().
SCORE_JPEG_ANOMALY = 0
# JPEG re-compression is INFORMATIONAL ONLY (weight 0): it has a ~100% base rate
# on processed images, so scoring it would flag almost everything and destroy the
# triage bands.  See integrity_analyzer.assess().  (Constant kept at 0 so any
# external reference stays valid.)
SCORE_RECOMPRESSION = 0
SCORE_THUMBNAIL_MISMATCH = 30   # embedded thumbnail differs from full image
SCORE_FILETYPE_MISMATCH = 40    # extension does not match detected content
SCORE_AI_PROVENANCE = 60        # metadata declares AI-generated/edited (C2PA)
# C2PA cryptographic-verification outcomes (see c2pa_verifier).  These are FACTS
# proven by public-key cryptography, not heuristics, so they carry decisive
# weight: a valid signature over bytes that no longer match, or a signature that
# fails outright, is strong evidence of manipulation/forgery.
SCORE_C2PA_TAMPERED = 60        # valid signature but asset edited after signing
SCORE_C2PA_INVALID = 40         # C2PA signature cryptographically failed

# Band thresholds applied to the 0-100 score.  "Processing Detected" reports that
# the image is a SOFTWARE-PROCESSED copy (not a camera original) - a true, high-
# recall observation, deliberately NON-accusatory: it does not claim the
# processing was a malicious edit, only that the image was processed.
SCORE_BAND_POTENTIAL = 1        # >= this (and < strong) -> PROCESSING_DETECTED
SCORE_BAND_STRONG = 40          # >= this -> STRONG_INDICATORS

# ---------------------------------------------------------------------------
# Assessment / audit
# ---------------------------------------------------------------------------
GENESIS_HASH = "GENESIS"

# Event type vocabulary (spec section 16).
EVENT_TYPES = [
    "CASE_CREATED", "CASE_OPENED", "EVIDENCE_IMPORTED", "EVIDENCE_HASHED",
    "EVIDENCE_INTEGRITY_VERIFIED", "CARVING_STARTED", "FILE_RECOVERED",
    "FILE_VALIDATED", "EXIF_EXTRACTED", "JPEG_ANALYSIS_COMPLETED",
    "AI_PROVENANCE_DETECTED", "BOOKMARK_CREATED", "NOTE_ADDED",
    "REPORT_GENERATED", "CASE_CLOSED",
]

CASE_STATUS_OPEN = "OPEN"
CASE_STATUS_CLOSED = "CLOSED"
