"""Orchestrates per-image forensic analysis and persists the results.

Runs EXIF, JPEG, recompression, thumbnail-consistency, file-type and provenance
engines on one carved file, computes the combined integrity & provenance
assessment and writes everything to the database and audit log.  Runnable off the
GUI thread.  Analysis is entirely rule-based and explainable - no AI/ML.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import exif_engine, jpeg_analyzer, thumbnail_engine, recompression_analyzer
from . import file_type_analyzer, integrity_analyzer, provenance_analyzer
from .case_manager import Case
from .integrity_analyzer import AnalysisBundle
from .logging_config import get_logger
from .utils import utc_now_iso


@dataclass
class ImageAnalysis:
    carved_id: int
    bundle: AnalysisBundle
    assessment: integrity_analyzer.Assessment


def analyze_carved_image(case: Case, carved_id: int) -> ImageAnalysis:
    """Run every image-forensics engine on one carved image and persist it."""
    logger = get_logger()
    row = case.db.get_carved(carved_id)
    if row is None:
        raise ValueError(f"Carved evidence id {carved_id} not found.")

    path = Path(row["file_path"])
    fmt = row["file_format"]
    bundle = AnalysisBundle()

    # -- Decodability guard ----------------------------------------------
    # An image that cannot be decoded must NOT be reported as "no significant
    # anomalies" (examiner finding: a 30 MB garbage PNG was reported clean).
    # Record INSUFFICIENT_DATA and stop before running misleading analysis.
    from PIL import Image
    try:
        with Image.open(path) as _probe:
            _probe.verify()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Analysis skipped for %s (undecodable): %s",
                       row["file_name"], exc)
        assessment = integrity_analyzer.Assessment(
            integrity_analyzer.INSUFFICIENT_DATA,
            ["Image could not be decoded; forensic analysis not applicable."])
        case.db.upsert_image_analysis({
            "carved_evidence_id": carved_id,
            "jpeg_quality_estimate": None, "jpeg_quantization_summary": None,
            "file_type_match": 0, "thumbnail_path": None,
            "assessment": assessment.outcome,
            "manipulation_score": assessment.score, "provenance": None,
            "analyzed_utc": utc_now_iso(),
        })
        return ImageAnalysis(carved_id, bundle, assessment)

    # -- EXIF -------------------------------------------------------------
    exif = exif_engine.extract_exif(path)
    bundle.exif = exif
    case.db.upsert_exif(
        {
            "carved_evidence_id": carved_id,
            "camera_make": exif.make,
            "camera_model": exif.model,
            "capture_datetime": exif.datetime_original,
            "software": exif.software,
            "gps_latitude": exif.gps_latitude,
            "gps_longitude": exif.gps_longitude,
            "orientation": exif.orientation,
            "metadata_json": exif_engine.exif_to_json(exif),
            "extracted_utc": utc_now_iso(),
        }
    )
    case.audit.record("EXIF_EXTRACTED", f"EXIF extracted for {row['file_name']}.",
                      evidence_id=carved_id)

    # -- JPEG + recompression --------------------------------------------
    jpeg_result = None
    if fmt == "JPEG":
        jpeg_result = jpeg_analyzer.analyze_jpeg(path)
        bundle.jpeg = jpeg_result
        recomp = recompression_analyzer.analyze(jpeg_result)
        bundle.recompressed = recomp.recompressed if recomp.is_jpeg else None
        bundle.recompression_quality = recomp.quality
        case.audit.record("JPEG_ANALYSIS_COMPLETED",
                          f"JPEG analysis for {row['file_name']}.", evidence_id=carved_id)

    # -- file-type --------------------------------------------------------
    ftype = file_type_analyzer.analyze_file_type(path)
    bundle.file_type = ftype

    # -- thumbnail recovery + consistency --------------------------------
    thumb = thumbnail_engine.recover_thumbnail(path, case.path("Analysis/Thumbnails"))
    bundle.thumbnail_state = thumb.state
    thumb_cmp = thumbnail_engine.compare_thumbnail(path)
    if thumb_cmp.available:
        bundle.thumbnail_mismatch = thumb_cmp.mismatch
        bundle.thumbnail_difference = thumb_cmp.difference

    # -- content provenance (C2PA / AI-generation metadata) ---------------
    provenance = provenance_analyzer.analyze_provenance(path)
    bundle.provenance = provenance
    if provenance.ai_generated:
        case.audit.record(
            "AI_PROVENANCE_DETECTED",
            f"AI-generation provenance detected in {row['file_name']}: "
            f"{provenance.summary()}.", evidence_id=carved_id)
    if provenance.asset_tampered:
        case.audit.record(
            "C2PA_TAMPER_DETECTED",
            f"C2PA credential in {row['file_name']} is validly signed but the "
            f"image was edited after signing (asset-hash mismatch).",
            evidence_id=carved_id)
    elif provenance.trust == provenance_analyzer.TRUST_INVALID:
        case.audit.record(
            "C2PA_SIGNATURE_INVALID",
            f"C2PA signature in {row['file_name']} failed cryptographic "
            f"verification (forged or corrupted manifest).",
            evidence_id=carved_id)
    elif provenance.signature_verified and provenance.signature_valid:
        case.audit.record(
            "C2PA_SIGNATURE_VERIFIED",
            f"C2PA signature in {row['file_name']} cryptographically verified: "
            f"{provenance.verification_summary}.", evidence_id=carved_id)

    # -- combined assessment ---------------------------------------------
    assessment = integrity_analyzer.assess(bundle)

    case.db.upsert_image_analysis(
        {
            "carved_evidence_id": carved_id,
            "jpeg_quality_estimate": jpeg_result.estimated_quality if jpeg_result else None,
            "jpeg_quantization_summary": jpeg_result.summary if jpeg_result else None,
            "file_type_match": 1 if ftype["result"] == file_type_analyzer.MATCH else 0,
            "thumbnail_path": thumb.thumbnail_path,
            "assessment": assessment.outcome,
            "manipulation_score": assessment.score,
            "provenance": provenance.summary() or None,
            "analyzed_utc": utc_now_iso(),
        }
    )
    logger.info("Analysis complete for %s -> %s", row["file_name"], assessment.outcome)
    return ImageAnalysis(carved_id, bundle, assessment)
