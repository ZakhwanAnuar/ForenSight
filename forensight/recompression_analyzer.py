"""JPEG re-compression detection via quantization-table fingerprinting.

Transparent and rule-based - NO AI/ML, and NO Error Level Analysis.

A camera writes its own (often manufacturer-specific) JPEG quantization tables
at capture.  When an image is opened and re-saved by a generic software encoder
- Photoshop, GIMP, a mobile editor, or any libjpeg/Pillow pipeline - it is
re-quantised using the *standard* IJG tables scaled to some quality Q.  So when
an image's luminance quantization table closely matches the standard IJG table
for its estimated quality, the file was (re)encoded by generic software rather
than left as a camera original - an indicator that it was re-saved / edited.

This replaces ELA, which cannot see a globally re-saved edit.  Limitation: it
only applies to JPEGs, and a genuine capture that happens to use standard tables
would also match - hence it is reported as an INDICATOR, never proof.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from . import config, jpeg_analyzer

# Standard IJG luminance quantization table (JPEG Annex K).
_STD_LUMA = jpeg_analyzer._STD_LUMA

# Mean absolute per-cell difference below which the table is treated as a match.
_TABLE_TOLERANCE = 2.0


@dataclass
class RecompressionResult:
    is_jpeg: bool = False
    quality: Optional[float] = None
    matches_standard_table: bool = False
    recompressed: bool = False
    detail: str = ""


def _std_table_for_quality(quality: float) -> list[int]:
    """Build the standard IJG luminance table scaled to ``quality`` (1-100)."""
    q = max(1, min(100, int(round(quality))))
    scale = 5000 / q if q < 50 else 200 - 2 * q
    out = []
    for val in _STD_LUMA:
        v = (val * scale + 50) // 100
        out.append(int(max(1, min(255, v))))
    return out


def analyze(jpeg_result: "jpeg_analyzer.JpegResult") -> RecompressionResult:
    """Assess re-compression from an already-computed JpegResult."""
    result = RecompressionResult(is_jpeg=jpeg_result.is_jpeg,
                                 quality=jpeg_result.estimated_quality)
    if not jpeg_result.is_jpeg or not jpeg_result.tables:
        result.detail = "Not a JPEG or no quantization table."
        return result

    q = jpeg_result.estimated_quality
    if q is None:
        result.detail = "Quality could not be estimated."
        return result

    actual = list(jpeg_result.tables[0])[:64]
    standard = _std_table_for_quality(q)
    n = min(len(actual), len(standard))
    if n == 0:
        return result
    mean_diff = sum(abs(actual[i] - standard[i]) for i in range(n)) / n
    result.matches_standard_table = mean_diff <= _TABLE_TOLERANCE

    # Standard-table encode below capture quality => software re-save.
    result.recompressed = (
        result.matches_standard_table
        and q < config.RECOMPRESSION_QUALITY_CEILING
    )
    result.detail = (
        f"Quality~{q:.0f}; mean table deviation {mean_diff:.2f}; "
        f"{'standard software table' if result.matches_standard_table else 'non-standard (camera-like) table'}."
    )
    return result
