"""JPEG forensic analysis: quantization tables and quality (spec section 33).

A quality estimate is never treated as definitive proof of editing.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from PIL import Image

# Standard JPEG luminance quantization table (Annex K) used as the reference
# for estimating quality from an image's own quantization table.
_STD_LUMA = [
    16, 11, 10, 16, 24, 40, 51, 61,
    12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77,
    24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101,
    72, 92, 95, 98, 112, 100, 103, 99,
]


@dataclass
class JpegResult:
    is_jpeg: bool = False
    estimated_quality: Optional[float] = None
    quantization_tables: int = 0
    sampling: str = "Unknown"
    summary: str = ""
    assessment: str = "No significant structural anomaly detected"
    tables: list = field(default_factory=list)


def _estimate_quality(qtable: list[int]) -> float:
    """Estimate JPEG quality from a luminance quantization table.

    Inverts the standard IJG scaling relationship between quality and table
    values.  This is an approximation and documented as such (spec section 33).
    """
    if not qtable:
        return 0.0
    n = min(len(qtable), len(_STD_LUMA))
    ratios = []
    for i in range(n):
        std = _STD_LUMA[i]
        q = qtable[i]
        if q <= 0:
            continue
        # scale factor S relates table to standard: q = round(std * S / 100)
        scale = (q * 100.0) / std
        ratios.append(scale)
    if not ratios:
        return 0.0
    scale = sum(ratios) / len(ratios)
    if scale <= 0:
        return 100.0
    if scale < 100:
        quality = 100 - scale / 2.0
    else:
        quality = 5000.0 / scale
    return round(max(1.0, min(100.0, quality)), 1)


def analyze_jpeg(path: str | Path) -> JpegResult:
    """Analyse quantization tables, quality and sampling of a JPEG file."""
    path = Path(path)
    result = JpegResult()

    try:
        with Image.open(path) as img:
            if (img.format or "").upper() != "JPEG":
                result.summary = "Not a JPEG image; JPEG analysis skipped."
                return result
            result.is_jpeg = True
            qtables = getattr(img, "quantization", None) or {}
            result.quantization_tables = len(qtables)
            result.tables = [list(v) for v in qtables.values()]

            # Sampling factors (chroma subsampling), if exposed by Pillow.
            try:
                from PIL import JpegImagePlugin  # noqa: F401
                layer = getattr(img, "layer", None)
                if layer and len(layer) >= 3:
                    # layer entries: (id, sampling_h, sampling_v, qtable_index)
                    h0, v0 = layer[0][1], layer[0][2]
                    if h0 == 2 and v0 == 2:
                        result.sampling = "4:2:0"
                    elif h0 == 2 and v0 == 1:
                        result.sampling = "4:2:2"
                    elif h0 == 1 and v0 == 1:
                        result.sampling = "4:4:4"
                    else:
                        result.sampling = f"{h0}x{v0}"
            except Exception:  # noqa: BLE001
                pass

            if result.tables:
                result.estimated_quality = _estimate_quality(result.tables[0])
    except Exception as exc:  # noqa: BLE001
        result.summary = f"JPEG analysis failed: {exc}"
        result.assessment = "JPEG could not be analysed"
        return result

    q = result.estimated_quality
    result.summary = (
        f"Quantization tables: {result.quantization_tables}; "
        f"Estimated quality: {q if q is not None else 'N/A'}; "
        f"Sampling: {result.sampling}"
    )
    # Simple, transparent structural note - reported as context only, never
    # scored: quality alone does not indicate editing.
    if q is not None and q >= 98:
        result.assessment = "Very high quality / low compression"
    elif q is not None and q < 40:
        result.assessment = "Low quality / heavy re-compression"
    else:
        result.assessment = "No significant structural anomaly detected"
    return result
