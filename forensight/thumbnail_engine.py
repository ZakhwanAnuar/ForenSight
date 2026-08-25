"""Embedded EXIF thumbnail recovery (spec section 34).

Missing thumbnails are not automatically suspicious.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from PIL import Image

THUMBNAIL_RECOVERED = "THUMBNAIL_RECOVERED"
NO_EMBEDDED_THUMBNAIL = "NO_EMBEDDED_THUMBNAIL"
EXTRACTION_FAILED = "EXTRACTION_FAILED"


@dataclass
class ThumbnailResult:
    state: str
    thumbnail_path: Optional[str] = None
    message: str = ""


def recover_thumbnail(input_path: str | Path, output_dir: str | Path) -> ThumbnailResult:
    """Attempt to extract an embedded JPEG thumbnail from EXIF."""
    input_path = Path(input_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Only JPEGs carry embedded EXIF thumbnails; require an EXIF block.
        with Image.open(input_path) as img:
            has_exif = bool(img.getexif())
        if not has_exif:
            return ThumbnailResult(NO_EMBEDDED_THUMBNAIL,
                                   message="No EXIF metadata present.")

        data = input_path.read_bytes()
        thumb_bytes = _extract_embedded_jpeg(data)
        if not thumb_bytes:
            return ThumbnailResult(NO_EMBEDDED_THUMBNAIL,
                                   message="No embedded EXIF thumbnail present.")

        # Validate that the extracted bytes decode as an image before saving.
        import io
        with Image.open(io.BytesIO(thumb_bytes)) as thumb:
            thumb.load()

        out_path = output_dir / f"THUMB_{input_path.stem}.jpg"
        with out_path.open("wb") as fh:
            fh.write(thumb_bytes)
        return ThumbnailResult(THUMBNAIL_RECOVERED, str(out_path),
                               "Embedded thumbnail recovered.")
    except Exception as exc:  # noqa: BLE001
        return ThumbnailResult(EXTRACTION_FAILED, message=f"Extraction failed: {exc}")


@dataclass
class ThumbnailComparison:
    available: bool = False          # an embedded thumbnail was found & decoded
    difference: Optional[float] = None   # 0-1 normalised mean pixel difference
    mismatch: bool = False           # difference exceeds the threshold
    message: str = ""


def compare_thumbnail(input_path: str | Path,
                      threshold: float | None = None) -> ThumbnailComparison:
    """Compare an embedded EXIF thumbnail against the full image.

    Cameras embed a thumbnail rendered from the ORIGINAL capture; many editors
    re-save the full image without updating that thumbnail.  A large difference
    is therefore evidence the picture was edited after capture.  When no
    thumbnail is present the check is simply unavailable (never a mismatch).
    """
    import io
    import numpy as np
    from . import config

    if threshold is None:
        threshold = config.THUMBNAIL_MISMATCH_THRESHOLD

    input_path = Path(input_path)
    result = ThumbnailComparison()
    try:
        data = input_path.read_bytes()
        thumb_bytes = _extract_embedded_jpeg(data)
        if not thumb_bytes:
            result.message = "No embedded thumbnail to compare."
            return result
        with Image.open(io.BytesIO(thumb_bytes)) as t:
            thumb = t.convert("L").resize((32, 32))
        with Image.open(input_path) as m:
            main = m.convert("L").resize((32, 32))
        ta = np.asarray(thumb, dtype=np.float32)
        ma = np.asarray(main, dtype=np.float32)
        diff = float(np.mean(np.abs(ta - ma)) / 255.0)
        result.available = True
        result.difference = diff
        result.mismatch = diff > threshold
        result.message = f"Thumbnail/full-image difference {diff:.0%}."
    except Exception as exc:  # noqa: BLE001
        result.message = f"Thumbnail comparison failed: {exc}"
    return result


def _extract_embedded_jpeg(data: bytes) -> bytes | None:
    """Return the nested EXIF thumbnail JPEG (the second SOI...EOI) if present.

    The main image begins with the first ``FF D8``; an EXIF thumbnail is a
    second complete JPEG embedded in the APP1 segment near the start.
    """
    first_soi = data.find(b"\xFF\xD8")
    if first_soi == -1:
        return None
    second_soi = data.find(b"\xFF\xD8", first_soi + 2)
    if second_soi == -1:
        return None
    eoi = data.find(b"\xFF\xD9", second_soi + 2)
    if eoi == -1:
        return None
    candidate = data[second_soi:eoi + 2]
    # Sanity bound: a thumbnail should be reasonably small and precede the scan.
    return candidate if 100 < len(candidate) < 200_000 else None
