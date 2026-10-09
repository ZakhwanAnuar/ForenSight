"""Error Level Analysis (ELA) - a NON-SCORING visual investigator aid.

ELA re-saves an image at a known JPEG quality and amplifies the per-pixel
difference between the original and the re-saved copy.  Regions with a
*different compression history* (for example, content spliced in from another,
differently-compressed source) tend to stand out against a uniformly-compressed
background.

Method (after Krawetz, "A Picture's Worth", Black Hat 2007 - the technique
behind FotoForensics):

1. Re-save the image once as JPEG at a fixed high quality (default 95).  A high
   quality gives a low baseline error, so genuine differences stand out more.
2. Take the absolute, per-channel difference between the original and the
   re-saved copy.  The *colour* of the error is informative, so the result is
   kept in RGB rather than converted to greyscale.
3. Amplify the difference for display.  Critically, the amplification is scaled
   by a high PERCENTILE of the error (default 99th), NOT by the single brightest
   pixel.  Global max-scaling (``255 / max``) is the classic naive mistake: one
   saturated pixel at any sharp edge collapses the whole image to black.  The
   gain is also clamped so a perfectly uniform frame is not amplified into pure
   sensor noise, and a very busy frame is not driven to black.

Interpretation, stated deliberately:

* ELA is a **hint for a human examiner, not proof of tampering.**  Bright
  regions can arise from genuine editing, but also from texture, sharp edges,
  text, high-contrast areas, or an image's prior recompression history.
* ELA is **uninformative on globally / uniformly re-compressed images** - every
  modern editor re-encodes the whole frame on export, and every messaging
  platform (WhatsApp, Telegram) re-compresses on transfer, which flattens the
  regional differences ELA relies on.
* ELA is designed for **JPEG** input.  On a lossless source (PNG/BMP) the map
  reflects the first JPEG cycle applied everywhere, so it reads as broadly
  uniform unless the lossless file itself contains spliced JPEG content.
* For these reasons ELA is **excluded from ForenSight's forensic integrity and
  provenance score**.  The score uses only defensible facts (a broken
  cryptographic C2PA signature, a documented generator marker).  ELA is offered
  purely as an optional visual comparison.

This module depends only on Pillow and numpy (both already required), so it adds
no new third-party requirement and is fully unit-testable.
"""
from __future__ import annotations

import io
from pathlib import Path
from typing import Optional, Union

try:
    import numpy as np
    from PIL import Image, ImageOps
    HAVE_PIL = True
except Exception:  # noqa: BLE001 - core deps, but degrade rather than crash
    np = None  # type: ignore
    Image = None  # type: ignore
    HAVE_PIL = False

# Shown in the UI and printed with any ELA output so the caveat travels with it.
CAVEAT = (
    "Error Level Analysis is a non-authoritative visual aid, not proof of "
    "tampering. Bright regions indicate a differing compression history, which "
    "may result from editing but also from texture, edges, text or prior "
    "recompression. ELA is excluded from the forensic score and must be read "
    "only as a hint for a human examiner."
)

Source = Union[str, Path, bytes, bytearray]

# -- tuning (display only; none of this feeds the forensic score) ----------
DEFAULT_QUALITY = 95        # JPEG re-save quality (Krawetz/FotoForensics range)
DEFAULT_MAX_DIM = 1400      # cap the long edge before analysis: ELA is a display
                            # aid shown scaled anyway, so working on a large image
                            # at full resolution only wastes time (a 12 MP frame
                            # can take seconds). Big images are downscaled to this.
_SCALE_PERCENTILE = 99.0    # error percentile mapped to full brightness
_MIN_GAIN = 8.0             # keep busy frames from going black
_MAX_GAIN = 50.0            # keep uniform frames from becoming pure noise

# Thresholds for the advisory hint line, measured on the RAW (unamplified)
# error magnitude at DEFAULT_QUALITY.  Advisory only, never a score input.
_UNIFORM_P99 = 8.0          # below this, essentially no error-level variation
_BLOCK_GRID = 24            # coarse grid for spatial localization
_LOCAL_RATIO = 4.0          # peak block must exceed the background by this factor
_STRONG_FLOOR = 6.0         # peak block above this => confident "localized" call
_WEAK_FLOOR = 3.0           # peak block above this => defer to the heatmap
                            # (a strong splice clears _STRONG_FLOOR; ordinary photo
                            # texture on a near-zero-error frame stays below
                            # _WEAK_FLOOR; the band between the two is reported as
                            # "inspect the heatmap" rather than falsely reassuring,
                            # because ELA cannot reliably decide it from stats alone)


def _load_rgb(source: Source, max_dim: int = DEFAULT_MAX_DIM):
    """Open ``source`` (path or bytes) as an orientation-corrected RGB image.

    Images whose long edge exceeds ``max_dim`` are downscaled first, so ELA stays
    fast on large frames (this is a display aid, not a pixel-exact measurement).
    """
    if isinstance(source, (bytes, bytearray)):
        img = Image.open(io.BytesIO(bytes(source)))
    else:
        img = Image.open(str(source))
    # Respect EXIF orientation so the ELA map aligns with the visible preview.
    img = ImageOps.exif_transpose(img).convert("RGB")
    if max_dim and max(img.size) > max_dim:
        img.thumbnail((max_dim, max_dim), Image.Resampling.LANCZOS)
    return img


def _error_array(source: Source, quality: int, max_dim: int = DEFAULT_MAX_DIM):
    """Return the per-channel absolute error as a float32 HxWx3 array, or None.

    This is the raw ELA signal before any amplification.  Both the visualization
    and the statistics derive from it, so they stay consistent.
    """
    if not HAVE_PIL:
        return None
    try:
        original = _load_rgb(source, max_dim=max_dim)
    except Exception:  # noqa: BLE001 - undecodable / truncated / not an image
        return None
    try:
        buffer = io.BytesIO()
        original.save(buffer, "JPEG", quality=max(1, min(100, int(quality))))
        buffer.seek(0)
        resaved = Image.open(buffer).convert("RGB")
        a = np.asarray(original, dtype=np.float32)
        b = np.asarray(resaved, dtype=np.float32)
        if a.shape != b.shape or a.size == 0:
            return None
        return np.abs(a - b)
    except Exception:  # noqa: BLE001 - malformed pixel data mid-process
        return None


def _auto_gain(magnitude) -> float:
    """Robust amplification factor: map the Nth percentile of error to 255.

    Using a high percentile instead of the maximum prevents a single saturated
    pixel (common at any sharp edge) from collapsing the whole map to black.
    """
    p = float(np.percentile(magnitude, _SCALE_PERCENTILE))
    gain = (255.0 / p) if p > 1e-6 else _MAX_GAIN
    return float(min(_MAX_GAIN, max(_MIN_GAIN, gain)))


def compute_ela(source: Source, quality: int = DEFAULT_QUALITY,
                gain: Optional[float] = None):
    """Return an amplified ELA image (PIL ``Image``) for ``source``.

    ``source`` may be a filesystem path or raw image bytes.  ``gain`` overrides
    the automatic percentile-based amplification when given.  Returns ``None`` if
    Pillow/numpy are unavailable or the input cannot be decoded - callers must
    handle ``None`` and never crash on bad evidence.
    """
    err = _error_array(source, quality)
    if err is None:
        return None
    try:
        magnitude = err.max(axis=2)          # per-pixel error strength
        g = _auto_gain(magnitude) if gain is None else float(gain)
        amplified = np.clip(err * g, 0, 255).astype(np.uint8)
        return Image.fromarray(amplified, "RGB")
    except Exception:  # noqa: BLE001
        return None


def ela_png_bytes(source: Source, quality: int = DEFAULT_QUALITY) -> Optional[bytes]:
    """Return the ELA heatmap encoded as PNG bytes, or ``None`` on failure.

    PNG is lossless, so the heatmap is not re-compressed for display/embedding.
    """
    ela = compute_ela(source, quality=quality)
    if ela is None:
        return None
    try:
        out = io.BytesIO()
        ela.save(out, "PNG")
        return out.getvalue()
    except Exception:  # noqa: BLE001
        return None


def _block_means(mag, grid: int = _BLOCK_GRID):
    """Mean error per cell of a ``grid`` x ``grid`` tiling of the frame.

    Averaging over blocks suppresses thin high-error edges (which touch only a
    sliver of a block) while preserving a spliced *region* (which fills whole
    blocks), giving a spatial localization signal that per-pixel percentiles
    miss on heavily-recompressed images.
    """
    h, w = mag.shape
    bh = max(1, h // grid)
    bw = max(1, w // grid)
    hc, wc = (h // bh) * bh, (w // bw) * bw
    if hc == 0 or wc == 0:
        return mag.reshape(1, -1).mean(axis=1)
    tiled = mag[:hc, :wc].reshape(hc // bh, bh, wc // bw, bw)
    return tiled.mean(axis=(1, 3))


def _stats_from_err(err) -> Optional[dict]:
    """Summary statistics from a precomputed error array (see :func:`ela_stats`)."""
    try:
        mag = err.max(axis=2)
        blocks = _block_means(mag)
        return {
            "mean": float(mag.mean()),
            "median": float(np.median(mag)),
            "p95": float(np.percentile(mag, 95)),
            "p99": float(np.percentile(mag, 99)),
            "max": float(mag.max()),
            "block_peak": float(blocks.max()),
            "block_bg": float(np.median(blocks)),
        }
    except Exception:  # noqa: BLE001
        return None


def ela_stats(source: Source, quality: int = DEFAULT_QUALITY) -> Optional[dict]:
    """Summary statistics of the RAW error magnitude (0-255), or ``None``.

    Includes a coarse spatial-localization measure (``block_peak`` vs
    ``block_bg``) used to flag a bright *region* even when absolute error is low.
    Provided for the advisory hint line and optional report use; deliberately
    NOT a score input.
    """
    err = _error_array(source, quality)
    return None if err is None else _stats_from_err(err)


def mean_error(source: Source, quality: int = DEFAULT_QUALITY) -> Optional[float]:
    """Mean raw error across the frame (0-255), or ``None`` on failure."""
    stats = ela_stats(source, quality=quality)
    return None if stats is None else stats["mean"]


def _hint_from_stats(stats: Optional[dict]) -> str:
    """Cautious human-readable interpretation from precomputed stats."""
    if not HAVE_PIL:
        return "ELA unavailable (Pillow/numpy not installed)."
    if stats is None:
        return "ELA could not be computed for this file."
    # Spatial localization: a bright cluster of whole blocks standing clearly
    # above the background is the signal of interest (a possible splice). It is
    # measured relative to the frame's own error floor, so it works even on
    # heavily-recompressed images where absolute error is tiny. Three tiers keep
    # the text honest: a confident call, a defer-to-the-heatmap call, and a
    # genuinely-uniform call - never a false reassurance.
    peak, bg = stats["block_peak"], stats["block_bg"]
    if peak >= bg * _LOCAL_RATIO + _STRONG_FLOOR:
        return ("A localized region of elevated error is present, standing out "
                "from the background. Inspect the brightest area manually - it "
                "may indicate an edited or spliced region, but edges, text and "
                "fine texture also raise ELA.")
    if peak >= _WEAK_FLOOR:
        return ("Mostly uniform, but one area shows somewhat higher error than "
                "the rest. Inspect the brighter region in the heatmap directly - "
                "ELA cannot confirm from statistics alone whether it is an edit "
                "or ordinary texture/edges.")
    if stats["p99"] < _UNIFORM_P99:
        return ("Frame appears uniformly compressed - little error-level "
                "variation anywhere. This is expected for a re-saved or "
                "messenger-transferred image and is not an authenticity signal "
                "either way.")
    return ("Error-level variation is spread across the frame, consistent with "
            "normal edges and texture. No single localized anomaly stands out.")


def hint(source: Source, quality: int = DEFAULT_QUALITY) -> str:
    """A short, cautious, human-readable interpretation line for the UI."""
    if not HAVE_PIL:
        return "ELA unavailable (Pillow/numpy not installed)."
    return _hint_from_stats(ela_stats(source, quality=quality))


def analyze(source: Source, quality: int = DEFAULT_QUALITY):
    """Compute the heatmap PNG AND the hint in a SINGLE pass over the image.

    Returns ``(png_bytes_or_None, hint_text)``.  This is what the UI should call:
    it does the (downscaled) error computation once, instead of running ELA twice
    (once for the image, once for the hint), roughly halving per-selection cost.
    """
    err = _error_array(source, quality)
    if err is None:
        return None, _hint_from_stats(None)
    png = None
    try:
        magnitude = err.max(axis=2)
        g = _auto_gain(magnitude)
        amplified = np.clip(err * g, 0, 255).astype(np.uint8)
        out = io.BytesIO()
        Image.fromarray(amplified, "RGB").save(out, "PNG")
        png = out.getvalue()
    except Exception:  # noqa: BLE001
        png = None
    return png, _hint_from_stats(_stats_from_err(err))
