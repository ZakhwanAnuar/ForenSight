"""Generate a comprehensive controlled forensic test disk image for ForenSight.

The produced raw ``.dd`` exercises every ForenSight feature end-to-end
(spec section 63):

  * valid JPEG / PNG / BMP / GIF recoveries
  * a JPEG with full camera EXIF + GPS + an embedded thumbnail
  * a JPEG whose metadata names image-processing software (an indicator)
  * a heavily recompressed low-quality JPEG (an indicator)
  * a deliberately truncated JPEG (suspicious / fragmented quarantine case)
  * a sub-5 KB image (SIZE_BELOW_THRESHOLD quarantine case)

Files sit in "unallocated space" separated by zero padding, and the GIF is
placed last followed only by zero padding so its trailer is detected cleanly.

Run:  python sample_data/make_sample.py
"""
from __future__ import annotations

import io
import random
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw

try:
    import piexif
except Exception:  # noqa: BLE001
    piexif = None

OUT = Path(__file__).resolve().parent / "suspect_test.dd"
PAD = 4096
_SEED = [0]


def _noise(size=(800, 600)) -> Image.Image:
    """A structured 'photo-like' scene: a smooth colour gradient overlaid with
    many shapes.  This reliably compresses to well over 5 KB yet, unlike pure
    random noise, recompresses cleanly so a genuine image reads as low-ELA (no
    false 'manipulation' indicator)."""
    _SEED[0] += 1
    rnd = random.Random(_SEED[0])
    w, h = size
    xr = np.linspace(0, 255, w, dtype=np.uint8)
    yr = np.linspace(0, 255, h, dtype=np.uint8)
    r = np.tile(xr, (h, 1))
    g = np.tile(yr.reshape(h, 1), (1, w))
    b = ((r.astype(int) + g.astype(int)) // 2).astype(np.uint8)
    img = Image.fromarray(np.dstack([r, g, b]), "RGB")
    draw = ImageDraw.Draw(img)
    for _ in range(60):
        x0, y0 = rnd.randint(0, w), rnd.randint(0, h)
        x1, y1 = rnd.randint(0, w), rnd.randint(0, h)
        box = [min(x0, x1), min(y0, y1), max(x0, x1), max(y0, y1)]
        color = (rnd.randint(0, 255), rnd.randint(0, 255), rnd.randint(0, 255))
        (draw.rectangle if rnd.random() < 0.5 else draw.ellipse)(box, fill=color)
    return img


def _jpeg(quality=90, size=(640, 480)) -> bytes:
    buf = io.BytesIO()
    _noise(size).save(buf, "JPEG", quality=quality)
    return buf.getvalue()


def _jpeg_with_exif(quality=90) -> bytes:
    """JPEG carrying camera EXIF, GPS and an embedded thumbnail."""
    if piexif is None:
        return _jpeg(quality)
    # Build an embedded thumbnail (large enough to also survive as its own
    # valid carved image when recovered separately).
    thumb_io = io.BytesIO()
    _noise((320, 240)).save(thumb_io, "JPEG", quality=80)

    exif_dict = {
        "0th": {
            piexif.ImageIFD.Make: b"Canon",
            piexif.ImageIFD.Model: b"Canon EOS 80D",
            piexif.ImageIFD.Software: b"Canon Firmware 1.0.2",
            piexif.ImageIFD.DateTime: b"2026:03:21 21:39:00",
        },
        "Exif": {
            piexif.ExifIFD.DateTimeOriginal: b"2026:03:21 21:39:00",
            piexif.ExifIFD.DateTimeDigitized: b"2026:03:21 21:39:00",
        },
        "GPS": {
            piexif.GPSIFD.GPSLatitudeRef: b"N",
            piexif.GPSIFD.GPSLatitude: [(3, 1), (8, 1), (3000, 100)],
            piexif.GPSIFD.GPSLongitudeRef: b"E",
            piexif.GPSIFD.GPSLongitude: [(101, 1), (41, 1), (2000, 100)],
        },
        "1st": {
            piexif.ImageIFD.Compression: 6,
            piexif.ImageIFD.XResolution: (72, 1),
            piexif.ImageIFD.YResolution: (72, 1),
            piexif.ImageIFD.ResolutionUnit: 2,
        },
        "thumbnail": thumb_io.getvalue(),
    }
    buf = io.BytesIO()
    _noise().save(buf, "JPEG", quality=quality, exif=piexif.dump(exif_dict))
    return buf.getvalue()


def _jpeg_photoshop(quality=80) -> bytes:
    """JPEG whose Software tag names an image-processing application."""
    if piexif is None:
        return _jpeg(quality)
    exif_dict = {"0th": {piexif.ImageIFD.Software: b"Adobe Photoshop 25.0 (Windows)",
                         piexif.ImageIFD.Make: b"NIKON CORPORATION",
                         piexif.ImageIFD.Model: b"NIKON D750"},
                 "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None}
    buf = io.BytesIO()
    _noise().save(buf, "JPEG", quality=quality, exif=piexif.dump(exif_dict))
    return buf.getvalue()


def _png(size=(640, 480)) -> bytes:
    buf = io.BytesIO()
    _noise(size).save(buf, "PNG")
    return buf.getvalue()


def _bmp(size=(400, 300)) -> bytes:
    buf = io.BytesIO()
    _noise(size).save(buf, "BMP")
    return buf.getvalue()


def _gif(size=(400, 300)) -> bytes:
    buf = io.BytesIO()
    _noise(size).convert("P").save(buf, "GIF")
    return buf.getvalue()


def _tiny_png() -> bytes:
    """A small (< 5 KB) solid image -> SIZE_BELOW_THRESHOLD quarantine."""
    buf = io.BytesIO()
    Image.new("RGB", (16, 16), (200, 30, 30)).save(buf, "PNG")
    return buf.getvalue()


def build() -> Path:
    manifest = []
    blobs: list[bytes] = []

    def add(label, data):
        blobs.append(data)
        manifest.append((label, len(data)))

    add("JPEG - normal (valid)", _jpeg(quality=92))
    add("JPEG - camera EXIF + GPS + thumbnail (valid)", _jpeg_with_exif(quality=90))
    add("JPEG - Photoshop metadata (indicator)", _jpeg_photoshop(quality=80))
    add("JPEG - low quality / recompressed (indicator)", _jpeg(quality=20))
    add("PNG  - normal (valid)", _png())
    add("BMP  - normal (valid)", _bmp())
    add("Tiny PNG - sub-5KB (suspicious quarantine)", _tiny_png())
    # Truncated JPEG: keep only the first half -> suspicious / fragmented.
    full = _jpeg(quality=85)
    add("JPEG - truncated (suspicious / fragmented)", full[: len(full) // 2])
    # GIF last so its trailer is followed only by zero padding.
    add("GIF  - normal (valid)", _gif())

    with OUT.open("wb") as fh:
        fh.write(b"\x00" * PAD)          # leading unallocated space
        for blob in blobs:
            fh.write(blob)
            fh.write(b"\x00" * PAD)      # inter-file padding
        fh.write(b"\x00" * PAD)          # trailing zero padding (clean GIF end)

    print(f"Wrote sample image: {OUT} ({OUT.stat().st_size:,} bytes)\n")
    print("Embedded blobs (recoverable evidence):")
    for label, size in manifest:
        print(f"  - {label:52s} {size:>8,} bytes")
    print("\nExpected after carving + 'Analyse All Valid':")
    print("  • ~6-7 valid images (JPEG/PNG/BMP/GIF + the embedded thumbnail)")
    print("  • 2 suspicious/quarantined (tiny PNG, truncated JPEG)")
    print("  • EXIF populated for the camera JPEG (Make/Model/GPS/thumbnail)")
    print("  • Photoshop JPEG -> POTENTIAL_MANIPULATION (software indicator)")
    return OUT


if __name__ == "__main__":
    build()
