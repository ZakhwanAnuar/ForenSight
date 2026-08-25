"""File-type mismatch detection (spec section 28).

Compares a file's *extension* with the type implied by its *magic bytes*.
Treated strictly as an indicator, never as proof of malicious activity.
"""
from __future__ import annotations

from pathlib import Path

MATCH = "MATCH"
MISMATCH = "MISMATCH"
UNKNOWN = "UNKNOWN"

# Magic-number table (prefix -> canonical type).
_MAGIC = [
    (b"\xFF\xD8\xFF", "JPEG"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"BM", "BMP"),
    (b"%PDF", "PDF"),
    (b"PK\x03\x04", "ZIP"),
    (b"\x1f\x8b", "GZIP"),
    (b"II*\x00", "TIFF"),
    (b"MM\x00*", "TIFF"),
    (b"RIFF", "RIFF"),      # webp/wav/avi container
    (b"\x00\x00\x01\x00", "ICO"),
    (b"\x42\x5A\x68", "BZIP2"),
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE/EXE"),
]

_EXT_TO_TYPE = {
    ".jpg": "JPEG", ".jpeg": "JPEG", ".jpe": "JPEG",
    ".png": "PNG",
    ".gif": "GIF",
    ".bmp": "BMP", ".dib": "BMP",
    ".pdf": "PDF",
    ".zip": "ZIP",
    ".gz": "GZIP",
    ".tif": "TIFF", ".tiff": "TIFF",
    ".txt": "TEXT",
    ".bin": "BINARY",
}


def detect_type_from_bytes(header: bytes) -> str:
    for magic, name in _MAGIC:
        if header.startswith(magic):
            return name
    # crude printable-text heuristic
    sample = header[:64]
    if sample and all(9 <= b <= 126 or b in (10, 13) for b in sample):
        return "TEXT"
    return "UNKNOWN"


def analyze_file_type(path: str | Path) -> dict:
    """Return a dict describing extension vs detected type and the result."""
    path = Path(path)
    ext = path.suffix.lower()
    expected = _EXT_TO_TYPE.get(ext, "UNKNOWN")

    try:
        with path.open("rb") as fh:
            header = fh.read(64)
    except OSError:
        header = b""

    detected = detect_type_from_bytes(header)

    if detected == "UNKNOWN" or expected == "UNKNOWN":
        result = UNKNOWN
    elif detected == expected:
        result = MATCH
    else:
        result = MISMATCH

    return {
        "extension": ext,
        "expected_type": expected,
        "detected_type": detected,
        "result": result,
    }
