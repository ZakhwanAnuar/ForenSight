"""Recovered-file validation (spec sections 23-24).

Each recovered file is checked structurally and with Pillow.  Files that are
too small or fail validation are flagged *suspicious* (not automatically
declared invalid) with a documented reason.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PIL import Image

from . import config

# Quarantine reasons (spec section 24).
SIZE_BELOW_THRESHOLD = "SIZE_BELOW_THRESHOLD"
PIL_VALIDATION_FAILED = "PIL_VALIDATION_FAILED"
INVALID_SIGNATURE = "INVALID_SIGNATURE"
TRUNCATED_FILE = "TRUNCATED_FILE"
STRUCTURAL_ERROR = "STRUCTURAL_ERROR"
VALID = "VALID"


@dataclass
class ValidationResult:
    is_valid: bool
    is_suspicious: bool
    message: str
    reason: str = ""


def _signature_ok(data: bytes, fmt: str) -> bool:
    if fmt == "JPEG":
        return data.startswith(config.JPEG_HEADER)
    if fmt == "PNG":
        return data.startswith(config.PNG_HEADER)
    if fmt == "BMP":
        return data.startswith(config.BMP_HEADER)
    if fmt == "GIF":
        return any(data.startswith(h) for h in config.GIF_HEADERS)
    return False


def validate_recovered_file(
    path: str | Path,
    fmt: str,
    suspicious_threshold: int = config.SUSPICIOUS_SIZE_THRESHOLD,
) -> ValidationResult:
    """Validate a single carved file.

    Steps (spec section 23): signature -> minimum size -> structural / Pillow
    verify -> reopen.  Hashing is handled by the caller.
    """
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError:
        return ValidationResult(False, True, "File not accessible.", STRUCTURAL_ERROR)

    with path.open("rb") as fh:
        head = fh.read(16)

    if not _signature_ok(head, fmt):
        return ValidationResult(False, True, f"Invalid {fmt} signature.", INVALID_SIGNATURE)

    if size < suspicious_threshold:
        # Small files are suspicious, not automatically proven invalid.
        return ValidationResult(
            False, True,
            f"File size {size} bytes is below the {suspicious_threshold}-byte threshold.",
            SIZE_BELOW_THRESHOLD,
        )

    # Structural / decode validation via Pillow.
    try:
        with Image.open(path) as img:
            img.verify()  # checks structure without full decode
        # verify() leaves the image unusable; reopen and load to be sure.
        with Image.open(path) as img2:
            img2.load()
            width, height = img2.size
        if width <= 0 or height <= 0:
            return ValidationResult(False, True, "Invalid image dimensions.", STRUCTURAL_ERROR)
    except Exception as exc:  # noqa: BLE001 - Pillow raises many types
        text = str(exc).lower()
        if "truncated" in text or "end of file" in text:
            return ValidationResult(False, True, f"Truncated file: {exc}", TRUNCATED_FILE)
        return ValidationResult(False, True, f"Pillow validation failed: {exc}",
                                PIL_VALIDATION_FAILED)

    return ValidationResult(True, False, f"Valid {fmt} ({width}x{height}).", VALID)
