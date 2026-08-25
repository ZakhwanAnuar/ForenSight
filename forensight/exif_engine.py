"""EXIF metadata extraction and indicator flagging (spec sections 31-32)."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from PIL import Image, ExifTags

from . import signatures

NOT_AVAILABLE = "Not Available"

# Camera/phone makers and OS/firmware markers come from the shared signatures
# module (see forensight/signatures.py) so they cannot drift from provenance.
_CAMERA_MAKERS = signatures.CAMERA_MAKERS
_CAMERA_OS_MARKERS = signatures.CAMERA_OS_MARKERS
_VERSION_RE = re.compile(r"^[\svV.\-_0-9()]+$")   # e.g. "17.2", "Ver.1.00"


def _looks_like_camera_software(software: str, make: str = "",
                               model: str = "") -> bool:
    """True if a Software tag is camera firmware / a device OS / the device name,
    rather than an editing application."""
    s = software.strip().lower()
    if not s or s == NOT_AVAILABLE.lower():
        return True
    if _VERSION_RE.match(s):                              # bare version string
        return True
    if s.startswith(("ver", "version", "firmware", "v.")):
        return True
    if any(m in s for m in _CAMERA_OS_MARKERS):
        return True
    if any(mk in s for mk in _CAMERA_MAKERS):
        return True
    for ctx in (make.strip().lower(), model.strip().lower()):
        if ctx and ctx != NOT_AVAILABLE.lower() and (ctx in s or s in ctx):
            return True
    # A recognised camera/phone Make means an unrecognised Software value is far
    # more likely device firmware than an editor (known editors are matched
    # earlier, before this fallback), so do not flag it.
    mk_low = make.strip().lower()
    if mk_low and mk_low != NOT_AVAILABLE.lower() \
            and any(mk in mk_low for mk in _CAMERA_MAKERS):
        return True
    return False

# Known editing-application substrings for the EXIF "Software" tag, derived from
# the single shared list (see forensight/signatures.py).
_EDITOR_HINTS = signatures.editor_hints_lower()

_TAG_NAME = {v: k for k, v in ExifTags.TAGS.items()}


@dataclass
class ExifResult:
    make: str = NOT_AVAILABLE
    model: str = NOT_AVAILABLE
    datetime: str = NOT_AVAILABLE
    datetime_original: str = NOT_AVAILABLE
    datetime_digitized: str = NOT_AVAILABLE
    software: str = NOT_AVAILABLE
    artist: str = NOT_AVAILABLE
    copyright: str = NOT_AVAILABLE
    orientation: str = NOT_AVAILABLE
    width: str = NOT_AVAILABLE
    height: str = NOT_AVAILABLE
    gps_latitude: str = NOT_AVAILABLE
    gps_longitude: str = NOT_AVAILABLE
    raw: dict = field(default_factory=dict)
    indicators: list = field(default_factory=list)

    @property
    def has_exif(self) -> bool:
        return bool(self.raw)


def _clean(value) -> str:
    if value is None:
        return NOT_AVAILABLE
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return NOT_AVAILABLE
    text = str(value).strip().replace("\x00", "")
    return text or NOT_AVAILABLE


def _gps_to_str(gps_info) -> tuple[str, str]:
    if not gps_info:
        return NOT_AVAILABLE, NOT_AVAILABLE
    gps = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_info.items()}

    def to_deg(values, ref):
        try:
            d, m, s = [float(x) for x in values]
            result = d + m / 60.0 + s / 3600.0
            if ref in ("S", "W"):
                result = -result
            return f"{result:.6f}"
        except Exception:  # noqa: BLE001
            return NOT_AVAILABLE

    lat = to_deg(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef", "N")) \
        if gps.get("GPSLatitude") else NOT_AVAILABLE
    lon = to_deg(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef", "E")) \
        if gps.get("GPSLongitude") else NOT_AVAILABLE
    return lat, lon


def extract_exif(path: str | Path) -> ExifResult:
    """Extract EXIF metadata; missing values are represented as Not Available.

    Metadata is never inferred (spec section 31).
    """
    path = Path(path)
    result = ExifResult()
    try:
        with Image.open(path) as img:
            result.width = str(img.size[0])
            result.height = str(img.size[1])
            exif = img.getexif()
    except Exception:  # noqa: BLE001 - unreadable / no EXIF
        return result

    if not exif:
        return result

    raw: dict[str, str] = {}
    for tag_id, value in exif.items():
        name = ExifTags.TAGS.get(tag_id, str(tag_id))
        raw[name] = _clean(value)

    result.raw = raw
    result.make = raw.get("Make", NOT_AVAILABLE)
    result.model = raw.get("Model", NOT_AVAILABLE)
    result.datetime = raw.get("DateTime", NOT_AVAILABLE)
    result.software = raw.get("Software", NOT_AVAILABLE)
    result.artist = raw.get("Artist", NOT_AVAILABLE)
    result.copyright = raw.get("Copyright", NOT_AVAILABLE)
    result.orientation = raw.get("Orientation", NOT_AVAILABLE)

    # Sub-IFD (Exif) tags: DateTimeOriginal, DateTimeDigitized.
    try:
        exif_ifd = exif.get_ifd(_TAG_NAME.get("ExifOffset", 0x8769))
        for tag_id, value in (exif_ifd or {}).items():
            name = ExifTags.TAGS.get(tag_id, str(tag_id))
            raw[name] = _clean(value)
        result.datetime_original = raw.get("DateTimeOriginal", NOT_AVAILABLE)
        result.datetime_digitized = raw.get("DateTimeDigitized", NOT_AVAILABLE)
    except Exception:  # noqa: BLE001
        pass

    # GPS.
    try:
        gps_ifd = exif.get_ifd(_TAG_NAME.get("GPSInfo", 0x8825))
        result.gps_latitude, result.gps_longitude = _gps_to_str(gps_ifd)
    except Exception:  # noqa: BLE001
        pass

    result.indicators = _build_indicators(result)
    return result


def _build_indicators(result: ExifResult) -> list[str]:
    indicators: list[str] = []
    software = result.software.lower()
    if software != NOT_AVAILABLE.lower() and result.software.strip():
        if any(hint in software for hint in _EDITOR_HINTS):
            # Known editing application - named attribution.
            indicators.append(
                "Image metadata contains an indicator associated with "
                f"image-processing software ({result.software})."
            )
        elif not _looks_like_camera_software(result.software, result.make,
                                             result.model):
            # Presence-based fallback: a Software tag that is not camera
            # firmware / a device OS names some application, so the image was
            # saved by software rather than written straight by a camera - an
            # indicator even for editors we do not recognise by name.
            indicators.append(
                "Image metadata names non-camera application software "
                f"({result.software}); the image was saved by an application, "
                "not written directly by a camera (indicator only)."
            )
    # Timestamp inconsistency (original later than modified is unusual).
    if (result.datetime_original != NOT_AVAILABLE
            and result.datetime != NOT_AVAILABLE
            and result.datetime_original != result.datetime):
        indicators.append(
            "DateTimeOriginal differs from DateTime - possible timestamp "
            "inconsistency (indicator only)."
        )
    return indicators


def exif_to_json(result: ExifResult) -> str:
    return json.dumps(result.raw, ensure_ascii=False, indent=2)
