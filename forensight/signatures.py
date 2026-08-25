"""Single source of truth for detection signatures.

Editing-application names live here so the two consumers can never drift apart:
  * exif_engine  - matches the EXIF "Software" tag (case-insensitive substrings)
  * provenance_analyzer - scans the file's metadata region (case-sensitive bytes)

Camera/phone maker and OS markers also live here, used by exif_engine to tell
device firmware from an editing application.
"""
from __future__ import annotations

# Editing applications whose name appears in metadata.  Ordered SPECIFIC-FIRST
# because the byte scan returns the first match (e.g. "Photoshop Express" must
# precede "Photoshop").  Each entry is (alias_in_metadata, canonical_name).
EDITOR_SIGNATURES: tuple[tuple[str, str], ...] = (
    # mobile / web editors
    ("MeituPic", "Meitu"), ("Meitu", "Meitu"),
    ("CapCut", "CapCut"), ("JianYing", "CapCut (JianYing)"),
    ("HYPIC", "Hypic"), ("Hypic", "Hypic"),
    ("BeautyPlus", "BeautyPlus"), ("AirBrush", "AirBrush"),
    ("Facetune", "Facetune"), ("PicsArt", "PicsArt"), ("Picsart", "PicsArt"),
    ("Snapseed", "Snapseed"), ("VSCO", "VSCO"), ("InShot", "InShot"),
    ("Fotor", "Fotor"), ("Pixlr", "Pixlr"), ("Canva", "Canva"),
    ("PhotoRoom", "PhotoRoom"), ("Remini", "Remini"), ("B612", "B612"),
    ("PhotoDirector", "PhotoDirector"), ("Prisma", "Prisma"),
    # Adobe (specific variants before the generic "Photoshop")
    ("Photoshop Express", "Adobe Express"), ("Adobe Express", "Adobe Express"),
    ("Photoshop Elements", "Adobe Photoshop Elements"),
    ("Adobe Photoshop", "Adobe Photoshop"), ("Photoshop", "Adobe Photoshop"),
    ("Lightroom", "Adobe Lightroom"),
    # desktop editors
    ("GIMP", "GIMP"), ("Pixelmator", "Pixelmator"),
    ("Affinity Photo", "Affinity Photo"), ("paint.net", "Paint.NET"),
    ("Corel", "Corel"), ("Luminar", "Luminar"), ("ACDSee", "ACDSee"),
    ("PhotoScape", "PhotoScape"), ("FastStone", "FastStone"),
    ("IrfanView", "IrfanView"), ("Photopea", "Photopea"), ("Krita", "Krita"),
)


def editor_bytes() -> tuple[tuple[bytes, str], ...]:
    """(needle_bytes, canonical_name) for the case-sensitive metadata scan."""
    return tuple((alias.encode(), name) for alias, name in EDITOR_SIGNATURES)


def editor_hints_lower() -> tuple[str, ...]:
    """Lower-case alias substrings for matching an EXIF Software string."""
    return tuple(alias.lower() for alias, _ in EDITOR_SIGNATURES)


# Camera/phone makers and OS/firmware markers: a Software tag that looks like
# device firmware, a device OS, or echoes the maker is NOT treated as editing.
CAMERA_MAKERS: tuple[str, ...] = (
    "apple", "iphone", "ipad", "samsung", "galaxy", "google", "pixel", "huawei",
    "honor", "xiaomi", "redmi", "poco", "oppo", "vivo", "oneplus", "realme",
    "sony", "canon", "nikon", "fujifilm", "fuji", "panasonic", "lumix",
    "olympus", "om system", "leica", "pentax", "ricoh", "gopro", "dji",
    "motorola", "nokia", "lg", "htc", "asus", "zte", "tecno", "infinix",
)
CAMERA_OS_MARKERS: tuple[str, ...] = (
    "ios", "android", "hdr+", "harmonyos", "coloros", "miui", "hyperos",
    "oneui", "one ui", "emui", "oxygenos", "funtouch", "firmware", "build",
)
