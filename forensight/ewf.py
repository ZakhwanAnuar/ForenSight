"""EnCase/EWF (.E01) detection.

ForenSight reads RAW (dd/img) images.  An E01 is a container it cannot parse as
a filesystem, so the Add Data Source flow detects one and warns the examiner
(carving still works on the bytes, but allocation degrades to "Unallocated").
The recommended path is to convert to raw first with libewf's ``ewfexport``.
"""
from __future__ import annotations

from pathlib import Path

# EWF containers by extension and by 3-byte magic ("EVF" / "LVF").
_EWF_EXTS = {".e01", ".ex01", ".s01", ".l01", ".lx01", ".e02"}


def is_ewf(path: str | Path) -> bool:
    """True if ``path`` is an EnCase/EWF container (by extension or magic bytes)."""
    p = Path(path)
    if p.suffix.lower() in _EWF_EXTS:
        return True
    try:
        with p.open("rb") as fh:
            return fh.read(3) in (b"EVF", b"LVF")
    except OSError:
        return False
