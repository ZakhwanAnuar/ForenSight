"""Classify recovered images as Allocated (live) / Deleted / Unallocated.

Signature carving alone cannot tell a live file from a deleted one - it just
reads raw bytes.  To distinguish them we parse the data source's filesystem (via
The Sleuth Kit) and record, for every file, the ABSOLUTE byte ranges its data
occupies on disk (its cluster "data runs"), together with whether that file is
live or a deleted directory entry.  A carved image is then classified by the
byte OFFSET at which it was found:

  * offset lies in a live file's clusters     -> "Allocated"
  * offset lies in a deleted file's clusters  -> "Deleted"
  * offset lies in neither                    -> "Unallocated" (carved from free
                                                 space; cannot be attributed)
  * filesystem not parseable                  -> "Unknown"

Offset-based matching is the method Autopsy/TSK use.  It works on both FAT and
NTFS and, unlike a size/hash heuristic, is unaffected by carved-vs-recorded size
differences or by different files sharing identical headers.

Honest limitation: a deleted file whose metadata (data runs) has been wiped -
common on NTFS, where the MFT record is reused - produces no extent, so its
carved data is reported "Unallocated".  The data is still recovered; it simply
cannot be *attributed* to the deletion once the metadata linking it is gone.  No
tool can do otherwise.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from .logging_config import get_logger

ALLOCATED = "Allocated"
DELETED = "Deleted"
UNALLOCATED = "Unallocated"
UNKNOWN = "Unknown"


def build_allocation_map(source_path: str | Path) -> Optional[list]:
    """Return a list of on-disk data extents ``[(start, end, is_deleted), ...]``
    (absolute byte offsets), or None when the image has no parseable filesystem.

    An empty list is a valid result (a filesystem with no addressable file data);
    callers must test for ``None`` explicitly, not truthiness.
    """
    logger = get_logger()
    try:
        from . import filesystem
        if not filesystem.HAVE_TSK:
            return None
        di = filesystem.DiskImage(str(source_path))
    except Exception:  # noqa: BLE001 - not a filesystem image / TSK error
        return None

    extents: list[tuple[int, int, bool]] = []
    try:
        for vol in di.volumes:
            for start, end, is_deleted, _path in di.iter_data_extents(vol.offset):
                if end > start:
                    extents.append((start, end, bool(is_deleted)))
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            di.close()
        except Exception:  # noqa: BLE001
            pass

    live = sum(1 for _s, _e, d in extents if not d)
    deleted = sum(1 for _s, _e, d in extents if d)
    logger.info("Allocation map: %d extents (%d live, %d deleted)",
                len(extents), live, deleted)
    return extents


def classify(source_offset: int, alloc_map: Optional[list]) -> str:
    """Classify a carved file by the byte offset at which it was found.

    On overlap (a stale deleted extent covering a cluster now owned by a live
    file), the LIVE owner wins - the cluster is currently allocated.
    """
    if alloc_map is None:
        return UNKNOWN
    found_deleted = False
    for start, end, is_deleted in alloc_map:
        if start <= source_offset < end:
            if not is_deleted:
                return ALLOCATED          # live owner takes precedence
            found_deleted = True
    return DELETED if found_deleted else UNALLOCATED
