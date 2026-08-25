"""Filesystem (Sleuth Kit) parsing tests.

Skipped automatically when pytsk3 or the sample filesystem image is unavailable,
so the suite still passes in a minimal environment.
"""
from pathlib import Path

import pytest

from forensight import filesystem

IMG = Path(__file__).resolve().parent.parent / "sample_data" / "suspect_fs.img"

pytestmark = pytest.mark.skipif(
    not filesystem.HAVE_TSK or not IMG.exists(),
    reason="pytsk3 or sample filesystem image not available",
)


def test_open_and_detect_volume():
    di = filesystem.DiskImage(str(IMG))
    try:
        assert di.volumes
        assert "FAT" in di.volumes[0].fs_type
    finally:
        di.close()


def test_directory_listing():
    di = filesystem.DiskImage(str(IMG))
    try:
        off = di.volumes[0].offset
        names = {e.name for e in di.list_dir(off, "/Users/suspect/Documents")}
        assert "notes.txt" in names
        pics = di.list_dir(off, "/Users/suspect/Pictures")
        assert any(e.name.endswith(".jpg") for e in pics)
    finally:
        di.close()


def test_deleted_file_is_recoverable():
    di = filesystem.DiskImage(str(IMG))
    try:
        off = di.volumes[0].offset
        deleted = [e for e in di.list_dir(off, "/Users/suspect/Documents")
                   if e.is_deleted]
        assert deleted, "expected a deleted directory entry"
        data = di.read_file(off, deleted[0].inode, deleted[0].size)
        assert b"CONFIDENTIAL" in data
    finally:
        di.close()


def test_read_allocated_image():
    di = filesystem.DiskImage(str(IMG))
    try:
        off = di.volumes[0].offset
        jpg = next(e for e in di.list_dir(off, "/Users/suspect/Pictures")
                   if e.name.endswith(".jpg") and not e.is_deleted)
        data = di.read_file(off, jpg.inode, jpg.size)
        assert data[:3] == b"\xFF\xD8\xFF"  # JPEG signature
        assert len(data) == jpg.size
    finally:
        di.close()
