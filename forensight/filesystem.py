"""Disk-image filesystem parsing via The Sleuth Kit (pytsk3).

This is the FTK Imager / Autopsy-style capability: open a raw disk image
(dd/img/raw/001), an Expert Witness image (E01) or a VMDK, enumerate its
volumes, walk the real filesystem tree (allocated *and* deleted entries), read
file content and read per-file metadata (MAC timestamps, size, inode).

The heavy lifting is done by TSK - the same engine Autopsy uses.  All three
optional format libraries degrade gracefully: if a library is missing, only
that container format is unavailable and a clear message is produced.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import pytsk3
    HAVE_TSK = True
except Exception:  # noqa: BLE001
    pytsk3 = None
    HAVE_TSK = False

try:
    import pyewf
    HAVE_EWF = True
except Exception:  # noqa: BLE001
    pyewf = None
    HAVE_EWF = False

try:
    import pyvmdk
    HAVE_VMDK = True
except Exception:  # noqa: BLE001
    pyvmdk = None
    HAVE_VMDK = False

RAW_EXTS = {".dd", ".img", ".raw", ".001", ".bin", ".iso", ".dmp"}
EWF_EXTS = {".e01", ".ex01", ".s01"}
VMDK_EXTS = {".vmdk"}
SUPPORTED_EXTS = RAW_EXTS | EWF_EXTS | VMDK_EXTS


class FileSystemError(Exception):
    """Raised for recoverable disk-image parsing problems (shown to the user)."""


# ---------------------------------------------------------------------------
# Img_Info wrappers for container formats that are not plain raw images
# ---------------------------------------------------------------------------
if HAVE_TSK and HAVE_EWF:
    class _EwfImgInfo(pytsk3.Img_Info):
        def __init__(self, handle):
            self._handle = handle
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def close(self):
            self._handle.close()

        def read(self, offset, size):
            self._handle.seek(offset)
            return self._handle.read(size)

        def get_size(self):
            return self._handle.get_media_size()

if HAVE_TSK and HAVE_VMDK:
    class _VmdkImgInfo(pytsk3.Img_Info):
        def __init__(self, handle):
            self._handle = handle
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def close(self):
            self._handle.close()

        def read(self, offset, size):
            self._handle.seek(offset)
            return self._handle.read(size)

        def get_size(self):
            return self._handle.get_media_size()


def _open_img(path: str):
    ext = Path(path).suffix.lower()
    if ext in EWF_EXTS:
        if not HAVE_EWF:
            raise FileSystemError("E01 support requires 'libewf-python' (pyewf).")
        names = pyewf.glob(path)
        handle = pyewf.handle()
        handle.open(names)
        return _EwfImgInfo(handle)
    if ext in VMDK_EXTS:
        if not HAVE_VMDK:
            raise FileSystemError("VMDK support requires 'libvmdk-python' (pyvmdk).")
        handle = pyvmdk.handle()
        handle.open(path)
        handle.open_extent_data_files()
        return _VmdkImgInfo(handle)
    # Raw / dd / img / 001 / bin / iso.
    return pytsk3.Img_Info(path)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass
class Volume:
    addr: int
    description: str
    offset: int          # byte offset of the filesystem within the image
    fs_type: str


@dataclass
class FSEntry:
    name: str
    path: str            # full path within the filesystem
    is_dir: bool
    is_deleted: bool
    size: int
    inode: Optional[int]
    modified: str
    accessed: str
    changed: str
    created: str
    is_virtual: bool = False   # TSK pseudo-files ($MBR, $FAT1, $OrphanFiles…)
    mtime_epoch: Optional[int] = None  # raw modified time for timeline sorting


def _fmt_time(epoch: Optional[int]) -> str:
    if not epoch:
        return "N/A"
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return "N/A"


_FS_TYPE_NAMES = {}
if HAVE_TSK:
    _FS_TYPE_NAMES = {
        pytsk3.TSK_FS_TYPE_NTFS: "NTFS",
        pytsk3.TSK_FS_TYPE_FAT12: "FAT12",
        pytsk3.TSK_FS_TYPE_FAT16: "FAT16",
        pytsk3.TSK_FS_TYPE_FAT32: "FAT32",
        pytsk3.TSK_FS_TYPE_EXFAT: "exFAT",
        pytsk3.TSK_FS_TYPE_EXT2: "Ext2",
        pytsk3.TSK_FS_TYPE_EXT3: "Ext3",
        pytsk3.TSK_FS_TYPE_EXT4: "Ext4",
        pytsk3.TSK_FS_TYPE_HFS: "HFS+",
        pytsk3.TSK_FS_TYPE_ISO9660: "ISO9660",
    }


def _fs_type_name(fs) -> str:
    return _FS_TYPE_NAMES.get(fs.info.ftype, str(fs.info.ftype))


class DiskImage:
    """An opened disk image with parsed volumes and a live TSK handle."""

    def __init__(self, path: str):
        if not HAVE_TSK:
            raise FileSystemError(
                "Filesystem browsing requires 'pytsk3' (The Sleuth Kit).\n"
                "Install it with:  pip install pytsk3")
        self.path = path
        if not Path(path).exists():
            raise FileSystemError(f"Image not found: {path}")
        try:
            self._img = _open_img(path)
        except FileSystemError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise FileSystemError(f"Could not open image:\n{exc}") from exc
        self.volumes: list[Volume] = []
        self._fs_cache: dict[int, object] = {}
        self._detect_volumes()

    # -- volume detection -------------------------------------------------
    def _detect_volumes(self):
        try:
            vs = pytsk3.Volume_Info(self._img)
            block = vs.info.block_size or 512
            for part in vs:
                if not (part.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC):
                    continue
                offset = part.start * block
                try:
                    fs = pytsk3.FS_Info(self._img, offset=offset)
                except Exception:  # noqa: BLE001
                    continue  # partition without a recognised filesystem
                desc = part.desc.decode("utf-8", "replace") if isinstance(part.desc, bytes) else str(part.desc)
                self.volumes.append(
                    Volume(part.addr, f"{desc} ({_fs_type_name(fs)})", offset,
                           _fs_type_name(fs)))
                self._fs_cache[offset] = fs
        except Exception:  # noqa: BLE001 - no volume system / partition table
            pass

        if not self.volumes:
            try:
                fs = pytsk3.FS_Info(self._img, offset=0)
            except Exception as exc:  # noqa: BLE001
                raise FileSystemError(
                    "No recognised partition or filesystem was found in this "
                    f"image.\n{exc}") from exc
            self.volumes.append(
                Volume(0, f"Filesystem ({_fs_type_name(fs)})", 0, _fs_type_name(fs)))
            self._fs_cache[0] = fs

    # -- filesystem access ------------------------------------------------
    def _fs(self, offset: int):
        fs = self._fs_cache.get(offset)
        if fs is None:
            fs = pytsk3.FS_Info(self._img, offset=offset)
            self._fs_cache[offset] = fs
        return fs

    def list_dir(self, offset: int, path: str) -> list[FSEntry]:
        """List entries of a directory (files, sub-dirs, deleted entries)."""
        fs = self._fs(offset)
        try:
            directory = fs.open_dir(path=path)
        except Exception as exc:  # noqa: BLE001
            raise FileSystemError(f"Could not open directory '{path}':\n{exc}") from exc

        entries: list[FSEntry] = []
        base = path.rstrip("/")
        for entry in directory:
            if entry.info.name.name in (b".", b".."):
                continue
            name = entry.info.name.name.decode("utf-8", "replace")
            meta = entry.info.meta
            # A DELETED entry often has entry.info.meta == None, but its directory
            # record still points at the (now-unallocated) metadata via meta_addr.
            # Resolve it (as Autopsy does) so deleted files keep their size, inode,
            # timestamps and data runs and can be recovered / classified Deleted.
            if meta is None:
                ma = entry.info.name.meta_addr
                if ma:
                    try:
                        meta = fs.open_meta(inode=ma).info.meta
                    except Exception:  # noqa: BLE001 - meta genuinely gone
                        meta = None
            is_dir = entry.info.name.type == pytsk3.TSK_FS_NAME_TYPE_DIR
            is_deleted = bool(entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
            is_virtual = name.startswith("$")
            size = meta.size if meta else 0
            inode = meta.addr if meta else None
            full = f"{base}/{name}"
            entries.append(FSEntry(
                name=name, path=full, is_dir=is_dir, is_deleted=is_deleted,
                size=size, inode=inode,
                modified=_fmt_time(meta.mtime if meta else None),
                accessed=_fmt_time(meta.atime if meta else None),
                changed=_fmt_time(meta.ctime if meta else None),
                created=_fmt_time(meta.crtime if meta else None),
                is_virtual=is_virtual,
                mtime_epoch=(meta.mtime if meta else None),
            ))
        # Directories first, then files; each alphabetically.
        entries.sort(key=lambda e: (not e.is_dir, e.name.lower()))
        return entries

    def walk_volume(self, offset: int, root: str = "/", max_entries: int = 300000):
        """Recursively yield every FSEntry under ``root`` in a volume.

        Used by the disk-analysis ingest to build the full file inventory.
        Deleted and virtual directories are not descended into, and visited
        inodes are tracked to avoid loops.
        """
        stack = [root]
        visited: set[int] = set()
        count = 0
        while stack:
            path = stack.pop()
            try:
                entries = self.list_dir(offset, path)
            except FileSystemError:
                continue
            for entry in entries:
                yield entry
                count += 1
                if count >= max_entries:
                    return
                if (entry.is_dir and not entry.is_virtual and not entry.is_deleted
                        and entry.inode is not None and entry.inode not in visited):
                    visited.add(entry.inode)
                    stack.append(entry.path)

    def iter_data_extents(self, offset: int):
        """Yield (start_byte, end_byte, is_deleted, path) for every file's data
        runs, as ABSOLUTE byte offsets within the disk image.

        This is what enables offset-based allocation: a carved file's byte offset
        is matched against these ranges to decide whether it lies in a live
        file's clusters (Allocated), a deleted file's clusters (Deleted), or
        neither (Unallocated).  Works for FAT and NTFS; deleted files whose
        metadata (data runs) has been wiped simply produce no extent, so their
        carved data is honestly reported as Unallocated.
        """
        fs = self._fs(offset)
        block = fs.info.block_size or 512
        data_types = {pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA,
                      pytsk3.TSK_FS_ATTR_TYPE_DEFAULT}
        sparse = pytsk3.TSK_FS_ATTR_RUN_FLAG_SPARSE
        filler = getattr(pytsk3, "TSK_FS_ATTR_RUN_FLAG_FILLER", 0)
        for entry in self.walk_volume(offset):
            if entry.is_dir or entry.is_virtual or entry.inode is None:
                continue
            try:
                f = fs.open_meta(inode=entry.inode)
            except Exception:  # noqa: BLE001 - unreadable inode
                continue
            try:
                for attr in f:
                    if attr.info.type not in data_types:
                        continue
                    for run in attr:
                        if run.flags & (sparse | filler):
                            continue
                        if run.len <= 0:
                            continue
                        start = offset + run.addr * block
                        end = start + run.len * block
                        yield (start, end, entry.is_deleted, entry.path)
            except Exception:  # noqa: BLE001 - odd attribute layout
                continue

    def read_file(self, offset: int, inode: int, size: int) -> bytes:
        """Read a file's content by inode (works for deleted files too)."""
        fs = self._fs(offset)
        try:
            f = fs.open_meta(inode=inode)
        except Exception as exc:  # noqa: BLE001
            raise FileSystemError(f"Could not open inode {inode}:\n{exc}") from exc
        data = bytearray()
        chunk = 1024 * 1024
        pos = 0
        size = size or 0
        while pos < size:
            want = min(chunk, size - pos)
            try:
                buf = f.read_random(pos, want)
            except Exception:  # noqa: BLE001 - sparse / unreadable region
                break
            if not buf:
                break
            data.extend(buf)
            pos += len(buf)
        return bytes(data)

    def close(self):
        try:
            self._img.close()
        except Exception:  # noqa: BLE001
            pass


def availability_note() -> str:
    """Human-readable summary of which container formats are available."""
    parts = ["Raw/dd/img: " + ("yes" if HAVE_TSK else "no (pytsk3 missing)")]
    parts.append("E01: " + ("yes" if HAVE_EWF else "no (libewf-python missing)"))
    parts.append("VMDK: " + ("yes" if HAVE_VMDK else "no (libvmdk-python missing)"))
    return " | ".join(parts)
