"""Generate a controlled forensic test disk image WITH A REAL FILESYSTEM.

Unlike ``make_sample.py`` (which lays raw image blobs into unallocated space to
demonstrate carving), this builds a genuine FAT16 filesystem containing a
directory tree of documents and pictures, then deletes one file so ForenSight's
filesystem browser can show allocated *and* deleted entries - the FTK Imager /
Autopsy style workflow.

Run:  python sample_data/make_fs_image.py
Produces: sample_data/suspect_fs.img  (raw disk image, FAT16)
"""
from __future__ import annotations

import io
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")  # silence pyfatfs pkg_resources notice

from PIL import Image, ImageDraw  # noqa: E402

OUT = Path(__file__).resolve().parent / "suspect_fs.img"
SIZE = 24 * 1024 * 1024  # 24 MiB


def _picture(color, text, size=(480, 360)) -> bytes:
    img = Image.new("RGB", size, color)
    d = ImageDraw.Draw(img)
    for i in range(0, size[0], 24):
        d.line([(i, 0), (i, size[1])], fill=(255, 255, 255), width=1)
    d.rectangle([40, 40, size[0] - 40, size[1] - 40], outline=(0, 0, 0), width=3)
    d.text((60, 60), text, fill=(0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=88)
    return buf.getvalue()


def build() -> Path:
    from pyfatfs.PyFat import PyFat
    from pyfatfs.PyFatFS import PyFatFS

    # 1. Create a zeroed container and format it FAT16.
    with OUT.open("wb") as fh:
        fh.truncate(SIZE)
    pf = PyFat()
    pf.mkfs(str(OUT), fat_type=PyFat.FAT_TYPE_FAT16, size=SIZE, label="EVIDENCE")
    pf.close()

    # 2. Populate a directory tree.
    fs = PyFatFS(filename=str(OUT))
    try:
        fs.makedirs("/Users/suspect/Pictures", recreate=True)
        fs.makedirs("/Users/suspect/Documents", recreate=True)
        fs.makedirs("/System/Logs", recreate=True)

        fs.writebytes("/Users/suspect/Pictures/holiday.jpg",
                      _picture((60, 120, 200), "HOLIDAY 2026"))
        fs.writebytes("/Users/suspect/Pictures/family.jpg",
                      _picture((200, 120, 60), "FAMILY"))
        fs.writebytes("/Users/suspect/Pictures/receipt_scan.jpg",
                      _picture((90, 160, 90), "RECEIPT"))
        fs.writetext("/Users/suspect/Documents/notes.txt",
                     "Case notes.\nMeeting at 21:39.\nSee attached pictures.\n")
        fs.writetext("/Users/suspect/Documents/passwords.txt",
                     "email: user@example.com\nnote: change these later\n")
        fs.writetext("/System/Logs/system.log",
                     "boot ok\nuser login\nusb device connected\n" * 40)
        # This file will be marked deleted (0xE5) but its data left intact,
        # so ForenSight can recover it via the deleted directory entry.  It is
        # kept small (fits one cluster) so the deleted content recovers fully,
        # and uses an 8.3-compliant upper-case name (a single short directory
        # entry, no long-file-name records) so the on-disk patch is reliable.
        fs.writetext("/Users/suspect/Documents/SECRET.TXT",
                     "CONFIDENTIAL\r\nBank PIN: 4471\r\n"
                     "Meeting location: warehouse 7\r\n"
                     "Remember to delete this file!\r\n")
    finally:
        fs.close()

    # 3. Mark SECRET.TXT deleted in place (set first byte of its 8.3 directory
    #    entry to 0xE5) without freeing its cluster - a recoverable deletion.
    data = bytearray(OUT.read_bytes())
    short_name = b"SECRET  TXT"          # 8.3 field: 'SECRET'+2 spaces+'TXT'
    idx = data.find(short_name)
    if idx != -1:
        data[idx] = 0xE5
        OUT.write_bytes(data)
        deleted_note = "SECRET.TXT  (DELETED - fully recoverable)"
    else:
        deleted_note = "SECRET.TXT  (present)"

    print(f"Wrote filesystem image: {OUT} ({OUT.stat().st_size:,} bytes)")
    print("Filesystem: FAT16, label EVIDENCE")
    print("Tree:")
    print("  /Users/suspect/Pictures/  holiday.jpg, family.jpg, receipt_scan.jpg")
    print("  /Users/suspect/Documents/ notes.txt, passwords.txt")
    print(f"                            {deleted_note}")
    print("  /System/Logs/             system.log")
    return OUT


if __name__ == "__main__":
    build()
