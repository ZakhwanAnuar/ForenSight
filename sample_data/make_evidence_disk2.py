"""Build a second, more realistic forensic disk image from ``gambar/`` photos.

Differences from ``make_evidence_disk.py``:
  * natural, lived-in filenames (beach_sunset.jpg, family_dinner.jpg, ...),
  * format variety -- two photos re-encoded to PNG and one to BMP, so the
    carver and the Evidence "File Types" tree exercise JPEG + PNG + BMP,
  * a richer folder tree (DCIM, Pictures/Private, Documents, Downloads),
  * one private photo and one credentials note marked deleted (data intact).

Run:  python sample_data/make_evidence_disk2.py
Produces: evidence_usb.dd  (raw disk image, FAT16, in the project root)
"""
from __future__ import annotations

import io
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # project root
from make_evidence_disk import _documents, _texts, _short83  # noqa: E402
from PIL import Image  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
GAMBAR = ROOT / "gambar"
OUT = ROOT / "evidence_usb.dd"
SIZE = 128 * 1024 * 1024  # 128 MiB


def _reencode(src: Path, fmt: str, maxdim: int) -> bytes:
    """Re-encode a source photo to PNG/BMP, downscaled to keep the disk lean."""
    im = Image.open(src).convert("RGB")
    if max(im.size) > maxdim:
        im.thumbnail((maxdim, maxdim))
    buf = io.BytesIO()
    im.save(buf, fmt)
    return buf.getvalue()


def build() -> Path:
    from pyfatfs.PyFat import PyFat
    from pyfatfs.PyFatFS import PyFatFS

    exts = {".jpg", ".jpeg", ".png", ".bmp", ".gif"}
    images = sorted(p for p in GAMBAR.iterdir()
                    if p.is_file() and p.suffix.lower() in exts)
    jpgs = [p for p in images if p.suffix.lower() in (".jpg", ".jpeg")]
    others = [p for p in images if p.suffix.lower() in (".png", ".bmp", ".gif")]
    if not images:
        raise SystemExit(f"No images ({', '.join(sorted(exts))}) found in {GAMBAR}")

    # 1. Container + FAT16 format.
    with OUT.open("wb") as fh:
        fh.truncate(SIZE)
    pf = PyFat()
    pf.mkfs(str(OUT), fat_type=PyFat.FAT_TYPE_FAT16, size=SIZE, label="FIELDUSB")
    pf.close()

    manifest: list[str] = []
    fs = PyFatFS(filename=str(OUT))
    try:
        fs.makedirs("/DCIM/Camera", recreate=True)
        fs.makedirs("/Pictures/Private", recreate=True)
        fs.makedirs("/Documents", recreate=True)
        fs.makedirs("/Downloads", recreate=True)

        # Reserve one JPEG as the private/deleted photo (8.3 name for a reliable
        # delete patch); every other real image is written BYTE-FOR-BYTE so any
        # embedded metadata (EXIF, C2PA Content Credentials) is preserved.
        # Prefer an AI-generated photo so the killer demo works: a DELETED file,
        # invisible to the file system, carved back AND flagged as AI-made.
        from forensight import provenance_analyzer as _prov
        ai_jpgs = [p for p in jpgs if _prov.analyze_provenance(p).ai_generated]
        if ai_jpgs:
            private_src = ai_jpgs[0]
        elif jpgs:
            private_src = jpgs[len(jpgs) // 2]
        else:
            private_src = images[0]

        jpg_names = ["beach_sunset", "family_dinner", "car_park", "apartment_view",
                     "meeting_board", "receipt", "office_party", "roadtrip",
                     "sunset_pier", "harbour", "market", "festival"]
        pic_names = ["artwork", "poster", "screenshot", "meme", "wallpaper",
                     "scan", "render", "sketch"]

        # Live JPEGs -> camera roll.
        jn = 0
        for src in jpgs:
            if src is private_src:
                continue
            base = jpg_names[jn] if jn < len(jpg_names) else f"photo_{jn + 1:03d}"
            jn += 1
            fs.writebytes(f"/DCIM/Camera/{base}.jpg", src.read_bytes())
            manifest.append(f"/DCIM/Camera/{base}.jpg  (JPEG, live)")

        # Real PNG/BMP/GIF images -> Pictures, verbatim (metadata preserved).
        have = {".png": False, ".bmp": False}
        for i, src in enumerate(others):
            ext = src.suffix.lower()
            have[ext] = have.get(ext, False) or ext in have
            base = pic_names[i] if i < len(pic_names) else f"picture_{i + 1:03d}"
            fs.writebytes(f"/Pictures/{base}{ext}", src.read_bytes())
            manifest.append(f"/Pictures/{base}{ext}  ({ext[1:].upper()}, live)")

        # Guarantee format variety for the carver demo: if a PNG or BMP was not
        # supplied, synthesise one from a spare JPEG (re-encoded, so only used
        # for plain photos - never for a metadata-bearing original).
        spare = [p for p in jpgs if p is not private_src]
        if not have.get(".png") and spare:
            fs.writebytes("/Pictures/hiking_trail.png",
                          _reencode(spare[0], "PNG", 1600))
            manifest.append("/Pictures/hiking_trail.png  (PNG, synthesised)")
        if not have.get(".bmp") and spare:
            fs.writebytes("/Pictures/id_card.bmp",
                          _reencode(spare[-1], "BMP", 1000))
            manifest.append("/Pictures/id_card.bmp  (BMP, synthesised)")

        # One private JPEG -> will be deleted (8.3 name for a reliable patch).
        fs.writebytes("/Pictures/Private/PRIVATE.JPG", private_src.read_bytes())

        # Decoy documents + text files (reused generators).
        docs = _documents()
        fs.writebytes("/Downloads/MANUAL.PDF", docs.pop("MANUAL.PDF"))
        for name, data in docs.items():
            fs.writebytes(f"/Documents/{name}", data)
        texts = _texts()
        fs.writebytes("/README.TXT", texts.pop("README.TXT"))
        for name, data in texts.items():
            fs.writebytes(f"/Documents/{name}", data)
    finally:
        fs.close()

    # 2. Mark PRIVATE.JPG and PASSWD.TXT deleted in place (data intact).
    data = bytearray(OUT.read_bytes())
    deleted = []
    for label, field in (("PRIVATE.JPG", _short83("PRIVATE", "JPG")),
                         ("PASSWD.TXT", _short83("PASSWD", "TXT"))):
        idx = data.find(field)
        if idx != -1:
            data[idx] = 0xE5
            deleted.append(label)
    if deleted:
        OUT.write_bytes(data)

    print(f"Wrote disk image: {OUT} ({OUT.stat().st_size:,} bytes)")
    print("Filesystem: FAT16, volume label FIELDUSB")
    for line in manifest:
        print("  " + line)
    print("  /Pictures/Private/PRIVATE.JPG  (JPEG)")
    print("  /Documents/  INVOICE.PDF, STMT.PDF, LETTER.PDF, "
          "NOTES.TXT, PASSWD.TXT, TODO.TXT")
    print("  /Downloads/MANUAL.PDF     /README.TXT")
    if deleted:
        print(f"Marked DELETED (data intact, recoverable): {', '.join(deleted)}")
    return OUT


if __name__ == "__main__":
    build()
