"""Build a realistic forensic disk image from the photos in ``gambar/``.

Creates a genuine FAT16 disk image (real boot sector, FAT tables and directory
tree) containing:

  * every JPEG in ``gambar/`` under /DCIM/CAMERA (camera-style 8.3 filenames),
  * a handful of decoy PDF documents (invoice, statement, letter, manual), and
  * several text files (notes, credentials, to-do, readme),

then marks one photo and one note as *deleted* (directory entry flagged 0xE5)
while leaving their data on disk intact -- so ForenSight's signature carver
recovers them along with the live files.

Run:  python sample_data/make_evidence_disk.py
Produces: evidence_disk.dd  (raw disk image, FAT16, in the project root)
"""
from __future__ import annotations

import io
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")  # silence pyfatfs pkg_resources notice

ROOT = Path(__file__).resolve().parent.parent
GAMBAR = ROOT / "gambar"
OUT = ROOT / "evidence_disk.dd"
SIZE = 64 * 1024 * 1024  # 64 MiB -- roomy but fast to hash/carve


# --------------------------------------------------------------------------
# Decoy document generators (real PDF / text content so the disk looks lived-in)
# --------------------------------------------------------------------------
def _pdf(title: str, lines: list[str]) -> bytes:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import A4
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    c.setFont("Helvetica-Bold", 16)
    c.drawString(60, h - 70, title)
    c.setFont("Helvetica", 11)
    y = h - 110
    for line in lines:
        c.drawString(60, y, line)
        y -= 18
        if y < 70:
            c.showPage(); c.setFont("Helvetica", 11); y = h - 70
    c.showPage()
    c.save()
    return buf.getvalue()


def _documents() -> dict[str, bytes]:
    invoice = _pdf("INVOICE  #INV-2026-0043", [
        "Meridian Trading Sdn Bhd", "12 Jalan Perdana, 50480 Kuala Lumpur",
        "", "Bill To:  Client Services", "Date: 14 August 2026",
        "", "Item                         Qty      Unit (RM)     Amount (RM)",
        "Consulting services            40         180.00        7,200.00",
        "On-site support                 6         250.00        1,500.00",
        "", "                                    Subtotal        8,700.00",
        "                                    Tax (6%)           522.00",
        "                                    Total           RM 9,222.00",
        "", "Payment due within 30 days. Thank you for your business.",
    ])
    statement = _pdf("ACCOUNT STATEMENT", [
        "Maybank Berhad - Savings Account", "Account: 5142 88** **31",
        "Statement period: 01 Aug 2026 - 31 Aug 2026", "",
        "Date        Description                       Amount        Balance",
        "03 Aug      Salary credit                  +6,500.00     8,140.22",
        "07 Aug      Grocery - Jaya store             -212.55     7,927.67",
        "11 Aug      ATM withdrawal                   -800.00     7,127.67",
        "14 Aug      Invoice INV-2026-0043 paid     +9,222.00    16,349.67",
        "22 Aug      Transfer to 7712-outgoing      -3,000.00    13,349.67",
        "", "This is a computer-generated statement.",
    ])
    letter = _pdf("LETTER OF AGREEMENT", [
        "Date: 20 August 2026", "",
        "This agreement confirms the terms discussed on 19 August 2026",
        "between the parties regarding the transfer of the listed assets.",
        "", "1. All items are to be delivered by the agreed date.",
        "2. Payment shall be settled in full on receipt.",
        "3. Both parties agree to keep the terms confidential.",
        "", "Signed,", "", "____________________        ____________________",
        "Party A                     Party B",
    ])
    manual = _pdf("QUICK START GUIDE", [
        "Model DX-220 Digital Camera", "",
        "1. Insert a charged battery and a memory card.",
        "2. Press and hold POWER for two seconds.",
        "3. Photos are stored under DCIM/CAMERA on the card.",
        "4. Connect via USB to copy files to a computer.",
        "", "Troubleshooting: if the card is not detected, reformat as FAT.",
    ])
    return {
        "INVOICE.PDF": invoice,
        "STMT.PDF": statement,
        "LETTER.PDF": letter,
        "MANUAL.PDF": manual,
    }


def _texts() -> dict[str, bytes]:
    notes = ("Meeting notes - 19 Aug\r\n"
             "- confirm delivery window\r\n"
             "- photos are on the camera card (DCIM)\r\n"
             "- send the signed letter before Friday\r\n")
    passwd = ("email: user@example.com\r\n"
              "router admin: admin / changeme\r\n"
              "note: rotate these credentials\r\n")
    todo = ("TODO\r\n"
            "[ ] back up the picture folder\r\n"
            "[x] pay invoice INV-2026-0043\r\n"
            "[ ] delete the old photos\r\n")
    readme = ("EVIDENCE DISK\r\n"
              "Removable media imaged for review.\r\n"
              "Contains camera photos and personal documents.\r\n")
    return {
        "NOTES.TXT": notes.encode(),
        "PASSWD.TXT": passwd.encode(),
        "TODO.TXT": todo.encode(),
        "README.TXT": readme.encode(),
    }


def _short83(field: str, ext: str) -> bytes:
    """Return the raw 11-byte 8.3 directory field, e.g. 'IMG_0007JPG'."""
    return field.ljust(8).encode() + ext.ljust(3).encode()


def build() -> Path:
    from pyfatfs.PyFat import PyFat
    from pyfatfs.PyFatFS import PyFatFS

    photos = sorted(p for p in GAMBAR.glob("*.jpg"))
    if not photos:
        raise SystemExit(f"No .jpg files found in {GAMBAR}")

    # 1. Zeroed container, formatted FAT16.
    with OUT.open("wb") as fh:
        fh.truncate(SIZE)
    pf = PyFat()
    pf.mkfs(str(OUT), fat_type=PyFat.FAT_TYPE_FAT16, size=SIZE, label="EVIDENCE")
    pf.close()

    # 2. Populate a realistic directory tree (all names 8.3 -> no LFN records).
    fs = PyFatFS(filename=str(OUT))
    image_names: list[str] = []
    try:
        fs.makedirs("/DCIM/CAMERA", recreate=True)
        fs.makedirs("/DOCS", recreate=True)
        fs.makedirs("/DOWNLOAD", recreate=True)

        for i, src in enumerate(photos, start=1):
            name = f"IMG_{i:04d}.JPG"          # e.g. IMG_0001.JPG
            image_names.append(name)
            fs.writebytes(f"/DCIM/CAMERA/{name}", src.read_bytes())

        docs = _documents()
        # one manual lives in Downloads, the rest under Documents
        fs.writebytes("/DOWNLOAD/MANUAL.PDF", docs.pop("MANUAL.PDF"))
        for name, data in docs.items():
            fs.writebytes(f"/DOCS/{name}", data)

        texts = _texts()
        fs.writebytes("/README.TXT", texts.pop("README.TXT"))
        for name, data in texts.items():
            fs.writebytes(f"/DOCS/{name}", data)
    finally:
        fs.close()

    # 3. Mark one photo and one note as DELETED in place (first byte of the 8.3
    #    directory entry -> 0xE5) while leaving the file data intact, so the
    #    carver still recovers the photo and the bytes remain on the medium.
    data = bytearray(OUT.read_bytes())
    deleted = []
    victim_img = image_names[len(image_names) // 2] if image_names else ""
    for label, field in ((victim_img, _short83(victim_img.split(".")[0], "JPG")),
                         ("PASSWD.TXT", _short83("PASSWD", "TXT"))):
        if not label:
            continue
        idx = data.find(field)
        if idx != -1:
            data[idx] = 0xE5
            deleted.append(label)
    if deleted:
        OUT.write_bytes(data)

    # 4. Manifest.
    total_photos = len(image_names)
    print(f"Wrote disk image: {OUT} ({OUT.stat().st_size:,} bytes)")
    print("Filesystem: FAT16, volume label EVIDENCE")
    print("Tree:")
    print(f"  /DCIM/CAMERA/   {total_photos} photos "
          f"({image_names[0]} .. {image_names[-1]})")
    print("  /DOCS/          INVOICE.PDF, STMT.PDF, LETTER.PDF, "
          "NOTES.TXT, PASSWD.TXT, TODO.TXT")
    print("  /DOWNLOAD/      MANUAL.PDF")
    print("  /README.TXT")
    if deleted:
        print(f"Marked DELETED (data intact, recoverable): {', '.join(deleted)}")
    return OUT


if __name__ == "__main__":
    build()
