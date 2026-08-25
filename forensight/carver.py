"""Signature-based file carving engine (spec sections 19-27).

The module has two layers:

* :func:`scan_source` / :func:`iter_headers` - pure-Python, Qt-free carving
  logic that is fully unit-testable.
* :class:`CarverWorker` - a ``QThread`` that drives ``scan_source`` off the GUI
  thread and emits progress/results through Qt signals.

Recovered files are described as "recovered from raw/unallocated image space by
signature-based carving" (spec section 27) - no filesystem deletion metadata is
claimed.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Optional

from . import config
from .hash_utils import sha256_bytes
from .utils import format_hex_offset, utc_now_iso

RECOVERY_METHOD = "Signature-based carving (raw/unallocated space)"

# Header patterns paired with their format label.
_HEADER_PATTERNS = [
    (config.JPEG_HEADER, "JPEG"),
    (config.PNG_HEADER, "PNG"),
    (config.BMP_HEADER, "BMP"),
    (config.GIF_HEADERS[0], "GIF"),
    (config.GIF_HEADERS[1], "GIF"),
]
_MAX_PATTERN_LEN = max(len(p) for p, _ in _HEADER_PATTERNS)

# A genuine JPEG's 4th byte (right after FF D8 FF) must be a legal marker.  The
# bare 3-byte FF D8 FF signature matches constantly inside executable code, 0xFF
# fill regions and compressed data, so validating this byte removes almost all
# false positives (examiner finding: 165/165 carved JPEGs were false positives).
_JPEG_VALID_MARKERS = (
    set(range(0xE0, 0xF0))                       # APP0-APP15 (JFIF/EXIF/etc.)
    | {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,  # SOF markers
       0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
    | {0xC4, 0xC8, 0xCC}                          # DHT / JPG / DAC
    | {0xDB, 0xDA, 0xDC, 0xDD, 0xDE, 0xDF, 0xFE}  # DQT/SOS/DNL/DRI/DHP/EXP/COM
)


def _header_extra_ok(buffer: bytes, i: int, fmt: str):
    """Validate the bytes just past a header to reject false positives.

    Returns True (accept), False (reject), or None (not enough bytes in this
    buffer yet - re-evaluate next chunk via the overlap carry).
    """
    if fmt == "JPEG":
        if i + 4 > len(buffer):
            return None
        return buffer[i + 3] in _JPEG_VALID_MARKERS
    if fmt == "PNG":
        # A real PNG signature is followed by the IHDR chunk: 00 00 00 0D "IHDR".
        if i + 16 > len(buffer):
            return None
        return (buffer[i + 8:i + 12] == b"\x00\x00\x00\x0D"
                and buffer[i + 12:i + 16] == b"IHDR")
    return True


@dataclass
class CarveControl:
    """Cooperative pause/cancel flags shared with a worker thread."""

    _cancel: threading.Event = field(default_factory=threading.Event)
    _pause: threading.Event = field(default_factory=threading.Event)

    def cancel(self) -> None:
        self._cancel.set()
        self._pause.clear()

    def pause(self) -> None:
        self._pause.set()

    def resume(self) -> None:
        self._pause.clear()

    def is_cancelled(self) -> bool:
        return self._cancel.is_set()

    def wait_if_paused(self) -> None:
        while self._pause.is_set() and not self._cancel.is_set():
            self._cancel.wait(0.1)


@dataclass
class CarvedFile:
    """A single carved candidate before database insertion."""

    file_format: str
    source_offset: int
    source_offset_hex: str
    data: bytes
    file_name: str


def _find_all(buffer: bytes, pattern: bytes, start: int = 0) -> Iterator[int]:
    idx = buffer.find(pattern, start)
    while idx != -1:
        yield idx
        idx = buffer.find(pattern, idx + 1)


def iter_headers(
    fh,
    formats: set[str],
    chunk_size: int = config.CHUNK_SIZE,
    overlap: int = config.OVERLAP_SIZE,
    progress_cb: Optional[Callable[[int], None]] = None,
    control: Optional[CarveControl] = None,
) -> Iterator[tuple[int, str]]:
    """Yield ``(absolute_offset, format)`` for every header signature found.

    Uses 1 MiB chunked reads with an overlap buffer so signatures that straddle
    a chunk boundary are still detected (spec section 21).  Duplicate reports
    from the overlap region are removed via a ``seen`` set.
    """
    patterns = [(p, f) for p, f in _HEADER_PATTERNS if f in formats]
    seen: set[tuple[int, str]] = set()
    carry = b""
    carry_base = 0          # absolute offset of the first byte of ``carry``
    position = 0            # absolute offset of the next byte to read

    while True:
        if control is not None:
            control.wait_if_paused()
            if control.is_cancelled():
                return
        chunk = fh.read(chunk_size)
        if not chunk:
            break
        buffer = carry + chunk
        base = carry_base if carry else position
        for pattern, fmt in patterns:
            plen = len(pattern)
            for i in _find_all(buffer, pattern):
                if i + plen > len(buffer):
                    continue  # incomplete at buffer end; caught next round
                extra = _header_extra_ok(buffer, i, fmt)
                if extra is None:
                    continue  # need more bytes; caught next round via carry
                if not extra:
                    continue  # false-positive signature rejected
                abs_off = base + i
                key = (abs_off, fmt)
                if key not in seen:
                    seen.add(key)
                    yield abs_off, fmt
        position += len(chunk)
        if progress_cb is not None:
            progress_cb(position)
        # retain the trailing bytes so boundary-spanning headers are caught.
        carry = buffer[-(overlap):] if len(buffer) >= overlap else buffer
        carry_base = position - len(carry)


def _find_jpeg_end(window: bytes) -> Optional[int]:
    """Locate the end of a JPEG by walking its segment markers.

    Parsing markers (rather than searching for the first ``FF D9``) is required
    so that a JPEG carrying an embedded EXIF thumbnail - itself a nested
    ``FF D8 ... FF D9`` JPEG inside the APP1 segment - is not truncated at the
    thumbnail's end marker.  Falls back to a plain footer search on any parse
    problem.
    """
    n = len(window)
    i = 2  # skip the leading FF D8 (SOI)
    try:
        while i < n - 1:
            if window[i] != 0xFF:
                nxt = window.find(b"\xFF", i)
                if nxt == -1:
                    break
                i = nxt
            while i < n and window[i] == 0xFF:  # skip fill bytes
                i += 1
            if i >= n:
                break
            marker = window[i]
            i += 1
            if marker == 0xD9:                  # EOI
                return i
            if marker == 0x01 or 0xD0 <= marker <= 0xD8:
                continue                        # standalone markers (no length)
            if i + 1 >= n:
                break
            seg_len = (window[i] << 8) | window[i + 1]
            if seg_len < 2:
                break
            if marker == 0xDA:                  # SOS - entropy data follows
                j = i + seg_len
                found = False
                while j < n - 1:
                    if window[j] == 0xFF:
                        b = window[j + 1]
                        if b == 0x00 or 0xD0 <= b <= 0xD7:
                            j += 2              # stuffed byte / restart marker
                            continue
                        i = j                   # next real marker
                        found = True
                        break
                    j += 1
                if not found:
                    break
                continue
            i += seg_len
    except Exception:  # noqa: BLE001 - malformed JPEG; use fallback
        pass
    end = window.find(config.JPEG_FOOTER, 3)
    return end + len(config.JPEG_FOOTER) if end != -1 else None


def _find_png_end(window: bytes) -> Optional[int]:
    end = window.find(config.PNG_IEND, len(config.PNG_HEADER))
    return end + len(config.PNG_IEND) if end != -1 else None


def _find_gif_end(window: bytes) -> Optional[int]:
    end = window.rfind(config.GIF_TRAILER)
    return end + len(config.GIF_TRAILER) if end > 6 else None


def _valid_bmp_size(window: bytes) -> Optional[int]:
    """Return a BMP's declared size only if the header is genuinely valid.

    The 2-byte ``BM`` signature yields many false positives in high-entropy
    data, so this validates the reserved field (zero in real BMPs), a known DIB
    header size and a sane pixel-data offset before accepting the candidate
    (spec section 20).  Returns None to reject the false positive.
    """
    if len(window) < 26:
        return None
    declared = int.from_bytes(window[2:6], "little")
    reserved = window[6:10]
    pixel_offset = int.from_bytes(window[10:14], "little")
    dib_size = int.from_bytes(window[14:18], "little")
    if reserved != b"\x00\x00\x00\x00":
        return None
    if dib_size not in (12, 40, 52, 56, 64, 108, 124):
        return None
    if not (26 <= pixel_offset <= declared):
        return None
    if not (26 < declared <= len(window)):
        return None
    return declared


def _decodes_as_image(data: bytes) -> bool:
    """Quick validity check: does the carved blob decode as a real image?

    Used to decide whether a candidate's span should mask later headers.  A
    genuine file legitimately hides interior markers (e.g. an embedded
    thumbnail), but an over-carved / corrupt blob must NOT mask a valid file
    that happens to fall within its bogus span.
    """
    try:
        import io
        from PIL import Image
        with Image.open(io.BytesIO(data)) as im:
            im.load()
        return True
    except Exception:  # noqa: BLE001 - undecodable / truncated / over-carved
        return False


def _extract(fh, offset: int, fmt: str, max_bytes: int) -> Optional[bytes]:
    """Read a window at ``offset`` and trim to the file's end marker.

    Returns the carved bytes, or ``None`` when no genuine end marker is found
    within the window - such candidates (false positives, or ones that would
    over-carve up to MAX_CARVE_BYTES) are discarded rather than saved as garbage.
    """
    fh.seek(offset)
    window = fh.read(max_bytes)
    if fmt == "JPEG":
        end = _find_jpeg_end(window)
    elif fmt == "PNG":
        end = _find_png_end(window)
    elif fmt == "GIF":
        end = _find_gif_end(window)
    elif fmt == "BMP":
        end = _valid_bmp_size(window)   # None -> reject false-positive BMP sig
    else:
        end = None

    if end is None:
        return None
    return window[:end]


def scan_source(
    source_path: str | Path,
    formats: set[str],
    on_file: Callable[[CarvedFile], None],
    on_progress: Optional[Callable[[int, int], None]] = None,
    on_log: Optional[Callable[[str], None]] = None,
    control: Optional[CarveControl] = None,
    max_bytes: int = config.MAX_CARVE_BYTES,
) -> int:
    """Scan ``source_path`` for image signatures and emit carved candidates.

    ``on_file`` receives each :class:`CarvedFile`; ``on_progress`` receives
    ``(bytes_done, total_bytes)``.  Returns the number of candidates emitted.
    """
    source_path = Path(source_path)
    total = source_path.stat().st_size
    count = 0

    def log(msg: str) -> None:
        if on_log:
            on_log(msg)

    with source_path.open("rb") as scan_fh, source_path.open("rb") as read_fh:
        def prog(pos: int) -> None:
            if on_progress:
                on_progress(min(pos, total), total)

        # Pass 1: collect validated header offsets (scan progress reported here).
        headers: list[tuple[int, str]] = []
        for offset, fmt in iter_headers(
            scan_fh, formats, progress_cb=prog, control=control
        ):
            if control is not None and control.is_cancelled():
                log("Scan cancelled - completed results preserved.")
                break
            headers.append((offset, fmt))
        headers.sort(key=lambda t: t[0])

        # Pass 2: carve, skipping any detection that falls inside a file already
        # carved (eliminates overlapping duplicates - examiner finding: 144/165).
        covered_until = -1
        for offset, fmt in headers:
            if control is not None and control.is_cancelled():
                break
            if offset < covered_until:
                continue
            data = _extract(read_fh, offset, fmt, max_bytes)
            if data is None:
                continue  # false positive / over-carve rejected
            # Only a genuinely decodable file masks later headers (it may hide an
            # interior marker such as an embedded thumbnail).  An over-carved or
            # corrupt blob must NOT advance the marker, or it would swallow a
            # valid file that falls within its bogus span.  The candidate is
            # still emitted (invalid ones are quarantined downstream).
            if _decodes_as_image(data):
                covered_until = offset + len(data)
            hex_off = format_hex_offset(offset)
            ext = {"JPEG": "jpg", "PNG": "png", "BMP": "bmp", "GIF": "gif"}[fmt]
            name = f"CARVED_{fmt}_{hex_off}.{ext}"
            on_file(
                CarvedFile(
                    file_format=fmt,
                    source_offset=offset,
                    source_offset_hex=hex_off,
                    data=data,
                    file_name=name,
                )
            )
            count += 1
            log(f"Recovered {fmt} @ {hex_off} ({len(data)} bytes)")
    return count


# ---------------------------------------------------------------------------
# Qt worker
# ---------------------------------------------------------------------------
try:
    from PyQt6.QtCore import QThread, pyqtSignal

    class CarverWorker(QThread):
        """Drives :func:`scan_source` off the GUI thread (spec sections 19, 25)."""

        progress_updated = pyqtSignal(int)            # percentage 0-100
        offset_updated = pyqtSignal(int, int)         # done, total (bytes)
        file_carved = pyqtSignal(dict)                # carved file payload
        log_message = pyqtSignal(str)
        scan_completed = pyqtSignal(int)              # total recovered
        scan_cancelled = pyqtSignal()
        scan_error = pyqtSignal(str)

        def __init__(self, source_path: str, formats: set[str], parent=None):
            super().__init__(parent)
            self.source_path = source_path
            self.formats = formats
            self.control = CarveControl()

        # external controls -------------------------------------------------
        def pause(self) -> None:
            self.control.pause()
            self.log_message.emit("Scan paused.")

        def resume(self) -> None:
            self.control.resume()
            self.log_message.emit("Scan resumed.")

        def cancel(self) -> None:
            self.control.cancel()

        # thread body -------------------------------------------------------
        def run(self) -> None:  # noqa: D401 - QThread entry point
            try:
                def on_file(cf: CarvedFile) -> None:
                    self.file_carved.emit(
                        {
                            "file_format": cf.file_format,
                            "source_offset": cf.source_offset,
                            "source_offset_hex": cf.source_offset_hex,
                            "data": cf.data,
                            "file_name": cf.file_name,
                        }
                    )

                def on_progress(done: int, total: int) -> None:
                    self.offset_updated.emit(done, total)
                    pct = int(done * 100 / total) if total else 100
                    self.progress_updated.emit(pct)

                total = scan_source(
                    self.source_path, self.formats,
                    on_file=on_file, on_progress=on_progress,
                    on_log=self.log_message.emit, control=self.control,
                )
                if self.control.is_cancelled():
                    self.scan_cancelled.emit()
                else:
                    self.scan_completed.emit(total)
            except Exception as exc:  # noqa: BLE001 - report to GUI
                self.scan_error.emit(str(exc))

except ImportError:  # pragma: no cover - allows Qt-free unit testing
    CarverWorker = None  # type: ignore
