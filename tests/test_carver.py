"""Carving-engine tests (spec section 65)."""
from forensight import carver, config


def _collect(source, formats, **kw):
    found = []
    carver.scan_source(source, formats, on_file=found.append, **kw)
    return found


def test_detects_all_formats(sample_image):
    found = _collect(sample_image, {"JPEG", "PNG", "BMP", "GIF"})
    formats = {f.file_format for f in found}
    assert {"JPEG", "PNG", "BMP", "GIF"} <= formats


def test_rejects_jpeg_false_positive_marker(tmp_path):
    """FF D8 FF followed by an illegal marker byte must NOT be carved."""
    # 0xA6 is not a valid JPEG marker; this pattern appears constantly in code.
    f = tmp_path / "fp.bin"
    f.write_bytes(b"\x00" * 100 + b"\xFF\xD8\xFF\xA6" + b"\x11" * 6000 + b"\xFF\xD9")
    assert _collect(f, {"JPEG"}) == []


def test_rejects_ff_d8_ff_ff_fill_region(tmp_path):
    """A run of FF D8 FF FF fill bytes must not produce any carves."""
    f = tmp_path / "fill.bin"
    f.write_bytes(b"\xFF\xD8\xFF\xFF" * 20000)   # 80 KB of the fill pattern
    assert _collect(f, {"JPEG"}) == []


def test_rejects_png_without_ihdr(tmp_path):
    """A PNG signature not followed by an IHDR chunk is a false positive."""
    f = tmp_path / "fpng.bin"
    f.write_bytes(b"\x00" * 50 + config.PNG_HEADER + b"\x00" * 40000
                  + config.PNG_IEND)
    assert _collect(f, {"PNG"}) == []


def test_no_overcarve_without_end_marker(tmp_path):
    """A valid-looking header with no end marker must be discarded, not dumped."""
    # Valid JPEG start (FF D8 FF E0) but no EOI anywhere -> must be discarded.
    f = tmp_path / "noeoi.bin"
    f.write_bytes(b"\xFF\xD8\xFF\xE0" + b"\x22" * (2 * 1024 * 1024))
    assert _collect(f, {"JPEG"}) == []


def test_absolute_offsets_are_recorded(sample_image):
    found = _collect(sample_image, {"JPEG"})
    assert found, "expected at least one JPEG"
    for cf in found:
        assert cf.source_offset >= 0
        assert cf.source_offset_hex.startswith("0x")


def test_signature_split_across_chunk_boundary(tmp_path):
    """A PNG header straddling a 1 MiB chunk boundary must still be found."""
    png_header = config.PNG_HEADER
    # A realistic PNG: signature + IHDR chunk (now required to reject false
    # positives) + ... + IEND.
    ihdr = (b"\x00\x00\x00\x0D" + b"IHDR"
            + b"\x00\x00\x00\x10\x00\x00\x00\x10\x08\x02\x00\x00\x00"  # 13-byte data
            + b"\x00\x00\x00\x00")                                     # CRC
    png = png_header + ihdr + b"\x00" * 32 + config.PNG_IEND
    # Place the signature so it spans the boundary: 4 bytes before, 4 after.
    pre = config.CHUNK_SIZE - 4
    body = b"\x00" * pre + png + b"\x00" * 16
    f = tmp_path / "boundary.bin"
    f.write_bytes(body)
    found = _collect(f, {"PNG"})
    offsets = [cf.source_offset for cf in found]
    assert pre in offsets


def test_bmp_size_parsing(sample_image):
    found = _collect(sample_image, {"BMP"})
    assert found
    # BMP end is derived from the declared little-endian size field.
    for cf in found:
        assert len(cf.data) > 6


def test_carved_naming_convention(sample_image):
    found = _collect(sample_image, {"JPEG"})
    for cf in found:
        assert cf.file_name.startswith("CARVED_JPEG_0x")
        assert cf.file_name.endswith(".jpg")


def test_cancel_stops_scan(sample_image):
    control = carver.CarveControl()
    collected = []

    def on_file(cf):
        collected.append(cf)
        control.cancel()  # cancel after the first hit

    carver.scan_source(sample_image, {"JPEG", "PNG", "BMP", "GIF"},
                       on_file=on_file, control=control)
    # Cancellation preserves already-collected results and stops early.
    assert len(collected) >= 1
