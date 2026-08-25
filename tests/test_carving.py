

def test_invalid_overcarve_does_not_mask_valid_file(tmp_path):
    # Regression (DFTT 8-jpeg-search): a corrupt/over-carved candidate must not
    # mask a valid image that falls within its bogus span. The carver advances
    # its "covered" marker only for candidates that actually decode.
    import io
    from PIL import Image
    from forensight import carver
    buf = io.BytesIO()
    Image.new("RGB", (80, 80), (20, 90, 160)).save(buf, "JPEG", quality=90)
    vj = buf.getvalue()
    # corrupt JPEG header + long gap (no valid image) THEN a real JPEG
    disk = tmp_path / "mask.dd"
    disk.write_bytes(b"\xFF\xD8\xFF" + b"\x00" * 3000 + vj + b"\x00" * 200)
    offsets = []
    carver.scan_source(str(disk), {"JPEG"},
                       on_file=lambda cf: offsets.append(cf.source_offset))
    assert 3003 in offsets, f"valid JPEG at 3003 was masked; got {offsets}"


def test_decodes_as_image_helper():
    import io
    from PIL import Image
    from forensight import carver
    buf = io.BytesIO()
    Image.new("RGB", (32, 32), (1, 2, 3)).save(buf, "JPEG")
    assert carver._decodes_as_image(buf.getvalue()) is True
    assert carver._decodes_as_image(b"\xFF\xD8\xFF" + b"\x00" * 500) is False
