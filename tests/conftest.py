"""Shared pytest fixtures for ForenSight tests."""
import io
import sys
from pathlib import Path

import pytest
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def _isolate_recent_cases(monkeypatch, tmp_path_factory):
    """Redirect the recent-cases store to a throwaway file so the test suite
    never pollutes the real ~/.forensight/recent_cases.json."""
    from forensight import recent_cases
    store = tmp_path_factory.mktemp("recent") / "recent_cases.json"
    monkeypatch.setattr(recent_cases, "_STORE", store)


def _image(color, size=(160, 120)):
    img = Image.new("RGB", size, color)
    ImageDraw.Draw(img).rectangle([10, 10, size[0] - 10, size[1] - 10],
                                  outline=(255, 255, 255))
    return img


def _jpeg(color, quality=90):
    buf = io.BytesIO()
    _image(color).save(buf, "JPEG", quality=quality)
    return buf.getvalue()


def _png(color):
    buf = io.BytesIO()
    _image(color).save(buf, "PNG")
    return buf.getvalue()


def _bmp(color):
    buf = io.BytesIO()
    _image(color).save(buf, "BMP")
    return buf.getvalue()


def _gif(color):
    buf = io.BytesIO()
    _image(color).convert("P").save(buf, "GIF")
    return buf.getvalue()


@pytest.fixture
def sample_image(tmp_path) -> Path:
    """A small raw .dd containing JPEG/PNG/BMP/GIF blobs with zero padding."""
    pad = b"\x00" * 2048
    blobs = [_jpeg((200, 60, 60)), _png((60, 120, 200)),
             _bmp((90, 160, 90)), _gif((210, 190, 60)),
             _jpeg((120, 60, 160), quality=95)]
    path = tmp_path / "sample.dd"
    with path.open("wb") as fh:
        fh.write(pad)
        for blob in blobs:
            fh.write(blob)
            fh.write(pad)
    return path


def _noisy_jpeg(quality=90):
    """A larger, high-detail JPEG that comfortably exceeds the 5 KB threshold."""
    import os
    size = (640, 480)
    img = Image.frombytes("RGB", size, os.urandom(size[0] * size[1] * 3))
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=quality)
    return buf.getvalue()


@pytest.fixture
def valid_jpeg(tmp_path) -> Path:
    path = tmp_path / "valid.jpg"
    path.write_bytes(_noisy_jpeg(quality=90))
    return path


@pytest.fixture
def new_case(tmp_path):
    from forensight import case_manager
    case = case_manager.create_case(
        "Test Case", "CL-T-1", "Tester", "EX0", "Org", tmp_path)
    yield case
    case.close_db()
