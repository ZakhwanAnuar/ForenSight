"""Tests for the Error Level Analysis (ELA) non-scoring visual aid."""
from __future__ import annotations

import io

import pytest

from forensight import ela

PIL = pytest.importorskip("PIL")
from PIL import Image  # noqa: E402


def _jpeg_bytes(img, quality=92) -> bytes:
    buf = io.BytesIO()
    img.convert("RGB").save(buf, "JPEG", quality=quality)
    return buf.getvalue()


def _solid(color=(120, 120, 120), size=(64, 64)):
    return Image.new("RGB", size, color)


def test_compute_ela_returns_same_size_image():
    data = _jpeg_bytes(_solid())
    out = ela.compute_ela(data)
    assert out is not None
    assert out.size == (64, 64)


def test_ela_png_bytes_is_valid_png():
    data = _jpeg_bytes(_solid())
    png = ela.ela_png_bytes(data)
    assert png is not None and png[:8] == b"\x89PNG\r\n\x1a\n"
    # It must decode back into an image of the original dimensions.
    reopened = Image.open(io.BytesIO(png))
    assert reopened.size == (64, 64)


def test_accepts_path(tmp_path):
    p = tmp_path / "sample.jpg"
    p.write_bytes(_jpeg_bytes(_solid()))
    assert ela.compute_ela(str(p)) is not None
    assert ela.mean_error(str(p)) is not None


@pytest.mark.parametrize("garbage", [b"", b"not an image", b"\xff\xd8\xff\x00" * 4])
def test_bad_input_returns_none_never_crashes(garbage):
    assert ela.compute_ela(garbage) is None
    assert ela.ela_png_bytes(garbage) is None
    assert ela.mean_error(garbage) is None
    # hint() must still yield a safe human-readable string, not raise.
    assert isinstance(ela.hint(garbage), str)


def test_missing_file_returns_none():
    assert ela.compute_ela("no_such_file_12345.jpg") is None


def test_spliced_region_raises_local_error():
    """A block re-pasted from a very differently-compressed source should show
    higher ELA energy than the untouched background (ELA's intended use)."""
    # Background: smooth gradient saved at high quality.
    base = Image.new("RGB", (96, 96))
    px = base.load()
    for y in range(96):
        for x in range(96):
            px[x, y] = (x * 2 % 256, y * 2 % 256, 128)
    base = Image.open(io.BytesIO(_jpeg_bytes(base, quality=95))).convert("RGB")

    # A patch that has been through a heavy low-quality JPEG cycle.
    patch_src = Image.new("RGB", (32, 32), (200, 60, 90))
    patch = Image.open(io.BytesIO(_jpeg_bytes(patch_src, quality=20))).convert("RGB")
    spliced = base.copy()
    spliced.paste(patch, (48, 48))
    # Hand ELA the exact pixels (PNG is lossless) so it does its own JPEG cycle.
    png = io.BytesIO()
    spliced.save(png, "PNG")

    out = ela.compute_ela(png.getvalue())
    assert out is not None
    grey = out.convert("L")
    region = grey.crop((48, 48, 80, 80))
    background = grey.crop((0, 0, 32, 32))

    def mean(im):
        h = im.histogram()
        return sum(i * n for i, n in enumerate(h)) / (sum(h) or 1)

    # The spliced region should carry more error energy than clean background.
    assert mean(region) > mean(background)


def test_caveat_is_present_and_non_scoring():
    assert "non-authoritative" in ela.CAVEAT.lower()
    assert "excluded from the forensic score" in ela.CAVEAT.lower()


def _mean_lum(pil_img):
    h = pil_img.convert("L").histogram()
    return sum(i * n for i, n in enumerate(h)) / (sum(h) or 1)


def test_percentile_scaling_beats_naive_max_scaling():
    """Regression for the naive 255/max scaling bug.

    Build an image with broad moderate compression error plus a few rare
    saturated pixels, so raw ``max`` is far above the 99th percentile. Naive
    max-scaling (gain = 255/max) then crushes the broad region toward black,
    while ForenSight's percentile scaling keeps it visible. We assert the
    real (percentile) map is markedly brighter than the naive one would be.
    """
    import numpy as np
    rng = np.random.default_rng(1)
    # Broad mid-frequency texture -> genuine, moderate error everywhere.
    arr = rng.integers(70, 190, size=(96, 96, 3), dtype=np.uint8)
    # A few rare, extreme high-frequency pixels -> inflate raw max only.
    arr[0:2, 0:2, :] = 0
    arr[0:2, 2:4, :] = 255
    png = io.BytesIO()
    Image.fromarray(arr, "RGB").save(png, "PNG")
    data = png.getvalue()

    stats = ela.ela_stats(data)
    assert stats is not None and stats["max"] > stats["p99"] > 0

    auto = ela.compute_ela(data)                       # percentile scaling
    naive = ela.compute_ela(data, gain=255.0 / stats["max"])  # simulate 255/max
    assert auto is not None and naive is not None

    auto_lum, naive_lum = _mean_lum(auto), _mean_lum(naive)
    assert auto_lum > naive_lum * 1.5, (auto_lum, naive_lum)
    assert auto_lum > 12, "percentile-scaled ELA should not be near-black"


def test_localized_edit_is_clearly_brighter_than_background():
    """A pasted, differently-compressed patch should stand out strongly."""
    base = Image.new("RGB", (128, 128))
    px = base.load()
    for y in range(128):
        for x in range(128):
            px[x, y] = ((x * 2) % 256, (y * 2) % 256, 100)
    base = Image.open(io.BytesIO(_jpeg_bytes(base, quality=96))).convert("RGB")

    patch = Image.open(
        io.BytesIO(_jpeg_bytes(Image.new("RGB", (40, 40), (180, 70, 90)), quality=18))
    ).convert("RGB")
    spliced = base.copy()
    spliced.paste(patch, (60, 60))
    png = io.BytesIO(); spliced.save(png, "PNG")

    out = ela.compute_ela(png.getvalue())
    assert out is not None
    grey = out.convert("L")
    region = _mean_lum(grey.crop((60, 60, 100, 100)))
    background = _mean_lum(grey.crop((0, 0, 40, 40)))
    # The edited region should be markedly brighter (clear, not marginal).
    assert region > background * 1.5


def test_ela_stats_shape_and_range():
    data = _jpeg_bytes(_solid())
    stats = ela.ela_stats(data)
    assert stats is not None
    for key in ("mean", "median", "p95", "p99", "max", "block_peak", "block_bg"):
        assert key in stats and 0 <= stats[key] <= 255
    assert ela.ela_stats(b"garbage") is None


def _hq_base(size=(256, 256)):
    img = Image.new("RGB", size)
    px = img.load()
    for y in range(size[1]):
        for x in range(size[0]):
            px[x, y] = ((x * 2) % 256, (y * 2) % 256, 90)
    return Image.open(io.BytesIO(_jpeg_bytes(img, quality=96))).convert("RGB")


def test_hint_flags_strong_localized_splice():
    """A strong splice on a high-quality source must be flagged as localized."""
    base = _hq_base()
    patch = Image.open(
        io.BytesIO(_jpeg_bytes(Image.new("RGB", (96, 96), (200, 60, 80)), quality=15))
    ).convert("RGB")
    base.paste(patch, (110, 110))
    png = io.BytesIO(); base.save(png, "PNG")
    assert "localized" in ela.hint(png.getvalue()).lower()


def test_hint_reports_uniform_clean_image_no_false_alarm():
    """A clean, uniformly-compressed image must NOT be flagged as localized."""
    data = _jpeg_bytes(_solid(size=(200, 200)))
    assert "localized" not in ela.hint(data).lower()
