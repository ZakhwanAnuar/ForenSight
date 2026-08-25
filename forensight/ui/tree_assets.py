"""Generated raster assets for the classic directory-tree navigation.

We draw (once, cached under ~/.forensight/assets/tree) the dotted branch
connector lines with [+]/[-] boxes and small folder / leaf / status icons, so
the Evidence tree renders like a traditional Windows-style directory tree
instead of relying on emoji glyphs.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

_DIR = Path.home() / ".forensight" / "assets" / "tree"

# -- geometry --------------------------------------------------------------
W, H = 18, 24          # branch cell: 18 wide (== tree indentation), 24 tall
CX, CY = 9, 12         # centre of the cell

# -- palette (warm, matches the light theme) -------------------------------
LINE = (168, 162, 150, 255)     # dotted connector line
BOX_BORDER = (140, 134, 122, 255)
BOX_FILL = (252, 251, 249, 255)
BOX_GLYPH = (74, 80, 88, 255)

FOLDER_EDGE = (183, 143, 40, 255)
FOLDER_BACK = (232, 190, 88, 255)
FOLDER_FRONT = (247, 209, 116, 255)

DISK_EDGE = (120, 126, 134, 255)
DISK_FILL = (196, 201, 208, 255)
DISK_SLOT = (96, 102, 110, 255)

PAGE_EDGE = (120, 130, 145, 255)
PAGE_FILL = (250, 251, 253, 255)
PAGE_LINE = (170, 180, 195, 255)

STAR_FILL = (243, 197, 60, 255)
STAR_EDGE = (183, 143, 40, 255)


def _dot_v(d, x, y0, y1, col=LINE):
    for y in range(y0, y1, 2):
        d.point((x, y), fill=col)


def _dot_h(d, y, x0, x1, col=LINE):
    for x in range(x0, x1, 2):
        d.point((x, y), fill=col)


def _new():
    from PIL import Image
    return Image.new("RGBA", (W, H), (0, 0, 0, 0))


def _box(d, minus_only=False):
    """Draw the [+]/[-] expand box centred in the cell."""
    d.rectangle([CX - 4, CY - 4, CX + 4, CY + 4], fill=BOX_FILL, outline=BOX_BORDER)
    d.line([(CX - 2, CY), (CX + 2, CY)], fill=BOX_GLYPH)          # minus
    if not minus_only:
        d.line([(CX, CY - 2), (CX, CY + 2)], fill=BOX_GLYPH)      # -> plus


# -------------------------------------------------------------------------
def ensure_line_assets() -> dict[str, str]:
    """Generate the seven branch images and return {name: file-url}."""
    names = ("vline", "more", "end",
             "closed_more", "closed_end", "open_more", "open_end")
    paths = {n: _DIR / f"{n}.png" for n in names}
    if all(p.exists() for p in paths.values()):
        return {n: p.as_posix() for n, p in paths.items()}
    try:
        from PIL import ImageDraw
        _DIR.mkdir(parents=True, exist_ok=True)

        def draw(name, fn):
            img = _new()
            fn(ImageDraw.Draw(img))
            img.save(paths[name])

        # pass-through vertical line (ancestor with more siblings below)
        draw("vline", lambda d: _dot_v(d, CX, 0, H))
        # leaf, has siblings below  ├
        def more(d):
            _dot_v(d, CX, 0, H); _dot_h(d, CY, CX, W)
        draw("more", more)
        # leaf, last sibling  └
        def end(d):
            _dot_v(d, CX, 0, CY + 1); _dot_h(d, CY, CX, W)
        draw("end", end)
        # parent nodes: line variant first, box on top, connector to item
        def closed_more(d):
            _dot_v(d, CX, 0, H); _dot_h(d, CY, CX + 4, W); _box(d)
        draw("closed_more", closed_more)
        def closed_end(d):
            _dot_v(d, CX, 0, CY + 1); _dot_h(d, CY, CX + 4, W); _box(d)
        draw("closed_end", closed_end)
        def open_more(d):
            _dot_v(d, CX, 0, H); _dot_h(d, CY, CX + 4, W); _box(d, minus_only=True)
        draw("open_more", open_more)
        def open_end(d):
            _dot_v(d, CX, 0, CY + 1); _dot_h(d, CY, CX + 4, W); _box(d, minus_only=True)
        draw("open_end", open_end)

        return {n: p.as_posix() for n, p in paths.items()}
    except Exception:  # noqa: BLE001
        return {n: "" for n in names}


# -------------------------------------------------------------------------
def _draw_folder(d):
    d.polygon([(2, 6), (2, 4), (7, 4), (9, 6)], fill=FOLDER_BACK, outline=FOLDER_EDGE)
    d.rectangle([2, 5, 15, 14], fill=FOLDER_BACK, outline=FOLDER_EDGE)
    d.polygon([(2, 14), (4, 7), (15, 7), (13, 14)], fill=FOLDER_FRONT, outline=FOLDER_EDGE)


def _draw_disk(d):
    d.rectangle([2, 6, 15, 12], fill=DISK_FILL, outline=DISK_EDGE)
    d.rectangle([2, 3, 15, 9], fill=DISK_FILL, outline=DISK_EDGE)
    d.line([(4, 6), (10, 6)], fill=DISK_SLOT)
    d.ellipse([12, 5, 13, 6], fill=(90, 170, 110, 255))


def _draw_page(d):
    d.polygon([(4, 2), (11, 2), (14, 5), (14, 14), (4, 14)], fill=PAGE_FILL, outline=PAGE_EDGE)
    d.polygon([(11, 2), (11, 5), (14, 5)], fill=(225, 232, 242, 255), outline=PAGE_EDGE)
    for y in (7, 9, 11):
        d.line([(6, y), (12, y)], fill=PAGE_LINE)


def _draw_star(d):
    pts = [(8, 2), (10, 6), (14, 6), (11, 9), (12, 14),
           (8, 11), (4, 14), (5, 9), (2, 6), (6, 6)]
    d.polygon(pts, fill=STAR_FILL, outline=STAR_EDGE)


def _draw_dot(color):
    def fn(d):
        edge = tuple(max(0, c - 55) for c in color[:3]) + (255,)
        d.ellipse([4, 4, 13, 13], fill=color, outline=edge)
    return fn


_ICON_DRAW = {
    "folder": _draw_folder,
    "disk": _draw_disk,
    "page": _draw_page,
    "star": _draw_star,
    "dot_red": _draw_dot((211, 74, 68, 255)),
    "dot_amber": _draw_dot((201, 146, 40, 255)),
    "dot_green": _draw_dot((70, 150, 100, 255)),
}


def ensure_icon_assets() -> dict[str, str]:
    paths = {n: _DIR / f"ic_{n}.png" for n in _ICON_DRAW}
    if all(p.exists() for p in paths.values()):
        return {n: p.as_posix() for n, p in paths.items()}
    try:
        from PIL import Image, ImageDraw
        _DIR.mkdir(parents=True, exist_ok=True)
        for name, fn in _ICON_DRAW.items():
            img = Image.new("RGBA", (16, 16), (0, 0, 0, 0))
            fn(ImageDraw.Draw(img))
            img.save(paths[name])
        return {n: p.as_posix() for n, p in paths.items()}
    except Exception:  # noqa: BLE001
        return {n: "" for n in _ICON_DRAW}


@lru_cache(maxsize=None)
def get_icon(name: str):
    """Return a cached QIcon for the given key ('' if unavailable)."""
    from PyQt6.QtGui import QIcon
    path = ensure_icon_assets().get(name, "")
    return QIcon(path) if path else QIcon()
