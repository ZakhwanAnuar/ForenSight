"""Premium light forensic-workstation theme.

Warm off-white workspace (not pure white), a dark charcoal top chrome for
contrast, and a restrained muted-emerald accent (no bright blue).
"""

from pathlib import Path


def _ensure_arrow_asset() -> str:
    """Create a small down-arrow PNG (once) and return a Qt-usable url path.

    Styling a QComboBox via stylesheet suppresses its native drop-down arrow,
    so we supply our own image to restore the visible caret.
    """
    asset_dir = Path.home() / ".forensight" / "assets"
    arrow = asset_dir / "down_arrow.png"
    if not arrow.exists():
        try:
            asset_dir.mkdir(parents=True, exist_ok=True)
            from PIL import Image, ImageDraw
            img = Image.new("RGBA", (16, 16), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.polygon([(3, 5), (13, 5), (8, 11)], fill=(110, 118, 129, 255))
            img.save(arrow)
        except Exception:  # noqa: BLE001
            return ""
    return arrow.as_posix()


_ARROW_URL = _ensure_arrow_asset()


from . import tree_assets

_LINES = tree_assets.ensure_line_assets()   # classic dotted branch images

# -- palette ---------------------------------------------------------------
ACCENT = "#2E6B57"          # muted emerald - primary actions, active states
ACCENT_LIGHT = "#35806C"    # hover
ACCENT_SOFT = "#DCEAE4"     # soft emerald tint - selections
ACCENT_HOVER_BG = "#EAF1EE"

CHROME = "#23272C"          # dark charcoal top bar
CHROME_LIGHT = "#2E3339"    # nav bar
CHROME_HOVER = "#262B31"

BG = "#F2F0EB"              # warm off-white workspace
PANEL = "#FBFAF8"           # cards / inputs (warm near-white)
PANEL_ALT = "#F6F4EF"       # alternate rows / inactive tabs
BORDER = "#E4E0D8"          # warm grey border
TEXT = "#23282E"            # deep slate near-black
MUTED = "#6E7681"

HEADER_BG = "#ECE8E1"       # table header (subtle warm grey)
HEADER_TEXT = "#454B53"

OK = "#2E7D5B"
WARN = "#B5771F"
DANGER = "#B23A34"
DISABLED_BG = "#D6D2CA"
DISABLED_TEXT = "#F2F0EB"

STYLESHEET = f"""
QWidget {{
    background: {BG};
    color: {TEXT};
    font-family: 'Segoe UI', 'Inter', Arial, sans-serif;
    font-size: 13px;
}}
QLabel#H1 {{ font-size: 22px; font-weight: 700; color: {TEXT}; }}
QLabel#H2 {{ font-size: 15px; font-weight: 700; color: {ACCENT}; }}
QLabel#Muted {{ color: {MUTED}; }}
QLabel#FilterStatus {{
    color: {TEXT}; background: {ACCENT_SOFT}; border-radius: 5px;
    padding: 5px 9px; font-size: 12px;
}}
QLabel#Tagline {{ color: {MUTED}; font-size: 14px; }}

/* Top navigation chrome */
QFrame#TopBar {{ background: {CHROME}; }}
QFrame#NavBar {{ background: {CHROME_LIGHT}; }}
QLabel#TopBrand {{ color: #F5F4F1; font-size: 18px; font-weight: 800; padding: 0 6px 0 16px; background: transparent; letter-spacing: 0.3px; }}
QLabel#TopBrandSub {{ color: #9AA1A9; font-size: 10px; padding: 0 16px 0 4px; background: transparent; }}
QPushButton#TopNavButton {{
    background: transparent; color: #C3C8CE; border: none;
    border-bottom: 3px solid transparent; padding: 9px 16px; font-size: 13px;
}}
QPushButton#TopNavButton:hover {{ background: {CHROME_HOVER}; color: #FFFFFF; }}
QPushButton#TopNavButton:checked {{
    background: transparent; color: #FFFFFF; font-weight: 700;
    border-bottom: 3px solid {ACCENT};
}}

/* Welcome / legacy sidebar (dark chrome) */
QFrame#Sidebar {{ background: {CHROME}; }}
QPushButton#NavButton {{
    background: transparent; color: #C3C8CE; border: none;
    text-align: left; padding: 11px 18px; font-size: 13px;
}}
QPushButton#NavButton:hover {{ background: {CHROME_HOVER}; color: white; }}
QPushButton#NavButton:checked {{ background: {BG}; color: {TEXT}; font-weight: 700; }}
QLabel#Brand {{ color: #F5F4F1; font-size: 18px; font-weight: 800; padding: 16px 18px; }}
QLabel#BrandSub {{ color: #9AA1A9; font-size: 10px; padding: 0 18px 10px 18px; }}

/* Panels / cards */
QFrame#Panel, QFrame#Card {{
    background: {PANEL}; border: 1px solid {BORDER}; border-radius: 10px;
}}
QLabel#StatValue {{ font-size: 24px; font-weight: 800; color: {ACCENT}; }}
QLabel#StatLabel {{ color: {MUTED}; font-size: 11px; }}

/* Buttons */
QPushButton {{
    background: {ACCENT}; color: #FFFFFF; border: none; border-radius: 6px;
    padding: 8px 16px; font-weight: 600;
}}
QPushButton:hover {{ background: {ACCENT_LIGHT}; }}
QPushButton:disabled {{ background: {DISABLED_BG}; color: {DISABLED_TEXT}; }}
QPushButton#Secondary {{ background: {PANEL}; color: {ACCENT}; border: 1px solid {ACCENT}; }}
QPushButton#Secondary:hover {{ background: {ACCENT_HOVER_BG}; }}
QPushButton#Secondary:disabled {{ background: {PANEL}; color: {MUTED}; border: 1px solid {BORDER}; }}
QPushButton#Danger {{ background: {DANGER}; }}
QPushButton#Danger:hover {{ background: #C64A43; }}

/* Inputs */
QLineEdit, QComboBox, QSpinBox, QTextEdit, QPlainTextEdit {{
    background: {PANEL}; border: 1px solid {BORDER}; border-radius: 6px;
    padding: 6px 8px; selection-background-color: {ACCENT_SOFT}; selection-color: {TEXT};
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus {{
    border: 1px solid {ACCENT};
}}
QComboBox::drop-down {{
    subcontrol-origin: padding; subcontrol-position: center right;
    width: 22px; border-left: 1px solid {BORDER};
}}
QComboBox::down-arrow {{ image: url({_ARROW_URL}); width: 11px; height: 11px; }}
QComboBox::down-arrow:on {{ top: 1px; }}

/* Tables */
QTableWidget, QTableView {{
    background: {PANEL}; border: 1px solid {BORDER}; border-radius: 8px;
    gridline-color: {BORDER}; selection-background-color: {ACCENT_SOFT};
    selection-color: {TEXT}; alternate-background-color: {PANEL_ALT};
}}
QHeaderView::section {{
    background: {HEADER_BG}; color: {HEADER_TEXT}; padding: 7px 6px; border: none;
    border-bottom: 1px solid {BORDER}; font-weight: 700;
}}
QTableWidget::item {{ padding: 4px; }}

/* Progress */
QProgressBar {{
    border: 1px solid {BORDER}; border-radius: 6px; text-align: center;
    background: {PANEL}; height: 22px; color: {TEXT};
}}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 5px; }}

/* Tree (classic directory tree) */
QTreeWidget, QTreeView {{
    background: {PANEL}; border: 1px solid {BORDER}; border-radius: 8px; outline: 0;
    padding: 6px 4px; show-decoration-selected: 1;
}}
QTreeWidget::item {{ height: 24px; }}
QTreeWidget::item:selected {{ background: {ACCENT_SOFT}; color: {TEXT}; }}
QTreeWidget::item:hover:!selected {{ background: {PANEL_ALT}; }}
/* Dotted connector lines + [+]/[-] boxes */
QTreeWidget::branch {{ background: transparent; }}
QTreeWidget::branch:has-siblings:!adjoins-item {{ image: url({_LINES['vline']}); }}
QTreeWidget::branch:has-siblings:adjoins-item {{ image: url({_LINES['more']}); }}
QTreeWidget::branch:!has-children:!has-siblings:adjoins-item {{ image: url({_LINES['end']}); }}
QTreeWidget::branch:closed:has-children:has-siblings {{ image: url({_LINES['closed_more']}); }}
QTreeWidget::branch:closed:has-children:!has-siblings {{ image: url({_LINES['closed_end']}); }}
QTreeWidget::branch:open:has-children:has-siblings {{ image: url({_LINES['open_more']}); }}
QTreeWidget::branch:open:has-children:!has-siblings {{ image: url({_LINES['open_end']}); }}

/* Tabbed detail viewer */
QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 8px; background: {PANEL}; top: -1px; }}
QTabBar::tab {{
    background: {PANEL_ALT}; color: {MUTED}; padding: 6px 14px; border: 1px solid {BORDER};
    border-bottom: none; border-top-left-radius: 7px; border-top-right-radius: 7px;
    margin-right: 2px;
}}
QTabBar::tab:selected {{ background: {PANEL}; color: {ACCENT}; font-weight: 700; }}

/* Misc */
QListWidget {{
    background: {PANEL}; border: 1px solid {BORDER}; border-radius: 8px;
    selection-background-color: {ACCENT_SOFT}; selection-color: {TEXT};
}}
QListWidget::item {{ padding: 5px 4px; }}
QListWidget::item:selected {{ background: {ACCENT_SOFT}; color: {TEXT}; }}
QCheckBox {{ spacing: 6px; }}
QScrollArea {{ border: none; background: {BG}; }}
QStatusBar {{ background: {BG}; color: {MUTED}; }}
QSplitter::handle {{ background: {BORDER}; }}
"""
