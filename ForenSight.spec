# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build recipe for ForenSight (Windows, one-folder GUI app).

Build with:   pyinstaller ForenSight.spec --noconfirm --clean
Output:       dist/ForenSight/ForenSight.exe   (ship the whole dist/ForenSight folder)

Requires PyInstaller >= 6.0. Build inside your virtual environment so only the
runtime dependencies are picked up.
"""
import os
from PyInstaller.utils.hooks import collect_submodules

# C-extensions / dynamically-imported packages PyInstaller may miss without a hint.
hiddenimports = collect_submodules("cbor2")
for _mod in ("pytsk3", "cryptography", "cbor2", "PIL", "reportlab"):
    try:
        __import__(_mod)
        hiddenimports.append(_mod)
    except Exception:
        pass  # optional (e.g. pytsk3) — the app degrades gracefully without it

# Keep the build lean: ForenSight's ML is disabled and excluded from the score,
# so TensorFlow/Keras (hundreds of MB) must NOT be bundled. Dev-only tooling is
# excluded too.
excludes = [
    "tensorflow", "keras", "tensorboard", "h5py",
    "pytest", "_pytest", "PyInstaller",
    "matplotlib", "IPython", "notebook", "jupyter",
]

icon = "forensight.ico" if os.path.exists("forensight.ico") else None

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=[
        ("forensight/ui/assets/logo.png", "forensight/ui/assets"),
        ("forensight.ico", "."),
    ],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="ForenSight",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,      # windowed GUI app — no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="ForenSight",
)
