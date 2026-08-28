# Building ForenSight as a Windows application

This turns ForenSight into a standalone Windows app that runs by double-clicking
`ForenSight.exe`, with no need for Python or `python main.py`. It uses
[PyInstaller](https://pyinstaller.org) in **one-folder** mode.

## Prerequisites

- Windows, with the project's virtual environment set up and working:
  ```
  python -m venv .venv
  .venv\Scripts\activate
  pip install -r requirements.txt
  ```
- Make sure the app runs normally first: `python main.py`.

> **Build inside the virtual environment.** PyInstaller bundles whatever is
> importable, so building in a clean venv (runtime deps only) keeps the app
> small. The build config already excludes TensorFlow/Keras because ForenSight's
> ML is disabled and excluded from the forensic score.

## Build (one command)

From the project root, with the venv active:

```
build.bat
```

or manually:

```
pip install "pyinstaller>=6.0"
pyinstaller ForenSight.spec --noconfirm --clean
```

The result is:

```
dist\ForenSight\ForenSight.exe        <- double-click to run
dist\ForenSight\ ... (bundled libraries)
```

**Ship the whole `dist\ForenSight` folder** (zip it to hand it over). The `.exe`
needs the files next to it. First launch is a little slow; after that it starts
quickly.

## Add an app icon (optional but recommended)

1. Create or download a square PNG and convert it to `.ico` (e.g. with an online
   PNG-to-ICO converter, or `pip install pillow` then
   `python -c "from PIL import Image; Image.open('logo.png').save('forensight.ico')"`).
2. Save it as `forensight.ico` in the project root.
3. Rebuild. The spec automatically uses `forensight.ico` if it exists.

## Test the built app

- Double-click `dist\ForenSight\ForenSight.exe`.
- Create a case, add a data source, carve and analyse an image, verify a C2PA
  file, and generate a report — confirm each works exactly as under
  `python main.py`.
- Deleted-file detection needs `pytsk3`; if it did not bundle, allocation simply
  shows "Unknown" (the app still runs). See troubleshooting below.

## Optional: a proper installer (Setup.exe)

To produce a `ForenSightSetup.exe` that installs to Program Files with a Start
Menu shortcut, use the free [Inno Setup](https://jrsoftware.org/isinfo.php).
After building with PyInstaller, compile a script like this (save as
`installer.iss` and open it in Inno Setup):

```ini
[Setup]
AppName=ForenSight
AppVersion=1.0
DefaultDirName={autopf}\ForenSight
DefaultGroupName=ForenSight
OutputBaseFilename=ForenSightSetup
Compression=lzma
SolidCompression=yes

[Files]
Source: "dist\ForenSight\*"; DestDir: "{app}"; Flags: recursesubdirs

[Icons]
Name: "{group}\ForenSight"; Filename: "{app}\ForenSight.exe"
Name: "{commondesktop}\ForenSight"; Filename: "{app}\ForenSight.exe"
```

Compiling it produces `Output\ForenSightSetup.exe` — the polished, hand-in-ready
installer.

## Troubleshooting

| Symptom | Fix |
|---|---|
| App window never appears / silent exit | Temporarily set `console=False` to `True` in `ForenSight.spec`, rebuild, and run from a terminal to see the traceback. |
| `Qt platform plugin "windows" could not be found` | Ensure you built inside the venv where PyQt6 is installed; rebuild with `--clean`. PyInstaller's PyQt6 hook bundles the plugins automatically. |
| Deleted-file detection missing | `pytsk3` (a C extension) did not bundle. The app still works; allocation shows "Unknown". Confirm `pip show pytsk3` succeeds in the venv, then rebuild. |
| Antivirus flags the .exe | A known false positive for PyInstaller one-file builds; one-folder mode (used here) reduces it. Add an exclusion, or sign the exe for distribution. |
| Missing DLL at startup | Install the latest **Microsoft Visual C++ Redistributable** on the target machine. |

## Notes

- `build/` and `dist/` are generated and are git-ignored — do not commit them.
- Keep `ForenSight.spec` in version control; it is the build recipe.
