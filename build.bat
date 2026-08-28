@echo off
REM ============================================================
REM  Build ForenSight into a standalone Windows app (one folder)
REM  Run this from the project root, inside your virtual environment.
REM ============================================================

echo.
echo [1/2] Installing/updating PyInstaller...
python -m pip install --upgrade "pyinstaller>=6.0"
if errorlevel 1 goto :error

echo.
echo [2/2] Building ForenSight (this can take a few minutes)...
pyinstaller ForenSight.spec --noconfirm --clean
if errorlevel 1 goto :error

echo.
echo ============================================================
echo  Build complete.
echo  Your app:  dist\ForenSight\ForenSight.exe
echo  Ship the WHOLE  dist\ForenSight  folder (zip it to share).
echo ============================================================
goto :end

:error
echo.
echo  Build FAILED. See the error above. Common fixes are in docs\BUILD.md.

:end
pause
