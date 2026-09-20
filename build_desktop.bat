@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul

echo ============================================
echo  HexHound build script
echo  Output: .\hexhound.exe  (CLI, console)
echo          dist\HexHound-desktop.exe (GUI, optional)
echo ============================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.11+ and add it to PATH.
    exit /b 1
)

echo [1/4] Installing build dependencies...
python -m pip install -e ".[dev]" >nul
python -m pip install --upgrade pyinstaller >nul
if errorlevel 1 (
    echo [ERROR] Failed to install PyInstaller.
    exit /b 1
)

echo [2/4] Building CLI executable (hexhound.exe)...
python -m PyInstaller --noconfirm --clean HexHound.spec
if errorlevel 1 (
    echo [ERROR] PyInstaller failed.
    exit /b 1
)

echo [3/4] Copying executable to project root...
copy /Y dist\hexhound.exe hexhound.exe >nul
if errorlevel 1 (
    echo [ERROR] Failed to copy dist\hexhound.exe
    exit /b 1
)

echo [4/4] Smoke test...
hexhound.exe --version
if errorlevel 1 (
    echo [WARN] Smoke test failed - check the executable manually.
) else (
    echo       Smoke test passed.
)

echo.
echo Done. Run it with:
echo     hexhound.exe providers
echo     hexhound.exe setup
echo     hexhound.exe audit --target http://127.0.0.1:5000 --mode blackbox
echo.
echo Optional desktop build (needs pywebview):
echo     python -m pip install -e ".[desktop]"
echo     python -m PyInstaller --noconfirm --clean HexHound-desktop.spec
echo.
endlocal
