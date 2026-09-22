@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul

echo ============================================
echo  HexHound build script
echo  Output: .\hexhound.exe  (desktop window, no console)
echo ============================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.11+ and add it to PATH.
    exit /b 1
)

echo [1/4] Installing build dependencies...
python -m pip install -e ".[dev,lab,desktop]"
if errorlevel 1 (
    echo [ERROR] Failed to install desktop dependencies.
    exit /b 1
)

echo [2/4] Building desktop executable...
python -m PyInstaller --noconfirm --clean HexHound-desktop.spec
if errorlevel 1 (
    echo [ERROR] PyInstaller failed.
    exit /b 1
)

echo [3/4] Copying executable to project root...
copy /Y dist\HexHound-desktop.exe hexhound.exe >nul
if errorlevel 1 (
    echo [ERROR] Failed to copy dist\HexHound-desktop.exe
    exit /b 1
)

echo [4/4] Desktop build complete.

echo.
echo Double-click hexhound.exe to open the desktop window.
echo.
echo Optional CLI build (dist\hexhound.exe):
echo     python -m PyInstaller --noconfirm --clean HexHound.spec
echo.
endlocal
