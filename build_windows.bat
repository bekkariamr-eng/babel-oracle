@echo off
title Babel Oracle - Build Windows Executable
echo.
echo  =============================================
echo   Babel Oracle - Windows Build Script
echo   By Amr Bekkari
echo  =============================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found. Install Python 3.10+ from python.org
    echo  Make sure "Add Python to PATH" is checked during installation.
    pause
    exit /b 1
)

echo  [1/3] Installing dependencies...
pip install cryptography pyinstaller --quiet
if errorlevel 1 (
    echo  [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)

echo  [2/3] Building executable...
pyinstaller --onefile --name babel_oracle --clean --noconfirm --console babel_oracle.py
if errorlevel 1 (
    echo  [ERROR] Build failed.
    pause
    exit /b 1
)

echo  [3/3] Done!
echo.
echo  =============================================
echo   Executable created: dist\babel_oracle.exe
echo  =============================================
echo.
echo  You can now run: dist\babel_oracle.exe
echo  Or copy it anywhere — it's fully standalone.
echo.
pause
