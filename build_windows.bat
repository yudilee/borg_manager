@echo off
REM ============================================
REM Borg Backup Manager - Windows Build Script
REM ============================================
REM This script builds a Windows executable using PyInstaller.
REM Run this on a Windows machine with Python installed.
REM ============================================

echo ============================================
echo   Borg Backup Manager - Build Script
echo ============================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python from https://python.org
    pause
    exit /b 1
)

echo [1/3] Installing dependencies...
pip install pyinstaller pillow pystray paramiko

echo.
echo [2/3] Building executable...
REM --onefile: Single executable file
REM --windowed: No console window (GUI app)
REM --icon: Application icon
REM --name: Output executable name
REM --hidden-import: Ensure these modules are included

pyinstaller ^
    --onefile ^
    --windowed ^
    --icon=borg_manager_icon.ico ^
    --name="BorgManager" ^
    --hidden-import=pystray ^
    --hidden-import=PIL ^
    --hidden-import=PIL.Image ^
    --hidden-import=paramiko ^
    --hidden-import=tkinter ^
    --hidden-import=tkinter.ttk ^
    --hidden-import=tkinter.messagebox ^
    --hidden-import=tkinter.filedialog ^
    --add-data="borg_manager_icon.ico;." ^
    borg_gui.py

echo.
echo [3/3] Build complete!
echo.
echo The executable is located at: dist\BorgManager.exe
echo.
echo ============================================
echo NOTES:
echo - The .exe includes all Python dependencies.
echo - Users still need SSH access to a Linux server
echo   (Windows OpenSSH or PuTTY must be installed).
echo - Borg Backup runs on the remote Linux server,
echo   not on Windows directly.
echo ============================================
pause
