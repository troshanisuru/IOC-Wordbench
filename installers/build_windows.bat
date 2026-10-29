@echo off
REM Builds the standalone Windows executable: dist\IOC-Workbench.exe
setlocal enabledelayedexpansion

cd /d "%~dp0\.."

if not exist ".venv\Scripts\python.exe" (
    echo Creating Python virtual environment...
    python -m venv .venv
    call .venv\Scripts\pip.exe install -r requirements-dev.txt
) else (
    call .venv\Scripts\pip.exe install pyinstaller
)

echo Building standalone Windows executable...
call .venv\Scripts\python.exe installers\build_app.py

echo.
echo ==========================================================
echo  Windows Standalone Executable Built:
echo    dist\IOC-Workbench.exe
echo ==========================================================
pause
