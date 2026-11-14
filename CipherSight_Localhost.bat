@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title CipherSight - Localhost Forensic Workstation
if not exist "pyproject.toml" (
  echo [ERROR] Run this file from the extracted CipherSight project folder.
  pause
  exit /b 1
)
set "PYTHON_CMD="
where py >nul 2>&1 && set "PYTHON_CMD=py -3"
if not defined PYTHON_CMD where python >nul 2>&1 && set "PYTHON_CMD=python"
if not defined PYTHON_CMD (
  echo [ERROR] Python 3.10-3.13 is required. Install from https://www.python.org/downloads/windows/
  pause
  exit /b 1
)
%PYTHON_CMD% -c "import sys; print('Python',sys.version.split()[0]); sys.exit(0 if (3,10) <= sys.version_info[:2] < (3,14) else 1)"
if errorlevel 1 goto fail
if not exist ".venv\Scripts\python.exe" (
  echo [setup] Creating virtual environment...
  %PYTHON_CMD% -m venv .venv
  if errorlevel 1 goto fail
)
set "VPY=%CD%\.venv\Scripts\python.exe"
echo [setup] Checking/installing project dependencies...
"%VPY%" -m pip install --disable-pip-version-check -e .
if errorlevel 1 goto fail
echo.
echo [launch] Starting CipherSight at http://127.0.0.1:8000/
echo [launch] Keep this window open. Press Ctrl+C to stop the server.
"%VPY%" main.py web --port 8000
set "RC=%errorlevel%"
if not "%RC%"=="0" echo [ERROR] CipherSight stopped with code %RC%.
pause
exit /b %RC%
:fail
echo [ERROR] Setup failed. Check Python, internet access and the messages above.
pause
exit /b 1
