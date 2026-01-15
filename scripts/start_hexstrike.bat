@echo off
REM ===============================================
REM HexStrike AI - Start Script
REM Starts the HexStrike security tools server
REM ===============================================
title HexStrike AI Server

echo.
echo ========================================
echo    HexStrike AI - Security Platform
echo    150+ Cybersecurity Tools
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [!] Python not found. Please install Python 3.10+
    pause
    exit /b 1
)

REM Navigate to HexStrike directory
cd /d "%~dp0hexstrike-ai"

REM Check if virtual environment exists
if not exist "hexstrike-env" (
    echo [1/3] Creating virtual environment...
    python -m venv hexstrike-env
)

REM Activate virtual environment
echo [2/3] Activating environment...
call hexstrike-env\Scripts\activate.bat

REM Check if dependencies are installed
pip show fastmcp >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [!] Installing dependencies...
    pip install -r requirements.txt
)

REM Start the server
echo [3/3] Starting HexStrike Server on port 8888...
echo.
echo ========================================
echo    Server: http://localhost:8888
echo    Health: http://localhost:8888/health
echo ========================================
echo.
echo Press Ctrl+C to stop the server
echo.

python hexstrike_server.py

pause
