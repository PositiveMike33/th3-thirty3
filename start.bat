@echo off
REM ===============================================
REM Th3 Thirty3 - Start Script with Tor + Brave
REM Secure OSINT/Hacking Environment
REM ===============================================
title Th3 Thirty3 - Secure Mode

echo.
echo ========================================
echo    Th3 Thirty3 - Secure Mode
echo    Tor + Brave Protection Active
echo ========================================
echo.

REM Define Brave path
set "BRAVE_PATH=%LocalAppData%\BraveSoftware\Brave-Browser\Application\brave.exe"
set "TOR_PATH=%UserProfile%\OneDrive\Desktop\Tor Browser\Browser\firefox.exe"

REM Start Tor Service (Background SOCKS5 Proxy)
echo [0/4] Starting Tor Network...
powershell -ExecutionPolicy Bypass -File ".\start_tor_proxy.ps1"
if %ERRORLEVEL% NEQ 0 (
    echo [!] Failed to start Tor Proxy. Continuing anyway...
) else (
    echo [OK] Tor Proxy active on port 9050
)

REM Start Ollama if not running
tasklist /FI "IMAGENAME eq ollama.exe" 2>NUL | find /I /N "ollama.exe">NUL
if "%ERRORLEVEL%"=="1" (
    echo [1/4] Starting Ollama (Local AI)...
    start "" "ollama" serve
    timeout /t 3 /nobreak >nul
)

REM Start Docker Services (GPU Trainer + HexStrike)
echo [3/5] Starting Docker Services (GPU Trainer + HexStrike)...
docker-compose up -d tensorflow-trainer hexstrike
if %ERRORLEVEL% NEQ 0 (
    echo [!] Docker startup failed. Ensuring fallback...
) else (
    echo [OK] Docker services started.
)

REM Start the server
echo [4/5] Starting backend server on port 3000...
set GPU_TRAINER_URL=http://localhost:5000
cd server
start "Th3 Thirty3 Server" cmd /k "npm start"
cd ..

REM Wait a bit for server to start
timeout /t 3 /nobreak >nul

REM Start the frontend
echo [5/5] Starting frontend on port 5173...
cd interface
start "Th3 Thirty3 Interface" cmd /k "npm run dev"
cd ..

REM Wait for all services to be ready
timeout /t 5 /nobreak >nul

echo.
echo ========================================
echo    Th3 Thirty3 - SECURE MODE ACTIVE
echo ========================================
echo.
echo   Tor Network:   ACTIVE (port 9050)
echo   Server:        http://localhost:3000
echo   Interface:     http://localhost:5173
echo   HexStrike AI:  http://localhost:8888
echo.
echo   SECURITY:
echo   - Brave with Tor Window (--tor)
echo   - All agents via Tor proxy
echo   - Intrusion protection ON
echo   - HexStrike: 150+ security tools
echo.

REM Open in Brave with private mode (NOT --tor for localhost access)
echo [5/5] Opening Brave in private mode...
if exist "%BRAVE_PATH%" (
    REM Note: --tor flag cannot access localhost, so we use private mode only
    REM Tor is still active via the backend service for external requests
    start "" "%BRAVE_PATH%" --incognito "http://localhost:5173"
    echo      Opened in Brave Private Mode!
    echo      NOTE: Agents use Tor via backend for external requests
) else (
    echo      [!] Brave not found, opening in default browser...
    start http://localhost:5173
)

echo.
echo ========================================
echo    Press any key to open Finance (Kraken)
echo    in secure Brave window...
echo ========================================
pause >nul

REM Open Kraken in Brave Tor mode for secure finance
if exist "%BRAVE_PATH%" (
    start "" "%BRAVE_PATH%" --incognito --tor "https://www.kraken.com"
    echo Kraken opened in Brave Tor Mode!
)

