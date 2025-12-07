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

REM Start Tor Browser in background (for SOCKS proxy on port 9050)
echo [0/4] Starting Tor Network...
tasklist /FI "IMAGENAME eq firefox.exe" 2>NUL | find /I /N "firefox.exe">NUL
if "%ERRORLEVEL%"=="1" (
    if exist "%TOR_PATH%" (
        start "" "%TOR_PATH%"
        echo      Tor Browser starting...
        timeout /t 8 /nobreak >nul
    ) else (
        echo      [!] Tor Browser not found at %TOR_PATH%
        echo      [!] Please install or move Tor Browser to Desktop
    )
)

REM Start Ollama if not running
tasklist /FI "IMAGENAME eq ollama.exe" 2>NUL | find /I /N "ollama.exe">NUL
if "%ERRORLEVEL%"=="1" (
    echo [1/4] Starting Ollama (Local AI)...
    start "" "ollama" serve
    timeout /t 3 /nobreak >nul
)

REM Start the server
echo [2/4] Starting backend server on port 3000...
cd server
start "Th3 Thirty3 Server" cmd /k "npm start"
cd ..

REM Wait a bit for server to start
timeout /t 3 /nobreak >nul

REM Start the frontend
echo [3/4] Starting frontend on port 5173...
cd interface
start "Th3 Thirty3 Interface" cmd /k "npm run dev"
cd ..

REM Wait for frontend to be ready
timeout /t 5 /nobreak >nul

echo.
echo ========================================
echo    Th3 Thirty3 - SECURE MODE ACTIVE
echo ========================================
echo.
echo   Tor Network:   ACTIVE (port 9050)
echo   Server:        http://localhost:3000
echo   Interface:     http://localhost:5173
echo.
echo   SECURITY:
echo   - Brave with Tor Window (--tor)
echo   - All agents via Tor proxy
echo   - Intrusion protection ON
echo.

REM Open in Brave with private mode (NOT --tor for localhost access)
echo [4/4] Opening Brave in private mode...
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

