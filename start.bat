@echo off
REM ===============================================
REM Th3 Thirty3 - Start Script
REM ===============================================
title Th3 Thirty3

echo.
echo ========================================
echo    Th3 Thirty3 - Starting...
echo ========================================
echo.

REM Start Ollama if not running
tasklist /FI "IMAGENAME eq ollama.exe" 2>NUL | find /I /N "ollama.exe">NUL
if "%ERRORLEVEL%"=="1" (
    echo [i] Starting Ollama...
    start "" "ollama" serve
    timeout /t 3 /nobreak >nul
)

REM Start the server
echo [1/2] Starting backend server on port 3000...
cd server
start "Th3 Thirty3 Server" cmd /k "npm start"
cd ..

REM Wait a bit for server to start
timeout /t 3 /nobreak >nul

REM Start the frontend
echo [2/2] Starting frontend on port 5173...
cd interface
start "Th3 Thirty3 Interface" cmd /k "npm run dev"
cd ..

echo.
echo ========================================
echo    Th3 Thirty3 Started!
echo ========================================
echo.
echo Server:    http://localhost:3000
echo Interface: http://localhost:5173
echo.
echo Press any key to open the interface in browser...
pause >nul
start http://localhost:5173
