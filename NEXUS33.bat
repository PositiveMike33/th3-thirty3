@echo off
title NEXUS33 - Launching...
color 0a
cls

echo.
echo    ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗██████╗ ██████╗ 
echo    ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝╚════██╗╚════██╗
echo    ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗ █████╔╝ █████╔╝
echo    ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║ ╚═══██╗ ╚═══██╗
echo    ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║██████╔╝██████╔╝
echo    ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═════╝ ╚═════╝ 
echo.
echo    [SYSTEM] Starting NEXUS33 AI Platform...
echo.

:: Kill any existing processes
echo    [1/5] Cleaning previous sessions...
taskkill /F /IM node.exe /T >nul 2>&1
timeout /t 2 /nobreak >nul

:: Start Ollama if not running
echo    [2/5] Checking Ollama AI Engine...
tasklist /FI "IMAGENAME eq ollama.exe" | find /I "ollama.exe" >nul
if errorlevel 1 (
    start /min "" ollama serve
    echo          Started Ollama
    timeout /t 3 /nobreak >nul
) else (
    echo          Ollama already running
)

:: Start Backend
echo    [3/5] Starting Neural Core (Backend)...
cd /d "C:\Users\th3th\Th3-Thirty3\th3-thirty3\server"
start /min cmd /c "npm start"
timeout /t 5 /nobreak >nul

:: Start Frontend
echo    [4/5] Starting Visual Interface (Frontend)...
cd /d "C:\Users\th3th\Th3-Thirty3\th3-thirty3\interface"
start /min cmd /c "npm run dev"
timeout /t 5 /nobreak >nul

:: Open Browser
echo    [5/5] Launching NEXUS33...
timeout /t 3 /nobreak >nul
start http://localhost:5173

echo.
echo    ========================================
echo    NEXUS33 is now running!
echo    ========================================
echo.
echo    Dashboard: http://localhost:5173
echo    Backend:   http://localhost:3000
echo.
echo    Press any key to close this window...
echo    (NEXUS33 will continue running in background)
pause >nul
