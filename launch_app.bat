@echo off
title Launching Th3 Thirty3 App...
echo.
echo ============================================
echo   Th3 Thirty3 - Lancement Mode Application
echo ============================================
echo.

REM Trouver Brave Browser
set BRAVE_PATH="C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"
if not exist %BRAVE_PATH% (
    set BRAVE_PATH="C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe"
)

REM Vérifier si Brave existe, sinon fallback sur Chrome
if not exist %BRAVE_PATH% (
    set BRAVE_PATH="C:\Program Files\Google\Chrome\Application\chrome.exe"
)

REM Lancer en mode app avec Brave (sans barre de navigateur)
echo Starting Th3 Thirty3 with Brave Browser (standalone mode)...
start "" %BRAVE_PATH% --app=http://localhost:5173 --window-size=1400,900

echo.
echo App launched! Close this window.
timeout /t 2 >nul
exit
