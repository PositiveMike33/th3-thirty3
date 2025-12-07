@echo off
title Launching Th3 Thirty3 App...
echo.
echo ============================================
echo   Th3 Thirty3 - Lancement Mode Application
echo ============================================
echo.

REM Trouver Chrome
set CHROME_PATH="C:\Program Files\Google\Chrome\Application\chrome.exe"
if not exist %CHROME_PATH% (
    set CHROME_PATH="C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
)

REM Lancer en mode app (sans barre de navigateur)
echo Starting Th3 Thirty3 in standalone mode...
start "" %CHROME_PATH% --app=http://localhost:5173 --window-size=1400,900

echo.
echo App launched! Close this window.
timeout /t 2 >nul
exit
