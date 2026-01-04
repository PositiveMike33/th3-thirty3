@echo off
REM ===============================================
REM Th3 Thirty3 - Safe Mode Startup
REM Verifie l'integrite reseau AVANT de demarrer
REM ===============================================
title Th3 Thirty3 - Safe Mode
color 0a
cls

echo.
echo    ========================================
echo      Th3 Thirty3 - MODE SECURISE
echo    ========================================
echo.

REM Etape 1: Verification integrite reseau
echo    [1/4] Verification integrite reseau...
powershell -ExecutionPolicy Bypass -File "%~dp0scripts\verify_network_integrity.ps1"
if errorlevel 1 (
    echo.
    echo    [ALERTE] Problemes reseau detectes!
    echo    Verifiez votre configuration avant de continuer.
    echo.
    pause
)

REM Etape 2: Demarrer Ollama si pas actif
echo.
echo    [2/4] Verification Ollama...
tasklist /FI "IMAGENAME eq ollama.exe" 2>NUL | find /I /N "ollama.exe">NUL
if "%ERRORLEVEL%"=="1" (
    echo          Demarrage Ollama...
    start /min "" ollama serve
    timeout /t 3 /nobreak >nul
) else (
    echo          Ollama deja actif
)

REM Etape 3: Demarrer le serveur backend
echo.
echo    [3/4] Demarrage serveur backend (port 3000)...
cd /d "%~dp0server"
start "Th3 Server" cmd /k "npm start"
cd /d "%~dp0"
timeout /t 3 /nobreak >nul

REM Etape 4: Demarrer le frontend
echo.
echo    [4/4] Demarrage interface (port 5173)...
cd /d "%~dp0interface"
start "Th3 Interface" cmd /k "npm run dev"
cd /d "%~dp0"
timeout /t 5 /nobreak >nul

echo.
echo    ========================================
echo      Th3 Thirty3 - PRET
echo    ========================================
echo.
echo    Interface:  http://localhost:5173
echo    Backend:    http://localhost:3000
echo.
echo    Tor:        NON demarre (mode securise)
echo                Pour activer Tor:
echo                .\scripts\start_tor_safe.ps1
echo.
echo    Votre IP:   PROTEGEE (pas de modification)
echo.

REM Ouvrir le navigateur
start http://localhost:5173

echo    Appuyez sur une touche pour fermer cette fenetre...
echo    (Les services continueront en arriere-plan)
pause >nul
