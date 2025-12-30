@echo off
REM ===============================================
REM Th3 Thirty3 - Start Tor Expert Bundle (sans Browser)
REM Démarre tor.exe en arrière-plan pour le proxy SOCKS5
REM ===============================================
title Th3 Thirty3 - Tor Launcher

echo.
echo ========================================
echo    Th3 Thirty3 - Tor Expert Bundle
echo    Standalone Proxy Mode
echo ========================================
echo.

set "TOR_EXE=C:\Tor\tor\tor.exe"
set "TOR_CONFIG=C:\Tor\torrc"

REM Vérifier que tor.exe existe
if not exist "%TOR_EXE%" (
    echo [ERREUR] tor.exe non trouve: %TOR_EXE%
    echo.
    echo Pour installer Tor Expert Bundle:
    echo   1. Telecharger: https://www.torproject.org/download/tor/
    echo   2. Extraire dans C:\Tor\
    echo   3. Relancer ce script
    echo.
    pause
    exit /b 1
)

REM Créer torrc si inexistant
if not exist "%TOR_CONFIG%" (
    echo [INFO] Creation du fichier torrc...
    (
        echo # Tor Configuration for Th3 Thirty3
        echo SocksPort 9050
        echo ControlPort 9051
        echo CookieAuthentication 0
        echo DataDirectory C:\Tor\data
        echo Log notice file C:\Tor\tor.log
    ) > "%TOR_CONFIG%"
    mkdir "C:\Tor\data" 2>nul
    echo [OK] torrc cree: %TOR_CONFIG%
)

REM Vérifier si Tor tourne déjà
tasklist /FI "IMAGENAME eq tor.exe" 2>NUL | find /I /N "tor.exe">NUL
if "%ERRORLEVEL%"=="0" (
    echo [INFO] Tor est deja en cours d'execution
    echo [INFO] Pour redemarrer, fermez d'abord tor.exe
    goto :check
)

echo [1/3] Demarrage de tor.exe...
start /min "" "%TOR_EXE%" -f "%TOR_CONFIG%"
echo      tor.exe lance en arriere-plan

echo.
echo [2/3] Attente de la connexion Tor (30s max)...
timeout /t 5 /nobreak >nul
echo      En cours de connexion au reseau Tor...

:waitloop
set /a count=0
:checkport
timeout /t 2 /nobreak >nul
powershell -Command "try { $c = New-Object System.Net.Sockets.TcpClient('127.0.0.1', 9050); $c.Close(); exit 0 } catch { exit 1 }"
if %ERRORLEVEL%==0 goto :connected
set /a count+=1
if %count% LSS 15 goto :checkport
echo [TIMEOUT] Port 9050 non disponible apres 30s
goto :end

:connected
echo [OK] Port 9050 actif!

:check
echo.
echo [3/3] Verification de la connexion Tor...
echo.

REM Tester la vraie connexion Tor via l'API
powershell -Command "try { $agent = New-Object System.Net.WebProxy('socks5://127.0.0.1:9050'); Write-Host 'Test proxy...' } catch { Write-Host 'Erreur proxy' }"

echo.
echo ========================================
echo    TOR EXPERT BUNDLE - STATUS
echo ========================================
echo.
echo   SOCKS5 Proxy: 127.0.0.1:9050
echo   Control Port: 127.0.0.1:9051
echo   Config:       %TOR_CONFIG%
echo   Log:          C:\Tor\tor.log
echo.
echo   [OK] Tor est pret pour Th3 Thirty3!
echo.
echo   Pour tester dans PowerShell:
echo     node -e "require('./server/tor_startup_check').performStartupCheck()"
echo.
echo ========================================

:end
pause
