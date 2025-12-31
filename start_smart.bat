@echo off
REM ===============================================
REM Th3 Thirty3 - SMART MODE LAUNCHER
REM Auto-detects network and uses optimal models
REM ===============================================
REM 
REM ONLINE:  Uses cloud models (Groq - ultra fast)
REM OFFLINE: Uses local Ollama models (granite4:3b, ministral-3)
REM NO Docker, NO GPU training = Maximum performance
REM ===============================================

title Th3 Thirty3 - Smart Mode
color 0a
cls

echo.
echo    ████████╗██╗  ██╗██████╗     ██████╗ ██████╗ 
echo    ╚══██╔══╝██║  ██║╚════██╗    ╚════██╗╚════██╗
echo       ██║   ███████║ █████╔╝     █████╔╝ █████╔╝
echo       ██║   ██╔══██║ ╚═══██╗     ╚═══██╗ ╚═══██╗
echo       ██║   ██║  ██║██████╔╝    ██████╔╝██████╔╝
echo       ╚═╝   ╚═╝  ╚═╝╚═════╝     ╚═════╝ ╚═════╝ 
echo.
echo    [SMART MODE] Performance Optimise
echo    Cloud Online / Ollama Offline
echo.

REM Set variables
set "IS_ONLINE=0"
set "OLLAMA_RUNNING=0"

REM ========================================
REM Step 1: Check Internet Connection
REM ========================================
echo    [1/5] Detection reseau...
ping -n 1 -w 1000 8.8.8.8 >nul 2>&1
if %errorlevel%==0 (
    set "IS_ONLINE=1"
    echo          [OK] Internet disponible - Mode CLOUD
) else (
    ping -n 1 -w 1000 1.1.1.1 >nul 2>&1
    if %errorlevel%==0 (
        set "IS_ONLINE=1"
        echo          [OK] Internet disponible - Mode CLOUD
    ) else (
        echo          [!] Hors ligne - Mode LOCAL
    )
)

REM ========================================
REM Step 2: Start Ollama (always needed as fallback)
REM ========================================
echo    [2/5] Demarrage Ollama...
tasklist /FI "IMAGENAME eq ollama.exe" 2>nul | find /I "ollama.exe" >nul
if %errorlevel%==0 (
    echo          Ollama deja actif
    set "OLLAMA_RUNNING=1"
) else (
    start /min "" ollama serve
    timeout /t 3 /nobreak >nul
    tasklist /FI "IMAGENAME eq ollama.exe" 2>nul | find /I "ollama.exe" >nul
    if %errorlevel%==0 (
        echo          Ollama demarre
        set "OLLAMA_RUNNING=1"
    ) else (
        echo          [!] Echec demarrage Ollama
    )
)

REM ========================================
REM Step 3: Configure Environment Variables
REM ========================================
echo    [3/5] Configuration environnement...

REM Set optimal mode based on network
if %IS_ONLINE%==1 (
    set "PREFERRED_PROVIDER=cloud"
    set "FAILOVER_MODE=AUTO"
    echo          Mode: CLOUD ^(Groq rapide^)
) else (
    set "PREFERRED_PROVIDER=local"  
    set "FAILOVER_MODE=LOCAL_ONLY"
    echo          Mode: LOCAL ^(Ollama^)
)

REM Disable GPU training and Docker by default
set "DISABLE_GPU_TRAINING=true"
set "TRAINING_MODE=manual"
set "TF_CPP_MIN_LOG_LEVEL=3"
echo          GPU Training: DESACTIVE
echo          Docker: NON UTILISE

REM ========================================
REM Step 4: Start Backend Server
REM ========================================
echo    [4/5] Demarrage serveur backend...
cd server
start "Th3 Server" cmd /c "set PREFERRED_PROVIDER=%PREFERRED_PROVIDER%&& set FAILOVER_MODE=%FAILOVER_MODE%&& set TRAINING_MODE=manual&& npm start"
cd ..
timeout /t 4 /nobreak >nul

REM Verify server started
curl -s http://localhost:3000/health >nul 2>&1
if %errorlevel%==0 (
    echo          Backend OK ^(port 3000^)
) else (
    echo          Backend en cours de demarrage...
)

REM ========================================
REM Step 5: Start Frontend
REM ========================================
echo    [5/5] Demarrage interface...
cd interface
start "Th3 Frontend" cmd /c "npm run dev"
cd ..

REM Wait for frontend
timeout /t 5 /nobreak >nul

REM Open browser
start http://localhost:5173

REM ========================================
REM Summary
REM ========================================
echo.
echo    =========================================
echo    Th3 Thirty3 - SMART MODE ACTIF
echo    =========================================
echo.
if %IS_ONLINE%==1 (
    echo    [ONLINE] Mode Cloud Active
    echo    - Modeles: Groq ^(ultra-rapide^)
    echo    - Fallback: Ollama local
) else (
    echo    [OFFLINE] Mode Local Active  
    echo    - Modeles: granite4:3b, ministral-3
    echo    - Embeddings: mxbai-embed-large
)
echo.
echo    URLs:
echo    - Interface: http://localhost:5173
echo    - Backend:   http://localhost:3000
echo    - Ollama:    http://localhost:11434
echo.
echo    Performance:
echo    - Docker:       DESACTIVE
echo    - GPU Training: DESACTIVE  
echo    - Auto-switch:  ACTIVE
echo.
echo    =========================================
echo    Appuie sur une touche pour fermer...
pause >nul
