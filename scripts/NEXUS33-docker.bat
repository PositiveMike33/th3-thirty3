@echo off
title NEXUS33 - Docker Mode
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
echo    [DOCKER MODE] Starting NEXUS33 Platform...
echo.

:: Check Docker
echo    [1/4] Checking Docker...
docker --version >nul 2>&1
if errorlevel 1 (
    echo          ERROR: Docker not running!
    echo          Please start Docker Desktop first.
    pause
    exit /b 1
)
echo          Docker OK

:: Check GPU option
set GPU_MODE=0
if "%1"=="--gpu" set GPU_MODE=1
if "%1"=="-g" set GPU_MODE=1

:: Start Ollama locally (GPU acceleration works better on host)
echo    [2/4] Starting Ollama...
tasklist /FI "IMAGENAME eq ollama.exe" | find /I "ollama.exe" >nul
if errorlevel 1 (
    start /min "" ollama serve
    echo          Ollama started
    timeout /t 3 /nobreak >nul
) else (
    echo          Ollama already running
)

:: Start with Docker Compose
echo    [3/4] Starting Docker containers...
if %GPU_MODE%==1 (
    echo          [GPU MODE ENABLED]
    docker compose -f docker-compose.gpu.yml up -d --build
) else (
    docker compose up -d --build
)

:: Wait for services
echo    [4/4] Waiting for services...
timeout /t 10 /nobreak >nul

:: Health check
echo.
echo    Checking health...
curl -s http://localhost:3000/health >nul 2>&1
if errorlevel 1 (
    echo          Backend: Starting...
) else (
    echo          Backend: OK
)

:: Open browser
start http://localhost:5174

echo.
echo    ========================================
echo    NEXUS33 is running in Docker!
echo    ========================================
echo.
echo    Dashboard: http://localhost:5174
echo    Backend:   http://localhost:3000
echo    Ollama:    http://localhost:11434
echo.
echo    Commands:
echo      docker compose logs -f     (view logs)
echo      docker compose down        (stop all)
echo      NEXUS33-docker --gpu       (GPU mode)
echo.
echo    Press any key to close...
pause >nul
