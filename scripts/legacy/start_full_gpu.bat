@echo off
REM Th3 Thirty3 - Full Stack with GPU
REM Starts all services including GPU training

echo ============================================
echo   Th3 Thirty3 - Full Stack (GPU Enabled)
echo ============================================
echo.

REM Check Docker
docker info > nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Docker is not running.
    pause
    exit /b 1
)

echo [1/5] Stopping any existing containers...
docker compose -f docker-compose.gpu.yml down 2>nul

echo.
echo [2/5] Building all services...
docker compose -f docker-compose.gpu.yml build

echo.
echo [3/5] Starting services...
docker compose -f docker-compose.gpu.yml up -d

echo.
echo [4/5] Waiting for services to initialize...
timeout /t 15 /nobreak > nul

echo.
echo [5/5] Checking service health...
echo.
echo GPU Trainer:
curl -s http://localhost:5000/health 2>nul || echo   [NOT READY]
echo.
echo Backend:
curl -s http://localhost:3000/health 2>nul || echo   [NOT READY]
echo.

echo ============================================
echo   All Services Started!
echo ============================================
echo.
echo   Frontend:        http://localhost:5174
echo   Backend API:     http://localhost:3000
echo   GPU Trainer:     http://localhost:5000
echo   TensorBoard:     http://localhost:6006
echo.
echo   View logs: docker compose -f docker-compose.gpu.yml logs -f
echo.
pause
