@echo off
REM Th3 Thirty3 - GPU Training Startup Script
REM Builds and starts the TensorFlow GPU container

echo ============================================
echo   Th3 Thirty3 - GPU Training Service
echo ============================================
echo.

REM Check if Docker is running
docker info > nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Docker is not running. Please start Docker Desktop.
    pause
    exit /b 1
)

echo [1/4] Checking NVIDIA GPU availability...
docker run --rm --gpus all nvidia/cuda:12.0-base nvidia-smi
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] GPU not detected. Will run in CPU mode.
    echo.
)

echo.
echo [2/4] Building GPU training container...
docker compose -f docker-compose.gpu.yml build tensorflow-trainer

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Build failed. Check the error messages above.
    pause
    exit /b 1
)

echo.
echo [3/4] Starting GPU training service...
docker compose -f docker-compose.gpu.yml up -d tensorflow-trainer

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to start container.
    pause
    exit /b 1
)

echo.
echo [4/4] Waiting for service to be ready...
timeout /t 10 /nobreak > nul

REM Check health
curl -s http://localhost:5000/health
echo.

echo.
echo ============================================
echo   GPU Training Service Started!
echo ============================================
echo.
echo   Training API:    http://localhost:5000
echo   TensorBoard:     http://localhost:6006
echo   Health Check:    http://localhost:5000/health
echo   GPU Info:        http://localhost:5000/api/gpu/info
echo.
echo   To start training:
echo   curl -X POST http://localhost:5000/api/train/start -H "Content-Type: application/json" -d "{\"category\":\"security\",\"iterations\":5}"
echo.
echo   To view logs:
echo   docker logs -f th3-gpu-trainer
echo.
pause
