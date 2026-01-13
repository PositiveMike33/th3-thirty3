@echo off
REM ===============================================
REM Th3 Thirty3 - Installation Script
REM ===============================================
echo.
echo ========================================
echo    Th3 Thirty3 - Installation
echo ========================================
echo.

REM Check if Node.js is installed
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not installed!
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

echo [1/5] Cloning Fabric patterns...
if not exist "server\fabric" (
    git clone --depth 1 https://github.com/danielmiessler/fabric.git server\fabric
) else (
    echo       Fabric already exists, updating...
    cd server\fabric && git pull && cd ..\..
)

echo.
echo [2/5] Installing server dependencies...
cd server
call npm install
cd ..

echo.
echo [3/5] Installing interface dependencies...
cd interface
call npm install
cd ..

echo.
echo [4/5] Creating .env template if not exists...
if not exist "server\.env" (
    echo PORT=3000 > server\.env
    echo GEMINI_API_KEY=your_gemini_api_key >> server\.env
    echo OLLAMA_URL=http://localhost:11434 >> server\.env
    echo ANYTHING_LLM_URL=http://localhost:3001/api/v1 >> server\.env
    echo ANYTHING_LLM_KEY=your_key >> server\.env
    echo AIKIDO_API_TOKEN=your_aikido_token >> server\.env
    echo.
    echo [!] Created server/.env template - Please configure your API keys!
)

echo.
echo [5/5] Checking Ollama...
where ollama >nul 2>nul
if %errorlevel% neq 0 (
    echo [!] Ollama not found. Install from https://ollama.com/
) else (
    echo       Pulling required models...
    ollama pull qwen2.5:3b
    ollama pull nomic-embed-text
)

echo.
echo ========================================
echo    Installation Complete!
echo ========================================
echo.
echo Next steps:
echo   1. Configure server/.env with your API keys
echo   2. Run: npm start (in server folder)
echo   3. Run: npm run dev (in interface folder)
echo.
pause
