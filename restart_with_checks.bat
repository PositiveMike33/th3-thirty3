@echo off
echo ========================================
echo   TH3 THIRTY3 - RESTART WITH CHECKS
echo ========================================
echo.

echo [1/4] Verifying Ollama models...
ollama list | findstr /C:"nomic-embed-text" >nul
if errorlevel 1 (
    echo    ❌ nomic-embed-text not found!
    echo    📥 Installing now...
    ollama pull nomic-embed-text
) else (
    echo    ✅ nomic-embed-text ready
)

echo.
echo [2/4] Verifying Ollama models...
ollama list | findstr /C:"dolphin-uncensored" >nul
if errorlevel 1 (
    echo    ⚠️  dolphin-uncensored not found (optional)
) else (
    echo    ✅ dolphin-uncensored ready
)

echo.
echo [3/4] Testing hybrid embeddings...
node server\quick_test_embeddings.js
if errorlevel 1 (
    echo    ❌ Embedding test failed!
    echo    Please check the logs above.
    pause
    exit /b 1
)

echo.
echo [4/4] Starting Th3 Thirty3...
echo.
echo ┌─────────────────────────────────────┐
echo │  Systems Ready - Launching...      │
echo └─────────────────────────────────────┘
echo.

start_th3_thirty3.bat
