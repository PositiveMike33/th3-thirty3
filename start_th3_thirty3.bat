@echo off
title Th3 Thirty3 - System Boot
color 0a
cls

echo [SYSTEM] Initializing Th3 Thirty3...

echo [SYSTEM] Cleaning up previous sessions...
taskkill /F /IM node.exe /T >nul 2>&1
echo [SYSTEM] Waiting for ports to release...
timeout /t 5 /nobreak >nul

echo [SYSTEM] Starting Neural Core (Server)...
cd server
start /B npm start
cd ..

echo [SYSTEM] Starting Visual Interface (Frontend)...
cd interface
start /B npm run dev
cd ..

echo [SYSTEM] Launching External Modules...
start "Ollama Server" /min ollama serve
start "" "C:\Users\th3th\AppData\Local\Programs\AnythingLLM\AnythingLLM.exe"

echo [SYSTEM] Pre-loading AI Models...
timeout /t 5 /nobreak >nul
start /min cmd /c "echo /bye | ollama run uandinotai/dolphin-uncensored:latest"
start /min cmd /c "echo /bye | ollama run nomic-embed-text:latest"

echo [SYSTEM] Waiting for connection...
timeout /t 5 /nobreak >nul

echo [SYSTEM] Launching Secure Browser...
start http://localhost:5173

echo [SYSTEM] Systems Online.
echo.
echo  _______  _   _  _______ 
echo ^|__   __^|^| ^| ^| ^|^|___ ___^|
echo    ^| ^|   ^| ^|_^| ^|   ^| ^|   
echo    ^| ^|   ^|  _  ^|   ^| ^|   
echo    ^|_^|   ^|_^| ^|_^|   ^|_^|   
echo.
echo Minimize this window to keep the agent running.
echo Close this window to shut down.
pause
