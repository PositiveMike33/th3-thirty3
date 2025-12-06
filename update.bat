@echo off
REM ===============================================
REM Th3 Thirty3 - Update Script
REM ===============================================
echo.
echo ========================================
echo    Th3 Thirty3 - Update
echo ========================================
echo.

echo [1/4] Pulling latest changes from GitHub...
git pull origin main

echo.
echo [2/4] Updating Fabric patterns...
if exist "server\fabric" (
    cd server\fabric
    git pull
    cd ..\..
) else (
    echo       Fabric not found, cloning...
    git clone --depth 1 https://github.com/danielmiessler/fabric.git server\fabric
)

echo.
echo [3/4] Updating server dependencies...
cd server
call npm install
cd ..

echo.
echo [4/4] Updating interface dependencies...
cd interface
call npm install
cd ..

echo.
echo ========================================
echo    Update Complete!
echo ========================================
echo.
echo To start the app:
echo   Server: cd server ^&^& npm start
echo   Interface: cd interface ^&^& npm run dev
echo.
pause
