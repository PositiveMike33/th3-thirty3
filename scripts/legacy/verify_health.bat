@echo off
echo [HEALTH CHECK] Starting diagnostics...
cd server
node verify_health.js
cd ..
pause
