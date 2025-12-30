@echo off
echo [DEBUG] Starting Server with logging...
cd server
npm start > server.log 2>&1
cd ..
