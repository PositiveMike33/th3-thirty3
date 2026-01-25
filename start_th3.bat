@echo off
title Th3 Thirty3 - Elite Cyber Platform
color 0A
cls

echo.
echo  ████████╗██╗  ██╗██████╗     ████████╗██╗  ██╗██╗██████╗ ████████╗██╗   ██╗██████╗ 
echo  ╚══██╔══╝██║  ██║╚════██╗    ╚══██╔══╝██║  ██║██║██╔══██╗╚══██╔══╝╚██╗ ██╔╝╚════██╗
echo     ██║   ███████║ █████╔╝       ██║   ███████║██║██████╔╝   ██║    ╚████╔╝  █████╔╝
echo     ██║   ██╔══██║ ╚═══██╗       ██║   ██╔══██║██║██╔══██╗   ██║     ╚██╔╝   ╚═══██╗
echo     ██║   ██║  ██║██████╔╝       ██║   ██║  ██║██║██║  ██║   ██║      ██║   ██████╔╝
echo     ╚═╝   ╚═╝  ╚═╝╚═════╝        ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═════╝ 
echo.
echo  ═══════════════════════════════════════════════════════════════════════════════════
echo                     ELITE CYBER PLATFORM - QUEBEC 2026
echo  ═══════════════════════════════════════════════════════════════════════════════════
echo.
echo   [SYSTEM]
echo   ├─ 62 Agents Managed by Orchestrator
echo   ├─ 35 HexStrike Tool Experts (Nmap, Nuclei, SQLMap, Metasploit...)
echo   ├─ 33 Elite Hacker Scenarios (Quebec 2026)
echo   ├─ Gemini 3 Pro (Cloud-Only Mode)
echo   └─ Tor + Kali Container Ready
echo.
echo   [FEATURES]
echo   ├─ /api/hexstrike-experts   - 35 Security Tool Experts
echo   ├─ /api/elite-scenarios     - 33 Attack Chains Scenarios
echo   ├─ /api/hexstrike           - 150+ Security Tools
echo   ├─ /api/orchestrator        - Multi-Agent Missions
echo   └─ /api/hackergpt           - Offensive Security AI
echo.
echo  ═══════════════════════════════════════════════════════════════════════════════════
echo.

cd /d "C:\Users\th3th\th3-thirty3"

echo [1/3] Demarrage du serveur backend...
start "Th3 Server" cmd /k "cd server && node index.js"
timeout /t 5 /nobreak > nul

echo [2/3] Demarrage de l'interface...
start "Th3 Interface" cmd /k "cd interface && npm run dev"
timeout /t 3 /nobreak > nul

echo [3/3] Ouverture du navigateur...
timeout /t 5 /nobreak > nul
start http://localhost:5174

echo.
echo  ═══════════════════════════════════════════════════════════════════════════════════
echo   [READY] Th3 Thirty3 is now running!
echo   
echo   Backend:    http://localhost:3000
echo   Frontend:   http://localhost:5174
echo   Health:     http://localhost:3000/health
echo  ═══════════════════════════════════════════════════════════════════════════════════
echo.
echo   Press any key to close this window (servers will keep running)
pause > nul
