@echo off
:: Configure Ollama Proxy Server for Th3 Thirty3
:: Run this script once to setup the proxy

cd /d "%~dp0ollama_proxy_server"

echo Creating .env configuration...
(
echo # Ollama Proxy Server - Th3 Thirty3 Config
echo DATABASE_URL=sqlite+aiosqlite:///./ollama_proxy.db
echo ADMIN_USER=th3-thirty3
echo ADMIN_PASSWORD=Th3Thirty3Proxy2024!
echo PROXY_PORT=8080
echo SECRET_KEY=593c85d5bf0f04a2e882b8d4769dea4eab19b236644aa910d07013ebacdf1952
echo LOG_LEVEL=info
) > .env

echo Configuration created!
echo.
echo Admin Login:
echo   URL: http://localhost:8080
echo   User: th3-thirty3
echo   Password: Th3Thirty3Proxy2024!
echo.
pause
