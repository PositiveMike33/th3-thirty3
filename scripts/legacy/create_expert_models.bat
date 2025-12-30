@echo off
echo ========================================
echo Th3 Thirty3 - Creating Expert Models
echo ========================================
echo.

cd /d "C:\Users\th3th\.Th3Thirty3\thethirty3"

echo [1/2] Creating DDoS Expert Model...
ollama create ddos-expert-33 -f Modelfile.ddos-expert
if %ERRORLEVEL% EQU 0 (
    echo [OK] ddos-expert-33 created successfully
) else (
    echo [FAIL] Failed to create ddos-expert-33
)

echo.
echo [2/2] Creating OSINT Shodan Expert Model...
ollama create osint-shodan-33 -f Modelfile.osint-shodan
if %ERRORLEVEL% EQU 0 (
    echo [OK] osint-shodan-33 created successfully
) else (
    echo [FAIL] Failed to create osint-shodan-33
)

echo.
echo ========================================
echo Verifying models...
echo ========================================
ollama list

echo.
echo Done! Press any key to exit.
pause > nul
