@echo off
if exist "C:\Tor\tor\tor.exe" (
    echo Starting Tor...
    start /min "" "C:\Tor\tor\tor.exe" -f "C:\Tor\torrc"
    echo Tor started.
) else (
    echo Tor executable not found at C:\Tor\tor\tor.exe
    dir C:\Tor /s
)
timeout /t 5
netstat -ano | findstr :9050
