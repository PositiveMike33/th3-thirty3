# Tor Management Script for Th3 Thirty3
# Quick commands for managing Tor service

param(
    [Parameter(Position=0)]
    [ValidateSet('start', 'stop', 'restart', 'status', 'logs', 'test')]
    [string]$Action = 'status'
)

$TorExe = "C:\Tor\tor\tor.exe"
$Torrc = "C:\Tor\torrc"
$TorLog = "C:\Tor\tor.log"
$ProjectDir = "C:\Users\th3th\.Th3Thirty3\thethirty3"

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""
}

function Start-TorService {
    Write-Header "STARTING TOR"
    
    # Check if already running
    $process = Get-Process -Name "tor" -ErrorAction SilentlyContinue
    if ($process) {
        Write-Host "  [!] Tor is already running (PID: $($process.Id))" -ForegroundColor Yellow
        return
    }
    
    # Check if tor.exe exists
    if (-not (Test-Path $TorExe)) {
        Write-Host "  [X] tor.exe not found at: $TorExe" -ForegroundColor Red
        Write-Host "  [>] Please install Tor Expert Bundle" -ForegroundColor Yellow
        return
    }
    
    # Start Tor
    Write-Host "  [*] Starting Tor..." -ForegroundColor Green
    Start-Process -FilePath $TorExe -ArgumentList "-f", $Torrc -WindowStyle Hidden
    
    # Wait and verify
    Start-Sleep -Seconds 5
    $process = Get-Process -Name "tor" -ErrorAction SilentlyContinue
    if ($process) {
        Write-Host "  [+] Tor started successfully (PID: $($process.Id))" -ForegroundColor Green
        
        # Test connection
        Start-Sleep -Seconds 10
        Write-Host "  [*] Testing connection..." -ForegroundColor Cyan
        node "$ProjectDir\scripts\tor_status.js"
    } else {
        Write-Host "  [X] Failed to start Tor" -ForegroundColor Red
        Write-Host "  [>] Check logs: $TorLog" -ForegroundColor Yellow
    }
}

function Stop-TorService {
    Write-Header "STOPPING TOR"
    
    $process = Get-Process -Name "tor" -ErrorAction SilentlyContinue
    if (-not $process) {
        Write-Host "  [!] Tor is not running" -ForegroundColor Yellow
        return
    }
    
    Write-Host "  [*] Stopping Tor (PID: $($process.Id))..." -ForegroundColor Yellow
    Stop-Process -Name "tor" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    
    $process = Get-Process -Name "tor" -ErrorAction SilentlyContinue
    if (-not $process) {
        Write-Host "  [+] Tor stopped successfully" -ForegroundColor Green
    } else {
        Write-Host "  [X] Failed to stop Tor" -ForegroundColor Red
    }
}

function Restart-TorService {
    Write-Header "RESTARTING TOR"
    Stop-TorService
    Start-Sleep -Seconds 2
    Start-TorService
}

function Get-TorStatus {
    Write-Header "TOR STATUS"
    
    # Check process
    $process = Get-Process -Name "tor" -ErrorAction SilentlyContinue
    if ($process) {
        Write-Host "  Process:      [+] RUNNING (PID: $($process.Id))" -ForegroundColor Green
        Write-Host "  Start Time:   $($process.StartTime)" -ForegroundColor Gray
        Write-Host "  Memory:       $([math]::Round($process.WorkingSet64 / 1MB, 2)) MB" -ForegroundColor Gray
    } else {
        Write-Host "  Process:      [X] NOT RUNNING" -ForegroundColor Red
        Write-Host ""
        Write-Host "  To start Tor, run:" -ForegroundColor Yellow
        Write-Host "    .\manage_tor.ps1 start" -ForegroundColor Cyan
        return
    }
    
    Write-Host ""
    
    # Check ports
    Write-Host "  Checking ports..." -ForegroundColor Cyan
    Write-Host ""
    
    # SOCKS Port
    $socks = Test-NetConnection -ComputerName 127.0.0.1 -Port 9050 -WarningAction SilentlyContinue
    if ($socks.TcpTestSucceeded) {
        Write-Host "  SOCKS Port:   [+] LISTENING (9050)" -ForegroundColor Green
    } else {
        Write-Host "  SOCKS Port:   [X] NOT LISTENING (9050)" -ForegroundColor Red
    }
    
    # Control Port
    $control = Test-NetConnection -ComputerName 127.0.0.1 -Port 9051 -WarningAction SilentlyContinue
    if ($control.TcpTestSucceeded) {
        Write-Host "  Control Port: [+] LISTENING (9051)" -ForegroundColor Green
    } else {
        Write-Host "  Control Port: [X] NOT LISTENING (9051)" -ForegroundColor Red
    }
    
    Write-Host ""
    
    # Test authentication
    if ($control.TcpTestSucceeded) {
        Write-Host "  Testing authentication..." -ForegroundColor Cyan
        node "$ProjectDir\scripts\tor_status.js"
    }
}

function Show-TorLogs {
    Write-Header "TOR LOGS (Last 30 lines)"
    
    if (Test-Path $TorLog) {
        Get-Content $TorLog -Tail 30 | ForEach-Object {
            if ($_ -match '\[warn\]') {
                Write-Host $_ -ForegroundColor Yellow
            } elseif ($_ -match '\[err\]') {
                Write-Host $_ -ForegroundColor Red
            } elseif ($_ -match '\[notice\]' -and $_ -match 'Bootstrapped') {
                Write-Host $_ -ForegroundColor Green
            } else {
                Write-Host $_ -ForegroundColor Gray
            }
        }
        
        Write-Host ""
        Write-Host "  Full log: $TorLog" -ForegroundColor Cyan
    } else {
        Write-Host "  [!] Log file not found: $TorLog" -ForegroundColor Yellow
    }
}

function Test-TorConnection {
    Write-Header "TOR CONNECTION TEST"
    
    # Quick status check
    Write-Host "  Running quick status check..." -ForegroundColor Cyan
    Write-Host ""
    node "$ProjectDir\scripts\tor_status.js"
    
    $quickTest = $LASTEXITCODE
    
    if ($quickTest -eq 0) {
        Write-Host ""
        Write-Host "  Run comprehensive tests? (y/n): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        
        if ($response -eq 'y') {
            Write-Host ""
            Write-Host "  Running comprehensive test suite..." -ForegroundColor Cyan
            Write-Host ""
            node "$ProjectDir\server\tests\test_tor_secure_connection.js"
        }
    }
}

# Main script execution
switch ($Action) {
    'start'   { Start-TorService }
    'stop'    { Stop-TorService }
    'restart' { Restart-TorService }
    'status'  { Get-TorStatus }
    'logs'    { Show-TorLogs }
    'test'    { Test-TorConnection }
}

Write-Host ""
Write-Host "Available commands:" -ForegroundColor Cyan
Write-Host "  .\manage_tor.ps1 start   - Start Tor service" -ForegroundColor Gray
Write-Host "  .\manage_tor.ps1 stop    - Stop Tor service" -ForegroundColor Gray
Write-Host "  .\manage_tor.ps1 restart - Restart Tor service" -ForegroundColor Gray
Write-Host "  .\manage_tor.ps1 status  - Show Tor status" -ForegroundColor Gray
Write-Host "  .\manage_tor.ps1 logs    - Show Tor logs" -ForegroundColor Gray
Write-Host "  .\manage_tor.ps1 test    - Test Tor connection" -ForegroundColor Gray
Write-Host ""
