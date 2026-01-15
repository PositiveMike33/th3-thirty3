# Restart Protocol for Thirty3
Write-Host "Initiating Restart Protocol..." -ForegroundColor Cyan

# 1. Kill existing Node server process
$port = 3000
$process = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique

if ($process) {
    Write-Host "Stopping server on port $port (PID: $process)..." -ForegroundColor Yellow
    Stop-Process -Id $process -Force -ErrorAction SilentlyContinue
    Write-Host "Server stopped." -ForegroundColor Green
}
else {
    Write-Host "No server found running on port $port." -ForegroundColor Gray
}

# 2. Cleanup Temporary Files (Optional)
# Add specific cleanup logic here if needed
# Remove-Item "server\*.tmp" -ErrorAction SilentlyContinue

# 3. System Integrity Check (Self-Healing)
Write-Host "Running System Integrity Check (Self-Healing)..." -ForegroundColor Cyan
node server/self_heal.js
if ($LASTEXITCODE -ne 0) {
    Write-Host "System Check Failed. Aborting Restart." -ForegroundColor Red
    exit 1
}

# 4. Restart Server
Write-Host "Restarting Server..." -ForegroundColor Cyan
Start-Process "node" -ArgumentList "server/index.js" -NoNewWindow
Write-Host "Server restarted successfully." -ForegroundColor Green
