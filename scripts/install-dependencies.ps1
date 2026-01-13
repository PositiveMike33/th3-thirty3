# ===========================================
# INSTALLATION COMPLETE TH3-THIRTY3
# ===========================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   INSTALLATION DEPENDANCES TH3-THIRTY3" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$projectPath = "C:\Users\th3th\th3-thirty3"

# 1. Verifier Node.js
Write-Host "`n[1/4] Verification Node.js..." -ForegroundColor Yellow
$nodeInstalled = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeInstalled) {
    Write-Host "   Node.js non trouve. Installation via winget..." -ForegroundColor Gray
    winget install OpenJS.NodeJS.LTS --accept-package-agreements --accept-source-agreements --silent
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    $nodeInstalled = Get-Command node -ErrorAction SilentlyContinue
    if (-not $nodeInstalled) {
        Write-Host "   [!] Node.js installe mais necessite un nouveau terminal" -ForegroundColor Yellow
        Write-Host "   Fermez ce terminal, ouvrez-en un nouveau, et relancez ce script" -ForegroundColor Yellow
        pause
        exit
    }
}
Write-Host "   [OK] Node.js $(node --version)" -ForegroundColor Green

# 2. Installer dependances Server
Write-Host "`n[2/4] Installation dependances Server..." -ForegroundColor Yellow
Set-Location "$projectPath\server"
npm install --legacy-peer-deps 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "   [OK] Server: packages installes" -ForegroundColor Green
}
else {
    Write-Host "   [X] Erreur installation server" -ForegroundColor Red
}

# 3. Installer dependances Interface
Write-Host "`n[3/4] Installation dependances Interface..." -ForegroundColor Yellow
Set-Location "$projectPath\interface"
npm install --legacy-peer-deps 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "   [OK] Interface: packages installes" -ForegroundColor Green
}
else {
    Write-Host "   [X] Erreur installation interface" -ForegroundColor Red
}

# 4. Verifier Docker
Write-Host "`n[4/4] Verification Docker..." -ForegroundColor Yellow
$dockerRunning = docker info 2>&1 | Select-String "Server Version"
if ($dockerRunning) {
    Write-Host "   [OK] Docker fonctionne" -ForegroundColor Green
}
else {
    Write-Host "   [!] Docker Desktop doit etre demarre" -ForegroundColor Yellow
    Write-Host "   Demarrez Docker Desktop manuellement" -ForegroundColor Yellow
}

# Resume
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "   INSTALLATION TERMINEE!              " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "`nPour lancer le projet:" -ForegroundColor White
Write-Host "  cd $projectPath" -ForegroundColor Gray
Write-Host "  docker compose -f docker-compose.gpu.yml up -d" -ForegroundColor Gray

Set-Location $projectPath
