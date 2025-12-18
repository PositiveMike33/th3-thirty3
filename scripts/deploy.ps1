# ===========================================
# Nexus33 Deployment Script (Windows PowerShell)
# ===========================================
# This script automates the deployment of Nexus33
# to your production server (nexus33.io)
# ===========================================

param(
    [switch]$LocalOnly,
    [string]$Host = "nexus33.io",
    [string]$User = "root",
    [string]$DeployPath = "/var/www/nexus33"
)

$ErrorActionPreference = "Stop"

# Colors
function Write-Step { Write-Host "▶ $args" -ForegroundColor Green }
function Write-Warn { Write-Host "⚠ $args" -ForegroundColor Yellow }
function Write-Err { Write-Host "✖ $args" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     NEXUS33 DEPLOYMENT SCRIPT (Windows)        ║" -ForegroundColor Cyan
Write-Host "╠════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║ Host: $Host" -ForegroundColor Cyan
Write-Host "║ Path: $DeployPath" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ===========================================
# STEP 1: Pre-flight checks
# ===========================================
Write-Step "STEP 1: Pre-flight checks..."

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

if (-not (Test-Path "interface")) {
    Write-Err "Please run this script from the project root or scripts directory"
}

# Check npm
try { npm --version | Out-Null } catch { Write-Err "npm is required but not installed" }

Write-Host "✓ All pre-flight checks passed" -ForegroundColor Green

# ===========================================
# STEP 2: Build Frontend
# ===========================================
Write-Step "STEP 2: Building frontend..."

Set-Location "interface"
npm ci --silent
npm run build

if (-not (Test-Path "dist")) {
    Write-Err "Frontend build failed - dist folder not found"
}

Write-Host "✓ Frontend built successfully" -ForegroundColor Green
Set-Location $projectRoot

# ===========================================
# STEP 3: Prepare deployment package
# ===========================================
Write-Step "STEP 3: Preparing deployment package..."

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$deployDir = "deploy_$timestamp"
$archiveName = "nexus33_deploy_$timestamp.zip"

# Create deployment directory
New-Item -ItemType Directory -Path $deployDir -Force | Out-Null

# Copy backend (excluding node_modules and .env)
Copy-Item -Path "server" -Destination "$deployDir/server" -Recurse
Remove-Item -Path "$deployDir/server/node_modules" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$deployDir/server/.env" -Force -ErrorAction SilentlyContinue

# Copy frontend build
Copy-Item -Path "interface/dist" -Destination "$deployDir/interface-dist" -Recurse

# Copy deployment configs
if (Test-Path "docker-compose.prod.yml") {
    Copy-Item "docker-compose.prod.yml" "$deployDir/"
}
if (Test-Path "docs/DEPLOYMENT_NEXUS33.md") {
    Copy-Item "docs/DEPLOYMENT_NEXUS33.md" "$deployDir/README.md"
}

# Create deployment info
$gitCommit = try { git rev-parse HEAD } catch { "unknown" }
$deployInfo = @{
    deployedAt = (Get-Date -Format "o")
    branch = "main"
    commit = $gitCommit
    host = $Host
} | ConvertTo-Json

Set-Content -Path "$deployDir/deploy_info.json" -Value $deployInfo

# Create ZIP archive
Compress-Archive -Path "$deployDir/*" -DestinationPath $archiveName -Force

Write-Host "✓ Deployment package created: $archiveName" -ForegroundColor Green

# Cleanup temp directory
Remove-Item -Path $deployDir -Recurse -Force

# ===========================================
# STEP 4: Deploy or provide instructions
# ===========================================
Write-Step "STEP 4: Deployment..."

if ($LocalOnly) {
    Write-Host "Local build only. Skipping remote deployment." -ForegroundColor Yellow
    Write-Host "Archive ready: $archiveName" -ForegroundColor Green
} else {
    Write-Warn "Remote SSH deployment not automated on Windows"
    Write-Host ""
    Write-Host "Archive is ready for manual deployment: $archiveName" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Manual deployment via SCP/SSH:" -ForegroundColor Yellow
    Write-Host "1. Upload archive: scp $archiveName ${User}@${Host}:/tmp/" -ForegroundColor White
    Write-Host "2. SSH to server: ssh ${User}@${Host}" -ForegroundColor White
    Write-Host "3. Extract: tar -xzf /tmp/$archiveName -C $DeployPath" -ForegroundColor White
    Write-Host "4. Install deps: cd $DeployPath/server && npm ci --production" -ForegroundColor White
    Write-Host "5. Copy frontend: cp -r interface-dist/* /var/www/nexus33-frontend/" -ForegroundColor White
    Write-Host "6. Restart: pm2 restart nexus33-backend" -ForegroundColor White
}

Write-Host ""
Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     DEPLOYMENT SUMMARY                         ║" -ForegroundColor Cyan
Write-Host "╠════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║ Archive: $archiveName" -ForegroundColor Cyan
Write-Host "║ Frontend: Built ✓" -ForegroundColor Cyan
Write-Host "║ Backend: Packaged ✓" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Return to original location
Set-Location $projectRoot
