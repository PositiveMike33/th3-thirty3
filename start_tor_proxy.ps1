# ===============================================
# Th3 Thirty3 - Auto-Start Tor (tor.exe)
# Lance tor.exe en arrière-plan au démarrage
# ===============================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Configuration Tor Auto-Start" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Vérifier que tor.exe existe
$torExe = "C:\Tor\tor\tor.exe"
$torrc = "C:\Tor\torrc"

if (-not (Test-Path $torExe)) {
    Write-Host "[ERREUR] tor.exe non trouvé: $torExe" -ForegroundColor Red
    Write-Host "Exécute d'abord: .\install_tor_service_v2.ps1" -ForegroundColor Yellow
    pause
    exit
}

Write-Host "[1/3] Création du script de démarrage automatique..." -ForegroundColor Cyan

# Script batch qui lance tor.exe au démarrage
$startupScript = @"
@echo off
title Tor Proxy Service - Th3 Thirty3
cd /d C:\Tor\tor
start /min `"`" tor.exe -f C:\Tor\torrc
exit
"@

$startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\StartTor.bat"
Set-Content -Path $startupPath -Value $startupScript -Encoding ASCII

Write-Host "  [OK] Script créé: $startupPath" -ForegroundColor Green
Write-Host "  [INFO] Tor démarrera automatiquement au prochain boot Windows" -ForegroundColor Gray

Write-Host ""
Write-Host "[2/3] Lancement de tor.exe maintenant..." -ForegroundColor Cyan

# Arrêter tor.exe s'il tourne déjà
$torProcess = Get-Process -Name "tor" -ErrorAction SilentlyContinue
if ($torProcess) {
    Write-Host "  [INFO] Arrêt de l'instance existante..." -ForegroundColor Yellow
    Stop-Process -Name "tor" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# Lancer tor.exe en arrière-plan
$torArgs = "-f `"$torrc`""
Start-Process -FilePath $torExe -ArgumentList $torArgs -WindowStyle Hidden -WorkingDirectory "C:\Tor\tor"

Write-Host "  [OK] tor.exe lancé en arrière-plan" -ForegroundColor Green

Write-Host ""
Write-Host "[3/3] Attente de la connexion au réseau Tor (30s)..." -ForegroundColor Cyan
Write-Host "  [INFO] Tor établit un circuit anonyme..." -ForegroundColor Gray

Start-Sleep -Seconds 30

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  VÉRIFICATION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Test du port SOCKS5
$test = Test-NetConnection -ComputerName 127.0.0.1 -Port 9050 -WarningAction SilentlyContinue

if ($test.TcpTestSucceeded) {
    Write-Host "✅ PORT 9050 ACTIF!" -ForegroundColor Green
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  TOR PROXY OPÉRATIONNEL" -ForegroundColor Green
    Write-Host "  SOCKS5: 127.0.0.1:9050" -ForegroundColor Green
    Write-Host "  Démarrage auto: OUI" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Le monitor Tor dans Brave affichera:" -ForegroundColor Cyan
    Write-Host "  🟢 TOR ACTIVE" -ForegroundColor Green
    Write-Host ""
    Write-Host "Rafraîchis l'interface Th3 Thirty3 !" -ForegroundColor Yellow
}
else {
    Write-Host "⚠️ Port 9050 pas encore actif" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Tor est en train de se connecter au réseau." -ForegroundColor Gray
    Write-Host "Patiente 1-2 minutes, puis reteste avec:" -ForegroundColor Gray
    Write-Host "  Test-NetConnection -ComputerName 127.0.0.1 -Port 9050" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Configuration:" -ForegroundColor Cyan
Write-Host "  - Processus: tor.exe (arrière-plan)" -ForegroundColor Gray
Write-Host "  - Config: $torrc" -ForegroundColor Gray
Write-Host "  - Log: C:\Tor\tor.log" -ForegroundColor Gray
Write-Host "  - Auto-start: $startupPath" -ForegroundColor Gray
Write-Host ""

# Ne pas bloquer le script
Write-Host "Initialisation terminée. Le démarrage continue..." -ForegroundColor Cyan
exit 0
