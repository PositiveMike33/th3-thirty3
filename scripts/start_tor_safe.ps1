# ===============================================
# Th3 Thirty3 - Safe Tor Startup
# Demarre Tor en mode securise (localhost only)
# ===============================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

param(
    [switch]$Stop
)

$projectPath = "C:\Users\th3th\th3-thirty3"
$torExe = "C:\Tor\tor\tor.exe"
$safeConfig = "$projectPath\.tor-data\torrc"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Th3 Thirty3 - Tor Securise" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Mode arret
if ($Stop) {
    Write-Host "[STOP] Arret de Tor..." -ForegroundColor Yellow
    $torProcess = Get-Process -Name "tor" -ErrorAction SilentlyContinue
    if ($torProcess) {
        Stop-Process -Name "tor" -Force
        Write-Host "  [OK] Tor arrete" -ForegroundColor Green
    }
    else {
        Write-Host "  [INFO] Tor n'etait pas en cours d'execution" -ForegroundColor Gray
    }
    exit 0
}

# Verifier que tor.exe existe
if (-not (Test-Path $torExe)) {
    Write-Host "[ERREUR] tor.exe non trouve: $torExe" -ForegroundColor Red
    Write-Host ""
    Write-Host "Installation requise:" -ForegroundColor Yellow
    Write-Host "  1. Telecharger Tor Expert Bundle depuis torproject.org" -ForegroundColor Gray
    Write-Host "  2. Extraire dans C:\Tor\" -ForegroundColor Gray
    exit 1
}

# Verifier que la config securisee existe
if (-not (Test-Path $safeConfig)) {
    Write-Host "[ERREUR] Configuration securisee non trouvee: $safeConfig" -ForegroundColor Red
    exit 1
}

# Verifier qu'aucun service Tor systeme n'existe
$torService = Get-Service -Name "Tor" -ErrorAction SilentlyContinue
if ($torService -and $torService.Status -eq "Running") {
    Write-Host "[ALERTE] Un service Tor systeme est actif!" -ForegroundColor Yellow
    Write-Host "  Ce script utilise Tor en mode utilisateur (plus sur)" -ForegroundColor Yellow
    Write-Host "  Voulez-vous arreter le service systeme? (O/N)" -ForegroundColor Yellow
    $response = Read-Host
    if ($response -eq "O" -or $response -eq "o") {
        Stop-Service -Name "Tor" -Force -ErrorAction SilentlyContinue
        Write-Host "  [OK] Service Tor systeme arrete" -ForegroundColor Green
    }
}

# Arreter tout processus Tor existant
$existingTor = Get-Process -Name "tor" -ErrorAction SilentlyContinue
if ($existingTor) {
    Write-Host "[INFO] Arret du processus Tor existant..." -ForegroundColor Yellow
    Stop-Process -Name "tor" -Force
    Start-Sleep -Seconds 2
}

# Demarrer Tor avec la configuration securisee
Write-Host "[1/3] Demarrage de Tor (mode securise)..." -ForegroundColor Yellow
Write-Host "  Config: $safeConfig" -ForegroundColor Gray
Write-Host "  Ecoute: 127.0.0.1:9050 (localhost uniquement)" -ForegroundColor Gray

try {
    Start-Process -FilePath $torExe -ArgumentList "-f `"$safeConfig`"" -WindowStyle Hidden -WorkingDirectory "C:\Tor\tor"
    Write-Host "  [OK] Processus Tor demarre" -ForegroundColor Green
}
catch {
    Write-Host "  [ERREUR] Impossible de demarrer Tor: $_" -ForegroundColor Red
    exit 1
}

# Attendre que Tor etablisse le circuit
Write-Host ""
Write-Host "[2/3] Etablissement du circuit Tor (30 secondes)..." -ForegroundColor Yellow
Write-Host "  " -NoNewline
for ($i = 0; $i -lt 30; $i++) {
    Write-Host "." -NoNewline -ForegroundColor Gray
    Start-Sleep -Seconds 1
    
    # Test rapide toutes les 5 secondes
    if (($i + 1) % 5 -eq 0) {
        $test = Test-NetConnection -ComputerName 127.0.0.1 -Port 9050 -WarningAction SilentlyContinue -InformationLevel Quiet
        if ($test) {
            Write-Host ""
            Write-Host "  [OK] Port 9050 actif apres $($i+1) secondes" -ForegroundColor Green
            break
        }
    }
}

Write-Host ""
Write-Host ""
Write-Host "[3/3] Verification finale..." -ForegroundColor Yellow

# Test du port SOCKS5
$sockTest = Test-NetConnection -ComputerName 127.0.0.1 -Port 9050 -WarningAction SilentlyContinue
if ($sockTest.TcpTestSucceeded) {
    Write-Host "  [OK] SOCKS5 Proxy: 127.0.0.1:9050" -ForegroundColor Green
    
    # Test de connectivite Tor (optionnel)
    Write-Host ""
    Write-Host "  Test IP via Tor..." -ForegroundColor Gray
    try {
        $torIP = curl.exe --socks5 127.0.0.1:9050 -s --max-time 15 "https://api.ipify.org"
        if ($torIP) {
            Write-Host "  [OK] IP Tor: $torIP" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  [INFO] Test IP externe echoue (normal si premier demarrage)" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  TOR SECURISE ACTIF" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Proxy SOCKS5: 127.0.0.1:9050" -ForegroundColor Cyan
    Write-Host "  Mode:         Utilisateur (pas service)" -ForegroundColor Cyan
    Write-Host "  Impact IP:    Aucun (localhost only)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Pour arreter: .\start_tor_safe.ps1 -Stop" -ForegroundColor Gray
    Write-Host ""
}
else {
    Write-Host "  [ALERTE] Port 9050 pas encore actif" -ForegroundColor Yellow
    Write-Host "  Tor demarre mais prend plus de temps" -ForegroundColor Yellow
    Write-Host "  Verifiez le log: $projectPath\.tor-data\tor.log" -ForegroundColor Gray
}
