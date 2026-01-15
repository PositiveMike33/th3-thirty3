# ===============================================
# Th3 Thirty3 - Installation Tor Expert Bundle
# Version Alternative avec Téléchargement Direct
# ===============================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Tor Expert Bundle - Installation v2" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Vérifier Admin
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[ERREUR] Privilèges Administrateur requis!" -ForegroundColor Red
    pause
    exit
}

$installPath = "C:\Tor"
$dataDir = "$installPath\Data"

Write-Host "[1/5] Téléchargement depuis GitHub (archive alternative)..." -ForegroundColor Cyan

# Utiliser une archive directe depuis un miroir fiable
$torUrl = "https://github.com/TheTorProject/gettorbrowser/releases/download/v13.0.1/tor-expert-bundle-13.0.1-windows-x86_64.tar.gz"
$downloadPath = "$env:TEMP\tor-expert.tar.gz"

try {
    Invoke-WebRequest -Uri $torUrl -OutFile $downloadPath -UseBasicParsing -ErrorAction Stop
    Write-Host "  [OK] Téléchargé" -ForegroundColor Green
} catch {
    Write-Host "  [INFO] Source GitHub échouée, utilisation de build local..." -ForegroundColor Yellow
    
    # Alternative: Télécharger depuis torproject.org (dernière version stable)
    $torUrl = "https://archive.torproject.org/tor-package-archive/torbrowser/13.0/tor-expert-bundle-windows-x86_64-13.0.tar.gz"
    
    try {
        Invoke-WebRequest -Uri $torUrl -OutFile $downloadPath -UseBasicParsing -ErrorAction Stop
        Write-Host "  [OK] Téléchargé depuis archive" -ForegroundColor Green
    } catch {
        Write-Host "  [ERREUR] Impossible de télécharger Tor" -ForegroundColor Red
        Write-Host "  [SOLUTION] Téléchargez manuellement: https://www.torproject.org/download/tor/" -ForegroundColor Yellow
        pause
        exit
    }
}

Write-Host ""
Write-Host "[2/5] Extraction..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $installPath | Out-Null
tar -xzf $downloadPath -C $installPath
Write-Host "  [OK] Fichiers extraits dans $installPath" -ForegroundColor Green

Write-Host ""
Write-Host "[3/5] Configuration..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

# Trouver tor.exe
$torExe = Get-ChildItem -Path $installPath -Filter "tor.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName

if (-not $torExe) {
    Write-Host "  [ERREUR] tor.exe non trouvé!" -ForegroundColor Red
    Write-Host "  Contenu de $installPath :" -ForegroundColor Yellow
    Get-ChildItem $installPath -Recurse | Select-Object FullName
    pause
    exit
}

Write-Host "  [OK] Tor trouvé: $torExe" -ForegroundColor Green

$torrcPath = "$installPath\torrc"
$torrcContent = @"
# Tor Configuration - Th3 Thirty3
SocksPort 127.0.0.1:9050
ControlPort 9051
DataDirectory $dataDir
CookieAuthentication 1
Log notice file $installPath\tor.log
"@

Set-Content -Path $torrcPath -Value $torrcContent -Encoding UTF8
Write-Host "  [OK] Configuration créée" -ForegroundColor Green

Write-Host ""
Write-Host "[4/5] Création du service Windows..." -ForegroundColor Cyan

# Nettoyer ancien service
$existing = Get-Service -Name "Tor" -ErrorAction SilentlyContinue
if ($existing) {
    Stop-Service -Name "Tor" -Force -ErrorAction SilentlyContinue
    sc.exe delete Tor | Out-Null
    Start-Sleep -Seconds 2
}

# Créer le service
New-Service -Name "Tor" `
            -BinaryPathName "`"$torExe`" -f `"$torrcPath`"" `
            -DisplayName "Tor Proxy (Th3 Thirty3)" `
            -Description "SOCKS5 Proxy sur port 9050" `
            -StartupType Automatic | Out-Null

Write-Host "  [OK] Service créé" -ForegroundColor Green

Write-Host ""
Write-Host "[5/5] Démarrage..." -ForegroundColor Cyan
Start-Service -Name "Tor"
Start-Sleep -Seconds 15

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  VÉRIFICATION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$test = Test-NetConnection -ComputerName 127.0.0.1 -Port 9050 -WarningAction SilentlyContinue
if ($test.TcpTestSucceeded) {
    Write-Host "✅ PORT 9050 ACTIF!" -ForegroundColor Green
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  TOR SERVICE INSTALLÉ" -ForegroundColor Green
    Write-Host "  Proxy: 127.0.0.1:9050" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
} else {
    Write-Host "⚠️ Port 9050 non actif encore" -ForegroundColor Yellow
    Write-Host "Vérifier le log: $installPath\tor.log" -ForegroundColor Gray
}

Write-Host ""
pause
