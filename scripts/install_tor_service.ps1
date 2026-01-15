# ===============================================
# Th3 Thirty3 - Installation Tor Expert Bundle
# Service Windows pour proxy SOCKS5 permanent
# ===============================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Tor Expert Bundle - Installation" -ForegroundColor Cyan
Write-Host "  Service Windows Automatique" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Vérifier les privilèges Admin
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[ERREUR] Ce script nécessite des privilèges Administrateur!" -ForegroundColor Red
    Write-Host "Clic droit -> Exécuter en tant qu'Administrateur" -ForegroundColor Yellow
    pause
    exit
}

# Configuration
$torVersion = "13.5.7"
$torUrl = "https://archive.torproject.org/tor-package-archive/torbrowser/$torVersion/tor-expert-bundle-windows-x86_64-$torVersion.tar.gz"
$installPath = "C:\Tor"
$torExe = "$installPath\Tor\tor.exe"
$dataDir = "$installPath\Data"
$torrcPath = "$installPath\torrc"

Write-Host "[1/6] Création du répertoire d'installation..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $installPath | Out-Null
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
Write-Host "  [OK] $installPath créé" -ForegroundColor Green

Write-Host ""
Write-Host "[2/6] Téléchargement de Tor Expert Bundle ($torVersion)..." -ForegroundColor Cyan
$downloadPath = "$env:TEMP\tor-expert.tar.gz"

try {
    # Utiliser la dernière version stable disponible
    $torUrl = "https://dist.torproject.org/torbrowser/13.5/tor-expert-bundle-windows-x86_64-13.5.tar.gz"
    Invoke-WebRequest -Uri $torUrl -OutFile $downloadPath -UseBasicParsing
    Write-Host "  [OK] Téléchargé: $downloadPath" -ForegroundColor Green
} catch {
    Write-Host "  [ERREUR] Téléchargement échoué: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  [INFO] Tentative avec version alternative..." -ForegroundColor Yellow
    
    # Fallback: télécharger depuis torproject.org
    $torUrl = "https://www.torproject.org/dist/torbrowser/13.5/tor-expert-bundle-windows-x86_64-13.5.tar.gz"
    Invoke-WebRequest -Uri $torUrl -OutFile $downloadPath -UseBasicParsing
}

Write-Host ""
Write-Host "[3/6] Extraction (tar.gz -> $installPath)..." -ForegroundColor Cyan
# Utiliser tar natif de Windows 10/11
tar -xzf $downloadPath -C $installPath
Write-Host "  [OK] Fichiers extraits" -ForegroundColor Green

Write-Host ""
Write-Host "[4/6] Configuration torrc..." -ForegroundColor Cyan
$torrcContent = @"
# Tor Configuration for Th3 Thirty3
# SOCKS5 Proxy on port 9050

SocksPort 127.0.0.1:9050
ControlPort 9051
DataDirectory $dataDir

# Sécurité
CookieAuthentication 1
CookieAuthFile $dataDir\control_auth_cookie

# Performance
AvoidDiskWrites 1
DisableDebuggerAttachment 0

# Logs
Log notice file $installPath\tor.log
"@

Set-Content -Path $torrcPath -Value $torrcContent -Encoding UTF8
Write-Host "  [OK] torrc configuré: $torrcPath" -ForegroundColor Green

Write-Host ""
Write-Host "[5/6] Création du service Windows..." -ForegroundColor Cyan

# Arrêter le service s'il existe déjà
$existingService = Get-Service -Name "Tor" -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "  [INFO] Service Tor existant trouvé, arrêt..." -ForegroundColor Yellow
    Stop-Service -Name "Tor" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    sc.exe delete Tor
    Start-Sleep -Seconds 1
}

# Créer le nouveau service
$torServiceArgs = "-f `"$torrcPath`""
New-Service -Name "Tor" `
            -BinaryPathName "`"$torExe`" $torServiceArgs" `
            -DisplayName "Tor Network Service (Th3 Thirty3)" `
            -Description "Proxy SOCKS5 anonyme pour Th3 Thirty3 - Port 9050" `
            -StartupType Automatic

Write-Host "  [OK] Service Windows créé" -ForegroundColor Green

Write-Host ""
Write-Host "[6/6] Démarrage du service Tor..." -ForegroundColor Cyan
Start-Service -Name "Tor"
Start-Sleep -Seconds 5

# Vérifier le statut
$service = Get-Service -Name "Tor"
if ($service.Status -eq "Running") {
    Write-Host "  [OK] Service Tor démarré!" -ForegroundColor Green
} else {
    Write-Host "  [ERREUR] Le service n'a pas démarré. Vérifier: $installPath\tor.log" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  VÉRIFICATION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Start-Sleep -Seconds 10

$torTest = Test-NetConnection -ComputerName 127.0.0.1 -Port 9050 -WarningAction SilentlyContinue
if ($torTest.TcpTestSucceeded) {
    Write-Host "✅ Port 9050 ACTIF - Proxy SOCKS5 OK!" -ForegroundColor Green
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  TOR SERVICE INSTALLÉ" -ForegroundColor Green
    Write-Host "  Le monitor Tor sera toujours actif!" -ForegroundColor Green
    Write-Host "  Port: 127.0.0.1:9050" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
} else {
    Write-Host "⚠️  Port 9050 non accessible" -ForegroundColor Yellow
    Write-Host "Le service démarre, patience 30s..." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Configuration:" -ForegroundColor Cyan
Write-Host "  - Executable: $torExe" -ForegroundColor Gray
Write-Host "  - Config: $torrcPath" -ForegroundColor Gray
Write-Host "  - Data: $dataDir" -ForegroundColor Gray
Write-Host "  - Log: $installPath\tor.log" -ForegroundColor Gray
Write-Host ""

pause
