# ===============================================
# Th3 Thirty3 - Network Integrity Verification
# ===============================================

$ReferencePath = "$PSScriptRoot\..\network_backups\network_config_REFERENCE.json"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Verification Integrite Reseau" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verifier que le fichier de reference existe
if (-not (Test-Path $ReferencePath)) {
    Write-Host "[ERREUR] Fichier de reference non trouve!" -ForegroundColor Red
    Write-Host "Executez d'abord: .\network_backup.ps1" -ForegroundColor Yellow
    exit 1
}

# Charger la configuration de reference
$reference = Get-Content $ReferencePath | ConvertFrom-Json
Write-Host "[INFO] Reference chargee: $($reference.Timestamp)" -ForegroundColor Gray

$issues = @()
$checksPass = 0
$checksFail = 0

# CHECK 1: Proxy Systeme
Write-Host ""
Write-Host "[CHECK 1] Proxy Systeme..." -ForegroundColor Yellow

$currentProxy = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -ErrorAction SilentlyContinue).ProxyEnable

if ($currentProxy -eq 1) {
    Write-Host "  [ALERTE] Proxy systeme ACTIVE!" -ForegroundColor Red
    $checksFail++
}
else {
    Write-Host "  [OK] Proxy systeme desactive" -ForegroundColor Green
    $checksPass++
}

# CHECK 2: Adresse IPv4 principale
Write-Host ""
Write-Host "[CHECK 2] Adresse IPv4 Wi-Fi..." -ForegroundColor Yellow

$currentWifi = Get-NetIPAddress -InterfaceAlias "Wi-Fi" -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
$refWifi = $reference.IPConfiguration | Where-Object { $_.InterfaceAlias -eq "Wi-Fi" }

if ($currentWifi -and $refWifi) {
    if ($currentWifi.IPAddress -eq $refWifi.IPv4Address) {
        Write-Host "  [OK] IPv4: $($currentWifi.IPAddress)" -ForegroundColor Green
        $checksPass++
    }
    else {
        Write-Host "  [ALERTE] IPv4 a change!" -ForegroundColor Red
        Write-Host "    Reference: $($refWifi.IPv4Address)" -ForegroundColor Gray
        Write-Host "    Actuel:    $($currentWifi.IPAddress)" -ForegroundColor Red
        $checksFail++
    }
}
elseif ($currentWifi) {
    Write-Host "  [OK] IPv4: $($currentWifi.IPAddress)" -ForegroundColor Green
    $checksPass++
}
else {
    Write-Host "  [INFO] Wi-Fi non connecte" -ForegroundColor Gray
    $checksPass++
}

# CHECK 3: Gateway par defaut
Write-Host ""
Write-Host "[CHECK 3] Gateway par defaut..." -ForegroundColor Yellow

$currentGateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -ne "0.0.0.0" } | Select-Object -First 1).NextHop

if ($currentGateway) {
    Write-Host "  [OK] Gateway: $currentGateway" -ForegroundColor Green
    $checksPass++
}
else {
    Write-Host "  [INFO] Pas de gateway" -ForegroundColor Gray
}

# CHECK 4: Service Tor non installe comme service systeme
Write-Host ""
Write-Host "[CHECK 4] Service Tor Windows..." -ForegroundColor Yellow

$torService = Get-Service -Name "Tor" -ErrorAction SilentlyContinue
if ($torService) {
    Write-Host "  [ALERTE] Tor installe comme SERVICE SYSTEME!" -ForegroundColor Red
    $checksFail++
}
else {
    Write-Host "  [OK] Tor n'est pas un service systeme" -ForegroundColor Green
    $checksPass++
}

# CHECK 5: DNS
Write-Host ""
Write-Host "[CHECK 5] Serveurs DNS..." -ForegroundColor Yellow

$currentDNS = (Get-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
Write-Host "  [OK] DNS: $($currentDNS -join ', ')" -ForegroundColor Green
$checksPass++

# RESUME
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  RESUME VERIFICATION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Checks reussis: $checksPass" -ForegroundColor Green
Write-Host "  Alertes:        $checksFail" -ForegroundColor $(if ($checksFail -gt 0) { 'Red' }else { 'Green' })
Write-Host ""

if ($checksFail -gt 0) {
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  PROBLEMES DETECTES" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    exit 1
}
else {
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  INTEGRITE RESEAU OK" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    exit 0
}
