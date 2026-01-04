# ===============================================
# Th3 Thirty3 - Network Configuration Backup
# Sauvegarde complète de la configuration réseau
# ===============================================

param(
    [string]$BackupPath = "$PSScriptRoot\..\network_backups"
)

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Sauvegarde Configuration Réseau" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Créer le dossier de backup
if (-not (Test-Path $BackupPath)) {
    New-Item -ItemType Directory -Force -Path $BackupPath | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$backupFile = Join-Path $BackupPath "network_config_$timestamp.json"
$latestFile = Join-Path $BackupPath "network_config_REFERENCE.json"

Write-Host "[1/5] Collecte des adaptateurs réseau..." -ForegroundColor Yellow

$adapters = Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed

Write-Host "  Trouvé $($adapters.Count) adaptateur(s)" -ForegroundColor Gray

Write-Host "[2/5] Collecte des adresses IP..." -ForegroundColor Yellow

$ipAddresses = Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" -or $_.AddressFamily -eq "IPv6" } | 
Select-Object InterfaceAlias, IPAddress, AddressFamily, PrefixLength, PrefixOrigin, SuffixOrigin

Write-Host "[3/5] Collecte des serveurs DNS..." -ForegroundColor Yellow

$dnsServers = Get-DnsClientServerAddress | 
Select-Object InterfaceAlias, AddressFamily, ServerAddresses

Write-Host "[4/5] Collecte des routes et gateway..." -ForegroundColor Yellow

$routes = Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -eq "0.0.0.0/0" } |
Select-Object InterfaceAlias, NextHop, RouteMetric

$ipConfig = Get-NetIPConfiguration | Select-Object InterfaceAlias, 
@{N = 'IPv4Address'; E = { $_.IPv4Address.IPAddress } },
@{N = 'IPv4Gateway'; E = { $_.IPv4DefaultGateway.NextHop } },
@{N = 'DNSServer'; E = { $_.DNSServer.ServerAddresses -join ',' } }

Write-Host "[5/5] Collecte des paramètres proxy..." -ForegroundColor Yellow

$proxySettings = @{
    ProxyEnabled  = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -ErrorAction SilentlyContinue).ProxyEnable
    ProxyServer   = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer
    AutoConfigURL = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name AutoConfigURL -ErrorAction SilentlyContinue).AutoConfigURL
}

# Assembler la configuration complète
$networkConfig = @{
    Timestamp       = $timestamp
    ComputerName    = $env:COMPUTERNAME
    Adapters        = $adapters
    IPAddresses     = $ipAddresses
    DNSServers      = $dnsServers
    DefaultRoutes   = $routes
    IPConfiguration = $ipConfig
    ProxySettings   = $proxySettings
}

# Sauvegarder en JSON
$networkConfig | ConvertTo-Json -Depth 5 | Set-Content -Path $backupFile -Encoding UTF8

# Copier comme référence si c'est la première fois
if (-not (Test-Path $latestFile)) {
    Copy-Item $backupFile $latestFile
    Write-Host ""
    Write-Host "[REFERENCE] Configuration de référence créée!" -ForegroundColor Green
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  SAUVEGARDE RÉUSSIE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Fichier: $backupFile" -ForegroundColor Cyan
Write-Host ""

# Afficher un résumé
Write-Host "=== Résumé de la Configuration ===" -ForegroundColor Cyan
foreach ($config in $ipConfig) {
    if ($config.IPv4Address) {
        Write-Host "  $($config.InterfaceAlias):" -ForegroundColor Yellow
        Write-Host "    IPv4: $($config.IPv4Address)" -ForegroundColor White
        Write-Host "    Gateway: $($config.IPv4Gateway)" -ForegroundColor White
        Write-Host "    DNS: $($config.DNSServer)" -ForegroundColor White
    }
}

Write-Host ""
Write-Host "Proxy Système: $(if($proxySettings.ProxyEnabled -eq 1){'ACTIVÉ - ' + $proxySettings.ProxyServer}else{'Désactivé'})" -ForegroundColor $(if ($proxySettings.ProxyEnabled -eq 1) { 'Yellow' }else { 'Green' })
Write-Host ""

return $backupFile
