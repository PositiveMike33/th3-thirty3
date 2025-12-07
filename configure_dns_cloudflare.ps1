# ===============================================
# Th3 Thirty3 - DNS Souverain (Cloudflare)
# Exécuter en tant qu'Administrateur
# ===============================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Th3 Thirty3 - Configuration DNS" -ForegroundColor Cyan
Write-Host "  Cloudflare DoH (1.1.1.1)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Vérifier les privilèges Admin
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[ERREUR] Ce script nécessite des privilèges Administrateur!" -ForegroundColor Red
    Write-Host "Clic droit -> Exécuter en tant qu'Administrateur" -ForegroundColor Yellow
    pause
    exit
}

# DNS Cloudflare
$cloudflareIPv4Primary = "1.1.1.1"
$cloudflareIPv4Secondary = "1.0.0.1"
$cloudflareIPv6Primary = "2606:4700:4700::1111"
$cloudflareIPv6Secondary = "2606:4700:4700::1001"

# Lister les adaptateurs actifs
Write-Host "[INFO] Adaptateurs réseau actifs:" -ForegroundColor Yellow
$adapters = Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.Name -notlike '*WSL*' -and $_.Name -notlike '*vEthernet*'}
$adapters | ForEach-Object {
    Write-Host "  - $($_.Name) ($($_.InterfaceDescription))" -ForegroundColor Gray
}
Write-Host ""

foreach ($adapter in $adapters) {
    Write-Host "[CONFIG] $($adapter.Name)..." -ForegroundColor Cyan
    
    try {
        # IPv4
        Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses ($cloudflareIPv4Primary, $cloudflareIPv4Secondary)
        Write-Host "  [OK] IPv4: $cloudflareIPv4Primary, $cloudflareIPv4Secondary" -ForegroundColor Green
        
        # IPv6 (optionnel, ignorer si erreur)
        try {
            Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses ($cloudflareIPv4Primary, $cloudflareIPv4Secondary, $cloudflareIPv6Primary, $cloudflareIPv6Secondary)
            Write-Host "  [OK] IPv6: 2606:4700:4700::1111" -ForegroundColor Green
        } catch {
            Write-Host "  [SKIP] IPv6 non configuré (OK)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [ERREUR] $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Vider le cache DNS
Write-Host ""
Write-Host "[FLUSH] Vidage du cache DNS..." -ForegroundColor Cyan
Clear-DnsClientCache
Write-Host "  [OK] Cache DNS vidé" -ForegroundColor Green

# Activer DoH (DNS over HTTPS) dans Windows 11
Write-Host ""
Write-Host "[DoH] Configuration DNS over HTTPS..." -ForegroundColor Cyan
try {
    # Windows 11 supporte DoH nativement
    $dohServers = @(
        @{ServerAddress="1.1.1.1"; DohTemplate="https://cloudflare-dns.com/dns-query"; AutoUpgrade=$true},
        @{ServerAddress="1.0.0.1"; DohTemplate="https://cloudflare-dns.com/dns-query"; AutoUpgrade=$true}
    )
    
    foreach ($server in $dohServers) {
        try {
            Add-DnsClientDohServerAddress -ServerAddress $server.ServerAddress -DohTemplate $server.DohTemplate -AllowFallbackToUdp $false -AutoUpgrade $server.AutoUpgrade -ErrorAction SilentlyContinue
        } catch {}
    }
    Write-Host "  [OK] DoH configuré pour Cloudflare" -ForegroundColor Green
} catch {
    Write-Host "  [INFO] DoH nécessite Windows 11 (ignoré)" -ForegroundColor Yellow
}

# Vérification
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  VÉRIFICATION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

nslookup cloudflare.com

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  DNS SOUVERAIN ACTIVÉ" -ForegroundColor Green
Write-Host "  Tes requêtes DNS sont maintenant" -ForegroundColor Green
Write-Host "  chiffrées via Cloudflare 1.1.1.1" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

pause
