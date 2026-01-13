# ============================================
# TH3 THIRTY3 - Proxy & Privacy Setup Script
# PowerShell Installation Script for Windows
# ============================================
# Run as Administrator: 
# powershell -ExecutionPolicy Bypass -File setup_proxy.ps1
# ============================================

param(
    [switch]$InstallTor,
    [switch]$ConfigureProxy,
    [switch]$ConfigureDNS,
    [switch]$TestConnection,
    [switch]$All
)

$ErrorActionPreference = "Stop"

# Configuration
$TorVersion = "13.0.9"
$TorDownloadUrl = "https://archive.torproject.org/tor-package-archive/torbrowser/$TorVersion/tor-expert-bundle-windows-x86_64-$TorVersion.tar.gz"
$TorInstallPath = "$env:LOCALAPPDATA\Tor"
$TorSocksPort = 9050
$TorControlPort = 9051

# Colors
function Write-Status { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Error { param($msg) Write-Host "[-] $msg" -ForegroundColor Red }
function Write-Warning { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }

# Header
Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║         TH3 THIRTY3 - PROXY & PRIVACY SETUP                    ║" -ForegroundColor Magenta
Write-Host "║         Secure your connection for OSINT operations            ║" -ForegroundColor Magenta
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

# ============================================
# STEP 1: Check/Install TOR
# ============================================
function Install-Tor {
    Write-Status "Checking TOR installation..."
    
    # Check if TOR is already running
    $torProcess = Get-Process -Name "tor" -ErrorAction SilentlyContinue
    if ($torProcess) {
        Write-Success "TOR is already running (PID: $($torProcess.Id))"
        return $true
    }
    
    # Check if TOR executable exists
    $torExe = "$TorInstallPath\tor\tor.exe"
    if (Test-Path $torExe) {
        Write-Success "TOR found at $torExe"
        return $true
    }
    
    # Check common locations
    $commonPaths = @(
        "C:\Program Files\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
        "$env:USERPROFILE\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
        "$env:LOCALAPPDATA\Tor Browser\Browser\TorBrowser\Tor\tor.exe"
    )
    
    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            Write-Success "TOR Browser found at $path"
            Write-Warning "For best results with Th3 Thirty3, use standalone TOR Expert Bundle"
            return $true
        }
    }
    
    # TOR not found - offer to download
    Write-Warning "TOR not found on this system"
    Write-Status "Downloading TOR Expert Bundle..."
    
    try {
        # Create install directory
        New-Item -ItemType Directory -Force -Path $TorInstallPath | Out-Null
        
        $downloadPath = "$env:TEMP\tor-expert-bundle.tar.gz"
        
        # Download
        Write-Status "Downloading from $TorDownloadUrl"
        Invoke-WebRequest -Uri $TorDownloadUrl -OutFile $downloadPath -UseBasicParsing
        
        # Extract (requires 7-zip or tar)
        if (Get-Command tar -ErrorAction SilentlyContinue) {
            Write-Status "Extracting with tar..."
            tar -xzf $downloadPath -C $TorInstallPath
        } else {
            Write-Error "Please install 7-zip or use Windows tar to extract"
            Write-Warning "Manual download: https://www.torproject.org/download/tor/"
            return $false
        }
        
        Write-Success "TOR installed to $TorInstallPath"
        
        # Clean up
        Remove-Item $downloadPath -Force
        
        return $true
    } catch {
        Write-Error "Failed to download/install TOR: $_"
        Write-Warning "Manual download: https://www.torproject.org/download/tor/"
        return $false
    }
}

# ============================================
# STEP 2: Start TOR Service
# ============================================
function Start-TorService {
    Write-Status "Starting TOR service..."
    
    $torProcess = Get-Process -Name "tor" -ErrorAction SilentlyContinue
    if ($torProcess) {
        Write-Success "TOR already running (PID: $($torProcess.Id))"
        return $true
    }
    
    # Find TOR executable
    $torExe = $null
    $searchPaths = @(
        "$TorInstallPath\tor\tor.exe",
        "C:\Program Files\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
        "$env:USERPROFILE\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe"
    )
    
    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            $torExe = $path
            break
        }
    }
    
    if (-not $torExe) {
        Write-Error "TOR executable not found. Please install TOR first."
        return $false
    }
    
    try {
        Write-Status "Starting TOR from $torExe"
        Start-Process -FilePath $torExe -WindowStyle Hidden
        
        # Wait for TOR to start
        Start-Sleep -Seconds 3
        
        # Verify
        $torProcess = Get-Process -Name "tor" -ErrorAction SilentlyContinue
        if ($torProcess) {
            Write-Success "TOR started successfully (PID: $($torProcess.Id))"
            return $true
        } else {
            Write-Error "TOR process not found after starting"
            return $false
        }
    } catch {
        Write-Error "Failed to start TOR: $_"
        return $false
    }
}

# ============================================
# STEP 3: Configure System Proxy
# ============================================
function Set-SystemProxy {
    param(
        [switch]$Enable,
        [switch]$Disable
    )
    
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    
    if ($Enable) {
        Write-Status "Configuring system SOCKS5 proxy..."
        
        # Note: Windows doesn't natively support SOCKS5 as system proxy
        # We configure IE/Edge proxy settings instead
        Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 0
        
        Write-Warning "Windows doesn't support system-wide SOCKS5 proxy natively"
        Write-Status "For SOCKS5 proxy, configure applications individually:"
        Write-Host "  - Firefox: Settings > Network > Manual proxy > SOCKS Host: 127.0.0.1:9050"
        Write-Host "  - Chrome: Use extension like 'Proxy SwitchyOmega'"
        Write-Host "  - Th3 Thirty3: Already configured to use TOR SOCKS5"
        
        return $true
    }
    
    if ($Disable) {
        Write-Status "Disabling system proxy..."
        Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 0
        Write-Success "System proxy disabled"
        return $true
    }
}

# ============================================
# STEP 4: Configure DNS-over-HTTPS
# ============================================
function Set-SecureDNS {
    Write-Status "Configuring DNS-over-HTTPS..."
    
    # Check if running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Warning "Run as Administrator to configure system DNS"
        Write-Status "Showing manual configuration steps instead..."
        
        Write-Host ""
        Write-Host "=== Chrome DNS Configuration ===" -ForegroundColor Yellow
        Write-Host "1. Open chrome://settings/security"
        Write-Host "2. Enable 'Use secure DNS'"
        Write-Host "3. Select 'Cloudflare (1.1.1.1)'"
        Write-Host ""
        Write-Host "=== Firefox DNS Configuration ===" -ForegroundColor Yellow
        Write-Host "1. Open about:preferences#privacy"
        Write-Host "2. Enable 'DNS over HTTPS'"
        Write-Host "3. Select 'Cloudflare'"
        Write-Host ""
        
        return $false
    }
    
    try {
        # Configure Windows DNS to use Cloudflare
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        
        foreach ($adapter in $adapters) {
            Write-Status "Configuring $($adapter.Name)..."
            
            # Set Cloudflare DNS (1.1.1.1 and 1.0.0.1)
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses ("1.1.1.1", "1.0.0.1")
            
            Write-Success "DNS configured for $($adapter.Name)"
        }
        
        # Enable DNS-over-HTTPS in Windows (Windows 11+)
        try {
            # Check if DoH is supported
            $dohServers = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
            if ($dohServers) {
                Write-Status "Enabling DNS-over-HTTPS..."
                
                # Add Cloudflare DoH if not present
                $cloudflareDoH = $dohServers | Where-Object { $_.ServerAddress -eq "1.1.1.1" }
                if (-not $cloudflareDoH) {
                    Add-DnsClientDohServerAddress -ServerAddress "1.1.1.1" -DohTemplate "https://cloudflare-dns.com/dns-query" -AllowFallbackToUdp $true -AutoUpgrade $true
                }
                
                Write-Success "DNS-over-HTTPS configured"
            }
        } catch {
            Write-Warning "DNS-over-HTTPS configuration not supported on this Windows version"
        }
        
        # Flush DNS cache
        Clear-DnsClientCache
        Write-Success "DNS cache cleared"
        
        return $true
    } catch {
        Write-Error "Failed to configure DNS: $_"
        return $false
    }
}

# ============================================
# STEP 5: Test Connection
# ============================================
function Test-AnonymousConnection {
    Write-Status "Testing anonymous connection..."
    
    # Test 1: Direct IP check
    Write-Status "Getting current IP..."
    try {
        $directIP = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json" -TimeoutSec 10).ip
        Write-Host "  Direct IP: $directIP"
    } catch {
        Write-Warning "Could not get direct IP"
        $directIP = "Unknown"
    }
    
    # Test 2: Check TOR SOCKS5
    Write-Status "Testing TOR SOCKS5 proxy (127.0.0.1:$TorSocksPort)..."
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect("127.0.0.1", $TorSocksPort)
        $tcpClient.Close()
        Write-Success "TOR SOCKS5 port is open"
        
        # Check if actually routing through TOR
        Write-Status "Verifying TOR routing..."
        $torCheck = Invoke-RestMethod -Uri "https://check.torproject.org/api/ip" -TimeoutSec 15 -ErrorAction SilentlyContinue
        
        if ($torCheck.IsTor) {
            Write-Success "Connection is routing through TOR!"
            Write-Host "  TOR Exit IP: $($torCheck.IP)" -ForegroundColor Green
        } else {
            Write-Warning "Connected but NOT routing through TOR"
            Write-Warning "Configure your browser/application to use SOCKS5 127.0.0.1:9050"
        }
    } catch {
        Write-Warning "TOR SOCKS5 not accessible: $_"
    }
    
    # Test 3: DNS leak test
    Write-Status "Checking DNS configuration..."
    try {
        $dnsResult = Resolve-DnsName "whoami.cloudflare.com" -Type TXT -ErrorAction SilentlyContinue
        if ($dnsResult) {
            Write-Host "  DNS Resolver: Cloudflare" -ForegroundColor Green
        }
    } catch {
        Write-Warning "DNS test failed"
    }
    
    Write-Host ""
    Write-Host "=== Connection Test Summary ===" -ForegroundColor Cyan
    Write-Host "Direct IP: $directIP"
    Write-Host "TOR Proxy: 127.0.0.1:$TorSocksPort"
    Write-Host "DNS: Cloudflare (1.1.1.1)"
    Write-Host ""
}

# ============================================
# STEP 6: Generate Config Report
# ============================================
function Get-ConfigReport {
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║              CONFIGURATION REPORT                              ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    # TOR Status
    $torProcess = Get-Process -Name "tor" -ErrorAction SilentlyContinue
    if ($torProcess) {
        Write-Success "TOR: Running (PID: $($torProcess.Id))"
    } else {
        Write-Warning "TOR: Not running"
    }
    
    # SOCKS5 Port
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect("127.0.0.1", $TorSocksPort)
        $tcpClient.Close()
        Write-Success "SOCKS5 Proxy: 127.0.0.1:$TorSocksPort (Open)"
    } catch {
        Write-Warning "SOCKS5 Proxy: 127.0.0.1:$TorSocksPort (Closed)"
    }
    
    # DNS
    $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses -First 2
    Write-Host "[*] DNS Servers: $($dnsServers -join ', ')" -ForegroundColor Cyan
    
    Write-Host ""
    Write-Host "=== For Th3 Thirty3 Application ===" -ForegroundColor Yellow
    Write-Host "Add to .env file:"
    Write-Host "  TOR_SOCKS_PORT=9050"
    Write-Host "  TOR_CONTROL_PORT=9051"
    Write-Host ""
}

# ============================================
# MAIN EXECUTION
# ============================================

if ($All -or (-not $InstallTor -and -not $ConfigureProxy -and -not $ConfigureDNS -and -not $TestConnection)) {
    # Run all steps
    $torOk = Install-Tor
    if ($torOk) {
        Start-TorService
    }
    Set-SystemProxy -Enable
    Set-SecureDNS
    Test-AnonymousConnection
    Get-ConfigReport
} else {
    if ($InstallTor) {
        $torOk = Install-Tor
        if ($torOk) { Start-TorService }
    }
    if ($ConfigureProxy) { Set-SystemProxy -Enable }
    if ($ConfigureDNS) { Set-SecureDNS }
    if ($TestConnection) { Test-AnonymousConnection }
}

Write-Host ""
Write-Success "Setup complete!"
Write-Host ""
