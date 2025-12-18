<#
.SYNOPSIS
    Th3 Thirty3 / Nexus33 - Cloudflare Tunnel & DNS Deployment Script

.DESCRIPTION
    This script sets up Cloudflare Tunnel for nexus33.io with all subdomains:
    - nexus33.io / www.nexus33.io (Frontend)
    - api.nexus33.io (Backend API)
    - ollama.nexus33.io (Ollama LLM)
    - llm.nexus33.io (AnythingLLM)
    - ws.nexus33.io (WebSocket)

.NOTES
    Author: Th3 Thirty3
    Version: 1.0
    Prerequisites: cloudflared CLI installed and authenticated
#>

param(
    [switch]$SetupDNS,
    [switch]$StartTunnel,
    [switch]$Test,
    [switch]$All
)

$ErrorActionPreference = "Continue"
$ProjectRoot = $PSScriptRoot -replace "\\cloudflare$", ""
$TunnelName = "nexus33"
$Domain = "nexus33.io"
$ConfigPath = "$PSScriptRoot\config.yml"
$CloudflaredHome = "$env:USERPROFILE\.cloudflared"

# Colors
function Write-Color($Text, $Color = "White") {
    Write-Host $Text -ForegroundColor $Color
}

function Write-Banner {
    Write-Color ""
    Write-Color "╔══════════════════════════════════════════════════════════╗" "Cyan"
    Write-Color "║   ████████╗██╗  ██╗██████╗     ████████╗██╗  ██╗██╗██████╗ ╚" "Cyan"
    Write-Color "║   ╚══██╔══╝██║  ██║╚════██╗    ╚══██╔══╝██║  ██║██║╚════██╗ ║" "Cyan"
    Write-Color "║      ██║   ███████║ █████╔╝       ██║   ███████║██║ █████╔╝ ║" "Cyan"
    Write-Color "║      ██║   ██╔══██║ ╚═══██╗       ██║   ██╔══██║██║ ╚═══██╗ ║" "Cyan"
    Write-Color "║      ██║   ██║  ██║██████╔╝       ██║   ██║  ██║██║██████╔╝ ║" "Cyan"
    Write-Color "║      ╚═╝   ╚═╝  ╚═╝╚═════╝        ╚═╝   ╚═╝  ╚═╝╚═╝╚═════╝  ║" "Cyan"
    Write-Color "║                CLOUDFLARE DEPLOYMENT SCRIPT                ║" "Yellow"
    Write-Color "╚════════════════════════════════════════════════════════════╝" "Cyan"
    Write-Color ""
}

function Test-Cloudflared {
    Write-Color "[*] Checking cloudflared installation..." "Yellow"
    $version = cloudflared --version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Color "[✓] cloudflared installed: $version" "Green"
        return $true
    } else {
        Write-Color "[✗] cloudflared not installed!" "Red"
        Write-Color "    Install: winget install Cloudflare.cloudflared" "White"
        return $false
    }
}

function Test-TunnelExists {
    Write-Color "[*] Checking tunnel '$TunnelName'..." "Yellow"
    $tunnels = cloudflared tunnel list 2>$null
    if ($tunnels -match $TunnelName) {
        Write-Color "[✓] Tunnel '$TunnelName' exists" "Green"
        return $true
    } else {
        Write-Color "[!] Tunnel '$TunnelName' not found" "Yellow"
        return $false
    }
}

function Setup-Tunnel {
    Write-Color "[*] Setting up Cloudflare Tunnel..." "Yellow"
    
    # Check if logged in
    if (!(Test-Path "$CloudflaredHome\cert.pem")) {
        Write-Color "[!] Not logged in to Cloudflare. Starting login..." "Yellow"
        cloudflared tunnel login
        if ($LASTEXITCODE -ne 0) {
            Write-Color "[✗] Login failed!" "Red"
            return $false
        }
    }
    
    # Create tunnel if doesn't exist
    if (!(Test-TunnelExists)) {
        Write-Color "[*] Creating tunnel '$TunnelName'..." "Yellow"
        cloudflared tunnel create $TunnelName
        if ($LASTEXITCODE -ne 0) {
            Write-Color "[✗] Failed to create tunnel!" "Red"
            return $false
        }
        Write-Color "[✓] Tunnel created successfully" "Green"
    }
    
    return $true
}

function Setup-DNSRoutes {
    Write-Color "[*] Setting up DNS routes for $Domain..." "Yellow"
    
    $subdomains = @(
        $Domain,
        "www.$Domain",
        "api.$Domain",
        "ollama.$Domain",
        "llm.$Domain",
        "ws.$Domain"
    )
    
    foreach ($subdomain in $subdomains) {
        Write-Color "[*] Creating DNS route: $subdomain -> $TunnelName" "Cyan"
        cloudflared tunnel route dns $TunnelName $subdomain 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Color "[✓] DNS route created: $subdomain" "Green"
        } else {
            Write-Color "[!] DNS route may already exist: $subdomain" "Yellow"
        }
    }
    
    Write-Color "[✓] DNS routes configured" "Green"
}

function Copy-ConfigToCloudflared {
    Write-Color "[*] Copying config to cloudflared home..." "Yellow"
    
    if (Test-Path $ConfigPath) {
        Copy-Item $ConfigPath "$CloudflaredHome\config.yml" -Force
        Write-Color "[✓] Config copied to $CloudflaredHome\config.yml" "Green"
    } else {
        Write-Color "[✗] Config file not found: $ConfigPath" "Red"
        return $false
    }
    return $true
}

function Start-CloudflareTunnel {
    Write-Color "[*] Starting Cloudflare Tunnel..." "Yellow"
    
    # Copy config first
    if (!(Copy-ConfigToCloudflared)) {
        return
    }
    
    Write-Color "[*] Tunnel will route traffic to:" "Cyan"
    Write-Color "    nexus33.io       -> localhost:5173 (Frontend)" "White"
    Write-Color "    api.nexus33.io   -> localhost:3000 (Backend)" "White"
    Write-Color "    ollama.nexus33.io-> localhost:11434 (Ollama)" "White"
    Write-Color "    llm.nexus33.io   -> localhost:3001 (AnythingLLM)" "White"
    Write-Color ""
    Write-Color "[!] Make sure all services are running locally!" "Yellow"
    Write-Color ""
    Write-Color "Press CTRL+C to stop the tunnel" "Magenta"
    Write-Color ""
    
    # Start tunnel with config
    cloudflared tunnel run --config "$CloudflaredHome\config.yml" $TunnelName
}

function Test-LocalServices {
    Write-Color "[*] Testing local services..." "Yellow"
    
    $services = @(
        @{ Name = "Frontend"; Port = 5173; Path = "/" },
        @{ Name = "Backend API"; Port = 3000; Path = "/api/health" },
        @{ Name = "Ollama"; Port = 11434; Path = "/api/version" }
    )
    
    $allGood = $true
    foreach ($service in $services) {
        try {
            $url = "http://localhost:$($service.Port)$($service.Path)"
            $response = Invoke-WebRequest -Uri $url -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            Write-Color "[✓] $($service.Name) (port $($service.Port)) - OK" "Green"
        } catch {
            Write-Color "[✗] $($service.Name) (port $($service.Port)) - NOT RUNNING" "Red"
            $allGood = $false
        }
    }
    
    return $allGood
}

function Test-PublicEndpoints {
    Write-Color "[*] Testing public endpoints (requires tunnel running)..." "Yellow"
    
    $endpoints = @(
        "https://nexus33.io",
        "https://api.nexus33.io/api/health"
    )
    
    foreach ($endpoint in $endpoints) {
        try {
            $response = Invoke-WebRequest -Uri $endpoint -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
            Write-Color "[✓] $endpoint - OK ($($response.StatusCode))" "Green"
        } catch {
            Write-Color "[✗] $endpoint - FAILED" "Red"
        }
    }
}

# Main execution
Write-Banner

if (!(Test-Cloudflared)) {
    exit 1
}

if ($All) {
    $SetupDNS = $true
    $StartTunnel = $true
}

if ($Test) {
    Write-Color ""
    Write-Color "═══════════════════════════════════════" "Cyan"
    Write-Color "        SERVICE STATUS TEST" "Yellow"
    Write-Color "═══════════════════════════════════════" "Cyan"
    Write-Color ""
    Test-LocalServices
    Write-Color ""
    Test-PublicEndpoints
    exit 0
}

if ($SetupDNS) {
    Write-Color ""
    Write-Color "═══════════════════════════════════════" "Cyan"
    Write-Color "         DNS ROUTE SETUP" "Yellow"
    Write-Color "═══════════════════════════════════════" "Cyan"
    Write-Color ""
    
    if (Setup-Tunnel) {
        Setup-DNSRoutes
    }
}

if ($StartTunnel) {
    Write-Color ""
    Write-Color "═══════════════════════════════════════" "Cyan"
    Write-Color "        STARTING TUNNEL" "Yellow"
    Write-Color "═══════════════════════════════════════" "Cyan"
    Write-Color ""
    
    # Test local services first
    if (Test-LocalServices) {
        Start-CloudflareTunnel
    } else {
        Write-Color ""
        Write-Color "[!] Some services are not running!" "Yellow"
        Write-Color "[!] Start them first with: npm run dev (frontend) and node index.js (backend)" "Yellow"
        Write-Color ""
        $continue = Read-Host "Continue anyway? (y/n)"
        if ($continue -eq "y") {
            Start-CloudflareTunnel
        }
    }
}

if (!$SetupDNS -and !$StartTunnel -and !$Test) {
    Write-Color "Usage:" "Yellow"
    Write-Color "  .\deploy-cloudflare.ps1 -SetupDNS    # Configure DNS routes" "White"
    Write-Color "  .\deploy-cloudflare.ps1 -StartTunnel # Start the tunnel" "White"
    Write-Color "  .\deploy-cloudflare.ps1 -Test        # Test services" "White"
    Write-Color "  .\deploy-cloudflare.ps1 -All         # Setup DNS + Start tunnel" "White"
}
