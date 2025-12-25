#!/bin/bash
# HackerGPT Kali Entrypoint Script
# Initializes TOR and security tools

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
cat << 'EOF'
    __  __           __            ________  ______
   / / / /___ ______/ /_____  ____/ ____/ /_/ /_  /
  / /_/ / __ `/ ___/ //_/ _ \/ ___/ / __/ __/ / / / 
 / __  / /_/ / /__/ ,< /  __/ /  / /_/ / /_/ / /__/
/_/ /_/\__,_/\___/_/|_|\___/_/   \____/\__/_/____/  
                                                   
    ⚡ KALI LINUX EDITION ⚡
    Th3 Thirty3 AI Security Platform
EOF
echo -e "${NC}"

# =============================================================================
# START TOR SERVICE
# =============================================================================
echo -e "${YELLOW}🔒 Starting TOR service...${NC}"
service tor start || tor &
TOR_PID=$!

# Wait for TOR to establish connection
echo -e "${YELLOW}⏳ Waiting for TOR to establish circuits...${NC}"
for i in {1..60}; do
    if curl -s --socks5 localhost:9050 https://check.torproject.org/api/ip 2>/dev/null | grep -q '"IsTor":true'; then
        echo -e "${GREEN}✅ TOR is connected!${NC}"
        IP=$(curl -s --socks5 localhost:9050 https://check.torproject.org/api/ip | jq -r '.IP')
        echo -e "${GREEN}🌐 Exit Node IP: ${CYAN}$IP${NC}"
        break
    fi
    if [ $i -eq 60 ]; then
        echo -e "${RED}⚠️  TOR connection timeout - continuing anyway...${NC}"
    else
        echo -e "${YELLOW}   Connection attempt $i/60...${NC}"
        sleep 2
    fi
done

# =============================================================================
# INITIALIZE METASPLOIT DATABASE
# =============================================================================
echo -e "${YELLOW}🗄️  Initializing Metasploit database...${NC}"
if [ -f /usr/bin/msfdb ]; then
    msfdb init 2>/dev/null || true
    echo -e "${GREEN}✅ Metasploit database ready${NC}"
fi

# =============================================================================
# SYSTEM STATUS
# =============================================================================
echo ""
echo -e "${CYAN}=========================================="
echo -e "  🐉 HACKERGPT KALI - READY"
echo -e "==========================================${NC}"
echo ""
echo -e "${GREEN}📡 Network Services:${NC}"
echo -e "   • TOR SOCKS5 Proxy: ${CYAN}0.0.0.0:9050${NC}"
echo -e "   • TOR Control Port: ${CYAN}9051${NC}"
echo ""
echo -e "${GREEN}🔧 Available Tool Categories:${NC}"
echo -e "   ${YELLOW}[RECON]${NC} nmap, masscan, recon-ng, theharvester, sherlock"
echo -e "   ${YELLOW}[WEB]${NC} nikto, dirb, gobuster, sqlmap, burpsuite, wpscan"
echo -e "   ${YELLOW}[EXPLOIT]${NC} metasploit, searchsploit, msfpc"
echo -e "   ${YELLOW}[PASSWORDS]${NC} hydra, john, hashcat, crunch, cewl"
echo -e "   ${YELLOW}[WIRELESS]${NC} aircrack-ng, wifite, bettercap"
echo -e "   ${YELLOW}[FORENSICS]${NC} binwalk, foremost, volatility3, autopsy"
echo -e "   ${YELLOW}[OSINT]${NC} sherlock, sublist3r, amass, dnsrecon"
echo ""
echo -e "${GREEN}🐍 Python Security Libraries:${NC}"
echo -e "   pwntools, scapy, impacket, shodan, paramiko"
echo ""
echo -e "${GREEN}🌐 Anonymity Tools:${NC}"
echo -e "   proxychains4, torsocks, openvpn, wireguard"
echo ""
echo -e "${CYAN}===========================================${NC}"
echo ""

# =============================================================================
# OPTIONAL: START INTERACTIVE SHELL OR KEEP RUNNING
# =============================================================================
if [ "$1" = "shell" ] || [ "$1" = "-i" ]; then
    exec /bin/bash
elif [ "$1" = "msf" ]; then
    exec msfconsole
elif [ -n "$1" ]; then
    exec "$@"
else
    # Keep container running and show status periodically
    while true; do
        sleep 300
        echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] HackerGPT Kali running...${NC}"
        
        # Check TOR status
        if curl -s --socks5 localhost:9050 https://check.torproject.org/api/ip 2>/dev/null | grep -q '"IsTor":true'; then
            IP=$(curl -s --socks5 localhost:9050 https://check.torproject.org/api/ip | jq -r '.IP')
            echo -e "${GREEN}   TOR Status: Connected (Exit: $IP)${NC}"
        else
            echo -e "${YELLOW}   TOR Status: Reconnecting...${NC}"
            service tor restart 2>/dev/null || tor &
        fi
    done
fi
