#!/bin/bash

# ===============================================
# Th3Thirty3 - CCTV Finder Script (WSL/Linux)
# Passive camera discovery for EasyLife/Tuya
# ===============================================
# 
# Usage: ./find_cams.sh [NETWORK_RANGE]
# Default: 192.168.1.0/24
#
# Requirements:
#   - nmap (apt install nmap)
#   - curl (for API integration)
#
# For authorized use on YOUR OWN network only!
# ===============================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
NETWORK_RANGE="${1:-192.168.1.0/24}"
OUTPUT_DIR="/tmp/th3_camera_scan"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$OUTPUT_DIR/scan_$TIMESTAMP.log"

# Camera ports to scan
CAMERA_PORTS="80,554,8080,8081,6668,9000,37777,34567"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# -----------------------------------------------
# Helper Functions
# -----------------------------------------------

log() {
    echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}✅ $1${NC}" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}⚠️  $1${NC}" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}❌ $1${NC}" | tee -a "$LOG_FILE"
}

header() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}\n"
}

# -----------------------------------------------
# Check Requirements
# -----------------------------------------------

check_requirements() {
    header "CHECKING REQUIREMENTS"
    
    # Check nmap
    if command -v nmap &> /dev/null; then
        NMAP_VERSION=$(nmap --version | head -1)
        success "nmap installed: $NMAP_VERSION"
    else
        error "nmap not installed"
        echo "Install with: sudo apt install nmap"
        exit 1
    fi
    
    # Check if running with sufficient privileges
    if [ "$EUID" -eq 0 ]; then
        success "Running as root (full scan capabilities)"
    else
        warn "Running as user (some features may be limited)"
        echo "    For full scan capabilities, run: sudo ./find_cams.sh"
    fi
}

# -----------------------------------------------
# Step 1: Host Discovery
# -----------------------------------------------

discover_hosts() {
    header "STEP 1/4: HOST DISCOVERY"
    log "Scanning network: $NETWORK_RANGE"
    
    # Run nmap ping scan
    nmap -sn "$NETWORK_RANGE" -oG "$OUTPUT_DIR/hosts_$TIMESTAMP.gnmap" > /dev/null 2>&1
    
    # Extract IP addresses
    HOSTS=$(grep "Up" "$OUTPUT_DIR/hosts_$TIMESTAMP.gnmap" | awk '{print $2}')
    HOST_COUNT=$(echo "$HOSTS" | wc -w)
    
    success "Found $HOST_COUNT active hosts"
    
    if [ -z "$HOSTS" ]; then
        error "No hosts found on network"
        exit 1
    fi
    
    echo "$HOSTS" > "$OUTPUT_DIR/active_hosts.txt"
    
    # Display hosts
    echo ""
    echo -e "${CYAN}Active hosts:${NC}"
    for ip in $HOSTS; do
        echo "  • $ip"
    done
}

# -----------------------------------------------
# Step 2: Port Scanning
# -----------------------------------------------

scan_ports() {
    header "STEP 2/4: PORT SCANNING"
    log "Scanning ports: $CAMERA_PORTS"
    
    HOSTS=$(cat "$OUTPUT_DIR/active_hosts.txt")
    
    # Create results file
    echo "" > "$OUTPUT_DIR/open_ports_$TIMESTAMP.txt"
    
    for ip in $HOSTS; do
        log "Scanning $ip..."
        
        # Quick port scan
        OPEN_PORTS=$(nmap -p "$CAMERA_PORTS" --open "$ip" 2>/dev/null | grep "open" | awk '{print $1}' | tr '\n' ',' | sed 's/,$//')
        
        if [ -n "$OPEN_PORTS" ]; then
            success "$ip → Ports: $OPEN_PORTS"
            echo "$ip:$OPEN_PORTS" >> "$OUTPUT_DIR/open_ports_$TIMESTAMP.txt"
        fi
    done
    
    echo ""
    DEVICES_WITH_PORTS=$(wc -l < "$OUTPUT_DIR/open_ports_$TIMESTAMP.txt")
    log "Devices with camera ports: $DEVICES_WITH_PORTS"
}

# -----------------------------------------------
# Step 3: Camera Identification
# -----------------------------------------------

identify_cameras() {
    header "STEP 3/4: CAMERA IDENTIFICATION"
    
    # Create results file
    echo "[]" > "$OUTPUT_DIR/cameras_$TIMESTAMP.json"
    
    CAMERA_COUNT=0
    
    while IFS=: read -r ip ports; do
        [ -z "$ip" ] && continue
        
        log "Analyzing $ip (ports: $ports)..."
        
        IS_CAMERA=false
        CAMERA_TYPE="Unknown"
        MANUFACTURER="Unknown"
        CONFIDENCE=0
        
        # Check for RTSP port (554)
        if echo "$ports" | grep -q "554"; then
            IS_CAMERA=true
            CAMERA_TYPE="RTSP Camera"
            CONFIDENCE=80
        fi
        
        # Check for Tuya port (6668)
        if echo "$ports" | grep -q "6668"; then
            IS_CAMERA=true
            CAMERA_TYPE="Tuya/EasyLife Camera"
            MANUFACTURER="EasyLife/Tuya"
            CONFIDENCE=90
        fi
        
        # Check for Dahua port (37777)
        if echo "$ports" | grep -q "37777"; then
            IS_CAMERA=true
            CAMERA_TYPE="Dahua Camera"
            MANUFACTURER="Dahua"
            CONFIDENCE=95
        fi
        
        # Check for XiongMai port (34567)
        if echo "$ports" | grep -q "34567"; then
            IS_CAMERA=true
            CAMERA_TYPE="XiongMai Camera"
            MANUFACTURER="XiongMai/Generic Chinese"
            CONFIDENCE=85
        fi
        
        # HTTP fingerprinting
        if echo "$ports" | grep -qE "80/|8080/"; then
            HTTP_PORT=$(echo "$ports" | grep -oE "80\b|8080\b" | head -1)
            HTTP_PORT=${HTTP_PORT:-80}
            
            # Try to get HTTP headers
            HEADERS=$(curl -s -I --connect-timeout 2 "http://$ip:$HTTP_PORT/" 2>/dev/null || echo "")
            
            if echo "$HEADERS" | grep -qi "hikvision"; then
                IS_CAMERA=true
                MANUFACTURER="Hikvision"
                CAMERA_TYPE="Hikvision Camera"
                CONFIDENCE=95
            elif echo "$HEADERS" | grep -qi "dahua"; then
                IS_CAMERA=true
                MANUFACTURER="Dahua"
                CAMERA_TYPE="Dahua Camera"
                CONFIDENCE=95
            elif echo "$HEADERS" | grep -qi "goahead\|boa"; then
                IS_CAMERA=true
                MANUFACTURER="Generic Chinese"
                CAMERA_TYPE="IP Camera (Generic)"
                CONFIDENCE=70
            elif echo "$HEADERS" | grep -qi "easylife\|tuya"; then
                IS_CAMERA=true
                MANUFACTURER="EasyLife/Tuya"
                CAMERA_TYPE="EasyLife Camera"
                CONFIDENCE=95
            fi
        fi
        
        # If camera detected, log and save
        if [ "$IS_CAMERA" = true ]; then
            CAMERA_COUNT=$((CAMERA_COUNT + 1))
            
            echo ""
            success "CAMERA FOUND: $ip"
            echo -e "    ${CYAN}Type:${NC} $CAMERA_TYPE"
            echo -e "    ${CYAN}Manufacturer:${NC} $MANUFACTURER"
            echo -e "    ${CYAN}Confidence:${NC} $CONFIDENCE%"
            echo -e "    ${CYAN}Ports:${NC} $ports"
            echo -e "    ${CYAN}Web Access:${NC} http://$ip"
            
            # Check RTSP stream
            if echo "$ports" | grep -q "554"; then
                echo -e "    ${CYAN}RTSP Stream:${NC} rtsp://$ip:554/live"
            fi
        fi
        
    done < "$OUTPUT_DIR/open_ports_$TIMESTAMP.txt"
    
    echo ""
    log "Total cameras found: $CAMERA_COUNT"
}

# -----------------------------------------------
# Step 4: Generate Report
# -----------------------------------------------

generate_report() {
    header "STEP 4/4: GENERATING REPORT"
    
    REPORT_FILE="$OUTPUT_DIR/report_$TIMESTAMP.txt"
    
    echo "========================================" > "$REPORT_FILE"
    echo "TH3 THIRTY3 - CAMERA DISCOVERY REPORT" >> "$REPORT_FILE"
    echo "========================================" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "Scan Time: $(date)" >> "$REPORT_FILE"
    echo "Network Range: $NETWORK_RANGE" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Count cameras from open ports file
    CAMERA_COUNT=$(wc -l < "$OUTPUT_DIR/open_ports_$TIMESTAMP.txt" 2>/dev/null || echo "0")
    
    echo "Results:" >> "$REPORT_FILE"
    echo "  - Active Hosts: $(wc -l < "$OUTPUT_DIR/active_hosts.txt")" >> "$REPORT_FILE"
    echo "  - Potential Cameras: $CAMERA_COUNT" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    if [ -s "$OUTPUT_DIR/open_ports_$TIMESTAMP.txt" ]; then
        echo "Cameras Found:" >> "$REPORT_FILE"
        
        while IFS=: read -r ip ports; do
            [ -z "$ip" ] && continue
            echo "  • $ip (Ports: $ports)" >> "$REPORT_FILE"
            echo "    → Web: http://$ip" >> "$REPORT_FILE"
            if echo "$ports" | grep -q "554"; then
                echo "    → RTSP: rtsp://$ip:554/live" >> "$REPORT_FILE"
            fi
        done < "$OUTPUT_DIR/open_ports_$TIMESTAMP.txt"
    fi
    
    success "Report saved: $REPORT_FILE"
    
    # Also copy to Windows-accessible location if running in WSL
    if grep -qi microsoft /proc/version 2>/dev/null; then
        WIN_PATH="/mnt/c/Users/$USER/.Th3Thirty3/thethirty3/server/data/camera_scans"
        if [ -d "$(dirname "$WIN_PATH")" ]; then
            mkdir -p "$WIN_PATH" 2>/dev/null || true
            cp "$REPORT_FILE" "$WIN_PATH/" 2>/dev/null || true
            log "Report also copied to: $WIN_PATH"
        fi
    fi
}

# -----------------------------------------------
# Step 5: Integration Commands
# -----------------------------------------------

show_integration() {
    header "INTEGRATION COMMANDS"
    
    echo "To add discovered cameras to Th3 Thirty3:"
    echo ""
    
    while IFS=: read -r ip ports; do
        [ -z "$ip" ] && continue
        
        echo "# Add camera at $ip"
        echo "curl -X POST http://localhost:3000/api/cameras/quick-add \\"
        echo "  -H 'Content-Type: application/json' \\"
        echo "  -d '{\"ip\": \"$ip\", \"name\": \"Camera @ $ip\"}'"
        echo ""
        
        # If Tuya port detected
        if echo "$ports" | grep -q "6668"; then
            echo "# Tuya/EasyLife specific:"
            echo "curl -X POST http://localhost:3000/api/tuya/devices \\"
            echo "  -H 'Content-Type: application/json' \\"
            echo "  -d '{\"ip\": \"$ip\", \"name\": \"EasyLife Camera\"}'"
            echo ""
        fi
        
    done < "$OUTPUT_DIR/open_ports_$TIMESTAMP.txt"
}

# -----------------------------------------------
# Main Script
# -----------------------------------------------

main() {
    clear
    
    echo -e "${GREEN}"
    echo "  _____ _   _ _____ _____ _   _ ___ ____ _____ _____ _____ "
    echo " |_   _| | | |___ /|_   _| | | |_ _|  _ \_   _|_   _|___ / "
    echo "   | | | |_| | |_ \  | | | |_| || || |_) || |   | |   |_ \ "
    echo "   | | |  _  |___) | | | |  _  || ||  _ < | |   | |  ___) |"
    echo "   |_| |_| |_|____/  |_| |_| |_|___|_| \_\|_|   |_| |____/ "
    echo ""
    echo "            PASSIVE CAMERA DISCOVERY TOOL"
    echo -e "${NC}"
    
    log "Starting camera discovery..."
    log "Target: $NETWORK_RANGE"
    log "Log file: $LOG_FILE"
    
    # Run steps
    check_requirements
    discover_hosts
    scan_ports
    identify_cameras
    generate_report
    show_integration
    
    echo ""
    header "SCAN COMPLETE"
    echo -e "${GREEN}All results saved in: $OUTPUT_DIR${NC}"
    echo ""
}

# Run main function
main "$@"
