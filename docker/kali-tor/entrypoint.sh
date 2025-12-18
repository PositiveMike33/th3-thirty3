#!/bin/bash
# Entrypoint script for Kali-TOR container

echo "🔒 Starting TOR service..."

# Start TOR in background
tor &
TOR_PID=$!

# Wait for TOR to be ready
echo "⏳ Waiting for TOR to establish circuits..."
sleep 10

# Check TOR status
for i in {1..30}; do
    if curl -s --socks5 localhost:9050 https://check.torproject.org/api/ip 2>/dev/null | grep -q '"IsTor":true'; then
        echo "✅ TOR is connected!"
        IP=$(curl -s --socks5 localhost:9050 https://check.torproject.org/api/ip | jq -r '.IP')
        echo "🌐 Exit IP: $IP"
        break
    fi
    echo "   Attempt $i/30..."
    sleep 2
done

# Keep container running and show status periodically
echo ""
echo "=========================================="
echo "  🐉 KALI-TOR CONTAINER READY"
echo "  SOCKS5 Proxy: 0.0.0.0:9050"
echo "  Control Port: 9051"
echo "=========================================="

# Show available tools
echo ""
echo "📦 Available tools:"
echo "  - nmap, nikto, dirb, gobuster"
echo "  - sqlmap, hydra, john"
echo "  - proxychains4, torsocks"
echo ""

# Keep running
while kill -0 $TOR_PID 2>/dev/null; do
    sleep 60
    echo "[TOR] Still running... $(date)"
done

echo "❌ TOR process died, exiting..."
exit 1
