#!/usr/bin/env python3
"""
Quick Camera Finder - Simplified script for rapid camera discovery
Author: Th3Thirty3
"""

import socket
import subprocess
import sys
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
CAMERA_PORTS = [554, 80, 8080, 8000]
TIMEOUT = 0.3

# MAC prefixes for camera manufacturers
MAC_VENDORS = {
    "00:12:34": "Hikvision", "BC:AD:28": "Hikvision",
    "00:40:8C": "Axis", "AC:CC:8E": "Axis",
    "3C:EF:8C": "Dahua", "4C:11:BF": "Dahua",
    "00:16:35": "Foscam", "EC:71:DB": "Reolink",
    "7C:F6:66": "Tuya", "D8:F3:BC": "Tuya",
}


def scan_port(ip: str, port: int) -> bool:
    """Check if port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False


def get_mac_vendor(mac: str) -> str:
    """Identify vendor from MAC address"""
    prefix = mac[:8].upper().replace('-', ':')
    return MAC_VENDORS.get(prefix, "")


def get_arp_table() -> dict:
    """Get ARP table entries"""
    arp_map = {}
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})', line)
            if match:
                ip, mac = match.groups()
                arp_map[ip] = mac.replace('-', ':').upper()
    except:
        pass
    return arp_map


def scan_network(subnet: str = "192.168.1"):
    """Scan network for cameras"""
    print(f"\n🔍 Scanning {subnet}.0/24 for IP cameras...\n")
    print("-" * 60)
    
    cameras = []
    arp_table = get_arp_table()
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {}
        
        for i in range(1, 255):
            ip = f"{subnet}.{i}"
            for port in CAMERA_PORTS:
                futures[executor.submit(scan_port, ip, port)] = (ip, port)
        
        found_ips = set()
        for future in as_completed(futures):
            ip, port = futures[future]
            if future.result() and ip not in found_ips:
                found_ips.add(ip)
                
                mac = arp_table.get(ip, "")
                vendor = get_mac_vendor(mac) if mac else ""
                
                open_ports = [p for p in CAMERA_PORTS if scan_port(ip, p)]
                
                camera = {
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "ports": open_ports
                }
                cameras.append(camera)
                
                vendor_str = f" [{vendor}]" if vendor else ""
                print(f"📹 {ip}{vendor_str}")
                print(f"   MAC: {mac or 'N/A'}")
                print(f"   Ports: {', '.join(map(str, open_ports))}")
                
                if 554 in open_ports:
                    print(f"   RTSP: rtsp://{ip}:554/stream1")
                if 80 in open_ports:
                    print(f"   HTTP: http://{ip}")
                print()
    
    print("-" * 60)
    print(f"✅ Found {len(cameras)} potential camera(s)\n")
    
    return cameras


if __name__ == "__main__":
    subnet = sys.argv[1] if len(sys.argv) > 1 else "192.168.1"
    cameras = scan_network(subnet)
