#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Th3Thirty3 - Pentest CCTV Discovery Tool - ONVIF + Port Scan
Passive camera discovery for personal network (EasyLife/Tuya cameras)

Usage: 
    python3 cam_discover.py <IP_RANGE>  
    Example: python3 cam_discover.py 192.168.1.0/24

Features:
    - Network host discovery via nmap
    - Port scanning (80, 554, 8080, 8081)
    - ONVIF camera detection
    - Manufacturer fingerprinting
    - RTSP endpoint enumeration
    - JSON output for integration

⚠️ For authorized use on YOUR OWN network only!
"""

import subprocess
import sys
import threading
import socket
import time
import json
import os
import re
from datetime import datetime
from pathlib import Path

# Try to import ONVIF, install if missing
try:
    from onvif import ONVIFCamera
    ONVIF_AVAILABLE = True
except ImportError:
    ONVIF_AVAILABLE = False
    print("[WARN] python-onvif-zeep not installed. ONVIF detection disabled.")
    print("       Install with: pip install python-onvif-zeep")

# Common IP camera ports
COMMON_PORTS = [80, 554, 8080, 8081, 8000, 6668, 9000, 37777, 34567]

# RTSP default paths by manufacturer
RTSP_PATHS = [
    "/live/ch00_0",     # Generic
    "/live",            # Common
    "/stream1",         # Hikvision
    "/cam/realmonitor", # Dahua
    "/h264_stream",     # Foscam
    "/video1",          # D-Link
    "/videoMain",       # Axis
    "/11",              # Samsung
    "/mpeg4/media.amp", # Sony
    "/MediaInput/h264", # Trendnet
    "/user=admin&password=&channel=1&stream=0.sdp",  # EasyLife/Chinese
]

# Default credentials to try
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "12345"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", ""),
    ("user", "user"),
    ("easylife", "easylife"),
]

# Output directory
OUTPUT_DIR = Path(__file__).parent.parent / "server" / "data" / "camera_scans"


class CameraDiscovery:
    """
    Passive camera discovery tool for local network
    Designed for finding personal EasyLife/Tuya cameras
    """
    
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.discovered = []
        self.lock = threading.Lock()
        
        # Create output directory
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    def log(self, msg):
        """Print log message if verbose"""
        if self.verbose:
            print(msg)
    
    def check_nmap(self):
        """Check if nmap is available"""
        try:
            result = subprocess.run(['nmap', '--version'], 
                                   capture_output=True, 
                                   text=True,
                                   timeout=5)
            return 'Nmap' in result.stdout
        except Exception:
            return False
    
    def scan_network(self, ip_range):
        """
        Scan network for active hosts using nmap
        Falls back to simple ping if nmap unavailable
        """
        self.log(f"[🔍] Scanning network: {ip_range}")
        
        if self.check_nmap():
            return self._nmap_scan(ip_range)
        else:
            self.log("[⚠️] nmap not found, using fallback ping scan")
            return self._ping_scan(ip_range)
    
    def _nmap_scan(self, ip_range):
        """Scan using nmap (preferred method)"""
        try:
            result = subprocess.run(
                ['nmap', '-sn', ip_range, '-oG', '-'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            ips = []
            for line in result.stdout.splitlines():
                if 'Up' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        ips.append(parts[1])
            
            self.log(f"[📍] Hosts found: {len(ips)}")
            return ips
            
        except subprocess.TimeoutExpired:
            self.log("[❌] Network scan timed out")
            return []
        except Exception as e:
            self.log(f"[❌] Scan error: {e}")
            return []
    
    def _ping_scan(self, ip_range):
        """Fallback ping scan when nmap unavailable"""
        # Parse IP range (simple /24 support)
        if '/24' in ip_range:
            base = ip_range.replace('/24', '').rsplit('.', 1)[0]
        else:
            base = ip_range.rsplit('.', 1)[0]
        
        ips = []
        threads = []
        
        def ping_host(ip):
            try:
                # Windows ping
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', '500', ip],
                    capture_output=True,
                    timeout=2
                )
                if result.returncode == 0:
                    with self.lock:
                        ips.append(ip)
            except Exception:
                pass
        
        # Scan 1-254
        for i in range(1, 255):
            ip = f"{base}.{i}"
            t = threading.Thread(target=ping_host, args=(ip,))
            threads.append(t)
            t.start()
        
        # Wait for all threads
        for t in threads:
            t.join(timeout=1)
        
        self.log(f"[📍] Hosts found: {len(ips)}")
        return sorted(ips, key=lambda x: [int(p) for p in x.split('.')])
    
    def scan_port(self, ip, port, results):
        """Scan a single port on an IP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                with self.lock:
                    results.append((ip, port))
                    
        except Exception:
            pass
    
    def scan_ports(self, ip_list, ports=None):
        """
        Scan specified ports on all discovered IPs
        Returns list of (ip, port) tuples with open ports
        """
        if ports is None:
            ports = COMMON_PORTS
        
        self.log(f"[⏳] Scanning ports {ports} on {len(ip_list)} hosts...")
        
        open_ports = []
        threads = []
        
        for ip in ip_list:
            for port in ports:
                t = threading.Thread(target=self.scan_port, args=(ip, port, open_ports))
                threads.append(t)
                t.start()
        
        # Wait for all threads
        for t in threads:
            t.join(timeout=2)
        
        # Group by IP
        ip_ports = {}
        for ip, port in open_ports:
            if ip not in ip_ports:
                ip_ports[ip] = []
            ip_ports[ip].append(port)
        
        return ip_ports
    
    def test_onvif(self, ip, port=80):
        """
        Test if device supports ONVIF protocol
        ONVIF is a global standard for IP-based security products
        """
        if not ONVIF_AVAILABLE:
            return None
        
        for user, passwd in DEFAULT_CREDENTIALS[:3]:  # Try first 3 credentials
            try:
                # ONVIF WSDL paths
                wsdl_paths = [
                    '/etc/onvif/wsdl/',
                    './wsdl/',
                    None  # Let library find it
                ]
                
                for wsdl in wsdl_paths:
                    try:
                        if wsdl:
                            cam = ONVIFCamera(ip, port, user, passwd, wsdl)
                        else:
                            cam = ONVIFCamera(ip, port, user, passwd)
                        
                        # Try to get device info
                        device_service = cam.create_devicemgmt_service()
                        device_info = device_service.GetDeviceInformation()
                        
                        return {
                            "onvif": True,
                            "manufacturer": device_info.Manufacturer,
                            "model": device_info.Model,
                            "firmware": device_info.FirmwareVersion,
                            "serial": device_info.SerialNumber,
                            "credentials": {"user": user, "pass": passwd}
                        }
                    except Exception:
                        continue
                        
            except Exception:
                continue
        
        return None
    
    def http_fingerprint(self, ip, port=80):
        """
        Fingerprint camera via HTTP headers and response
        Returns manufacturer hints
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            
            # Send HTTP request
            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
            sock.send(request.encode())
            
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            # Parse headers
            headers = {}
            manufacturer = "Unknown"
            
            for line in response.split('\r\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Fingerprint by server header
            server = headers.get('server', '')
            
            if 'hikvision' in server.lower():
                manufacturer = "Hikvision"
            elif 'dahua' in server.lower():
                manufacturer = "Dahua"
            elif 'foscam' in server.lower():
                manufacturer = "Foscam"
            elif 'axis' in server.lower():
                manufacturer = "Axis"
            elif 'goahead' in server.lower():
                manufacturer = "GoAhead (Generic Chinese)"
            elif 'boa' in server.lower():
                manufacturer = "Boa (EasyLife/Tuya)"
            elif 'thttpd' in server.lower():
                manufacturer = "thttpd (Generic)"
            elif 'mini_httpd' in server.lower():
                manufacturer = "mini_httpd (Generic)"
            
            # Check response body for hints
            body = response.split('\r\n\r\n', 1)[-1] if '\r\n\r\n' in response else ''
            
            if 'easylife' in body.lower() or 'tuya' in body.lower():
                manufacturer = "EasyLife/Tuya"
            elif 'hikvision' in body.lower():
                manufacturer = "Hikvision"
            elif 'dahua' in body.lower():
                manufacturer = "Dahua"
            
            return {
                "server": server,
                "manufacturer": manufacturer,
                "headers": headers
            }
            
        except Exception as e:
            return None
    
    def test_rtsp(self, ip, port=554):
        """
        Test RTSP connectivity
        Returns working RTSP paths if found
        """
        working_paths = []
        
        for path in RTSP_PATHS[:5]:  # Test first 5 paths
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip, port))
                
                # RTSP OPTIONS request
                request = f"OPTIONS rtsp://{ip}:{port}{path} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
                sock.send(request.encode())
                
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                if 'RTSP/1.0 200' in response:
                    working_paths.append(path)
                    
            except Exception:
                pass
        
        return working_paths if working_paths else None
    
    def analyze_device(self, ip, open_ports):
        """
        Analyze a device with open ports
        Determines if it's likely a camera
        """
        device = {
            "ip": ip,
            "ports": open_ports,
            "is_camera": False,
            "confidence": 0,
            "type": "unknown",
            "manufacturer": "Unknown",
            "onvif": None,
            "rtsp_paths": None,
            "http_info": None,
            "tuya_port": 6668 in open_ports,
            "discovered_at": datetime.now().isoformat()
        }
        
        # Check for camera indicators
        camera_ports = [554, 8080, 8081, 6668, 37777, 34567]
        camera_port_count = sum(1 for p in open_ports if p in camera_ports)
        
        # HTTP fingerprint
        if 80 in open_ports:
            device["http_info"] = self.http_fingerprint(ip, 80)
            if device["http_info"]:
                device["manufacturer"] = device["http_info"].get("manufacturer", "Unknown")
        
        # ONVIF detection
        if 80 in open_ports or 8080 in open_ports:
            for port in [80, 8080]:
                if port in open_ports:
                    onvif_result = self.test_onvif(ip, port)
                    if onvif_result:
                        device["onvif"] = onvif_result
                        device["is_camera"] = True
                        device["confidence"] = 100
                        device["manufacturer"] = onvif_result.get("manufacturer", device["manufacturer"])
                        break
        
        # RTSP detection
        if 554 in open_ports:
            device["rtsp_paths"] = self.test_rtsp(ip, 554)
            if device["rtsp_paths"]:
                device["is_camera"] = True
                device["confidence"] = max(device["confidence"], 90)
        
        # Tuya detection
        if 6668 in open_ports:
            device["type"] = "Tuya/EasyLife Camera"
            device["is_camera"] = True
            device["confidence"] = max(device["confidence"], 85)
            device["manufacturer"] = "EasyLife/Tuya"
        
        # Confidence based on ports
        if camera_port_count >= 2:
            device["confidence"] = max(device["confidence"], 70)
            device["is_camera"] = True
        elif camera_port_count >= 1:
            device["confidence"] = max(device["confidence"], 50)
        
        # Set type
        if device["is_camera"]:
            if device["onvif"]:
                device["type"] = "ONVIF Camera"
            elif 6668 in open_ports:
                device["type"] = "Tuya/EasyLife Camera"
            elif 554 in open_ports:
                device["type"] = "RTSP Camera"
            else:
                device["type"] = "IP Camera (suspected)"
        
        return device
    
    def discover(self, ip_range, save_results=True):
        """
        Main discovery function
        Scans network and identifies potential cameras
        """
        start_time = time.time()
        
        self.log("\n" + "="*60)
        self.log("🔍 TH3 THIRTY3 - CAMERA DISCOVERY")
        self.log("="*60)
        self.log(f"Target: {ip_range}")
        self.log(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log("")
        
        # Step 1: Network scan
        hosts = self.scan_network(ip_range)
        
        if not hosts:
            self.log("[❌] No hosts found on network")
            return []
        
        # Step 2: Port scan
        ip_ports = self.scan_ports(hosts)
        
        self.log("\n[📊] Devices with open ports:")
        self.log("-" * 40)
        
        for ip, ports in ip_ports.items():
            self.log(f"  {ip} → Ports: {ports}")
        
        # Step 3: Analyze devices
        self.log("\n[🔍] Analyzing devices...")
        self.log("-" * 40)
        
        cameras = []
        
        for ip, ports in ip_ports.items():
            device = self.analyze_device(ip, ports)
            
            if device["is_camera"]:
                cameras.append(device)
                self.log(f"\n  ✅ CAMERA FOUND: {ip}")
                self.log(f"     Type: {device['type']}")
                self.log(f"     Manufacturer: {device['manufacturer']}")
                self.log(f"     Confidence: {device['confidence']}%")
                self.log(f"     Ports: {device['ports']}")
                
                if device["onvif"]:
                    self.log(f"     ONVIF: ✅ Supported")
                    self.log(f"     Model: {device['onvif'].get('model', 'N/A')}")
                
                if device["rtsp_paths"]:
                    self.log(f"     RTSP Paths: {device['rtsp_paths']}")
                    
                if device["tuya_port"]:
                    self.log(f"     Tuya Port: ✅ Port 6668 open")
        
        # Step 4: Summary
        elapsed = time.time() - start_time
        
        self.log("\n" + "="*60)
        self.log("📊 DISCOVERY SUMMARY")
        self.log("="*60)
        self.log(f"  Hosts scanned: {len(hosts)}")
        self.log(f"  Devices with open ports: {len(ip_ports)}")
        self.log(f"  Cameras found: {len(cameras)}")
        self.log(f"  Time elapsed: {elapsed:.1f}s")
        self.log("")
        
        for cam in cameras:
            self.log(f"  🎥 {cam['ip']} - {cam['type']} ({cam['manufacturer']})")
        
        # Save results
        if save_results and cameras:
            output_file = OUTPUT_DIR / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            results = {
                "scan_time": datetime.now().isoformat(),
                "target_range": ip_range,
                "hosts_found": len(hosts),
                "cameras_found": len(cameras),
                "elapsed_seconds": elapsed,
                "cameras": cameras
            }
            
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            self.log(f"\n💾 Results saved: {output_file}")
            
            # Also save latest scan
            latest_file = OUTPUT_DIR / "latest_scan.json"
            with open(latest_file, 'w') as f:
                json.dump(results, f, indent=2)
        
        self.discovered = cameras
        return cameras


def main():
    """Main entrypoint"""
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nUsage: python3 cam_discover.py <IP_RANGE>")
        print("Example: python3 cam_discover.py 192.168.1.0/24")
        print()
        
        # Try to detect default gateway
        try:
            if sys.platform == 'win32':
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'Default Gateway' in line and ':' in line:
                        gateway = line.split(':')[-1].strip()
                        if gateway:
                            print(f"Detected gateway: {gateway}")
                            base = gateway.rsplit('.', 1)[0]
                            print(f"Suggested command: python cam_discover.py {base}.0/24")
                            break
        except Exception:
            pass
        
        sys.exit(1)
    
    ip_range = sys.argv[1]
    
    # Validate IP range format
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$', ip_range):
        print(f"[❌] Invalid IP range format: {ip_range}")
        print("    Expected format: 192.168.1.0/24")
        sys.exit(1)
    
    # Run discovery
    scanner = CameraDiscovery(verbose=True)
    cameras = scanner.discover(ip_range)
    
    # Print results for integration
    if cameras:
        print("\n" + "="*60)
        print("🔌 INTEGRATION COMMANDS")
        print("="*60)
        
        for cam in cameras:
            if cam.get("tuya_port"):
                print(f"\n# Add {cam['ip']} to Th3 Thirty3:")
                print(f"curl -X POST http://localhost:3000/api/tuya/devices \\")
                print(f"  -H 'Content-Type: application/json' \\")
                print(f"  -d '{{\"ip\": \"{cam['ip']}\", \"name\": \"EasyLife Camera\"}}'")


if __name__ == "__main__":
    main()
