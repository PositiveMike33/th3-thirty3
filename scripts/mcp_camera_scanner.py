#!/usr/bin/env python3
"""
MCP Camera Scanner - Network IP Camera Discovery Tool
Integrates with Model Context Protocol for LLM-driven reconnaissance
Author: Th3Thirty3
Version: 1.0.0
"""

import socket
import subprocess
import json
import re
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class CameraDevice:
    """Represents a discovered camera device"""
    ip: str
    mac: Optional[str] = None
    manufacturer: Optional[str] = None
    open_ports: List[int] = None
    rtsp_endpoints: List[str] = None
    http_title: Optional[str] = None
    onvif_supported: bool = False
    firmware: Optional[str] = None
    model: Optional[str] = None
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
        if self.rtsp_endpoints is None:
            self.rtsp_endpoints = []


# ============================================================================
# MAC ADDRESS MANUFACTURER DATABASE
# ============================================================================

MAC_MANUFACTURERS = {
    "00:12:34": "Hikvision",
    "BC:AD:28": "Hikvision",
    "C0:56:E3": "Hikvision",
    "54:C4:15": "Hikvision",
    "00:40:8C": "Axis Communications",
    "AC:CC:8E": "Axis Communications",
    "B8:A4:4F": "Axis Communications",
    "3C:EF:8C": "Dahua Technology",
    "4C:11:BF": "Dahua Technology",
    "E0:50:8B": "Dahua Technology",
    "00:16:35": "Foscam",
    "EC:71:DB": "Reolink",
    "7C:F6:66": "Tuya/Smart Life",
    "D8:F3:BC": "Tuya/Smart Life",
    "10:D5:61": "Tuya/Smart Life",
    "A0:92:08": "TP-Link",
    "14:EB:B6": "TP-Link",
    "00:0F:7C": "Amcrest",
    "00:18:AE": "Samsung Techwin",
    "00:09:18": "Samsung",
    "00:30:53": "Vivotek",
    "00:1A:07": "Arecont Vision",
}

# Common camera ports
CAMERA_PORTS = [80, 443, 554, 8000, 8080, 8443, 8554, 37777, 34567, 9527]

# Common RTSP paths
RTSP_PATHS = [
    "/stream1",
    "/stream2",
    "/h264",
    "/h265",
    "/live/ch00_0",
    "/live/ch00_1",
    "/Streaming/Channels/101",
    "/Streaming/Channels/102",
    "/cam/realmonitor",
    "/cam1/h264",
    "/video1",
    "/videoMain",
    "/video.mp4",
    "/media/video1",
    "/onvif/media/video1",
    "/user=admin_password=_channel=1_stream=0.sdp",
    "/",
]


# ============================================================================
# MCP TOOL CLASS
# ============================================================================

class MCPCameraScanner:
    """
    MCP-compatible Camera Scanner Tool
    Provides methods that can be invoked via Model Context Protocol
    """
    
    def __init__(self, timeout: float = 0.5, max_workers: int = 50):
        self.timeout = timeout
        self.max_workers = max_workers
        self.discovered_devices: Dict[str, CameraDevice] = {}
        
    # ------------------------------------------------------------------------
    # MCP TOOL: Network Scanner
    # ------------------------------------------------------------------------
    
    def mcp_network_scan(self, subnet: str = "192.168.1.0/24", 
                         ports: List[int] = None) -> Dict:
        """
        MCP Tool: Scan network for camera devices
        
        Args:
            subnet: Network range to scan (CIDR notation)
            ports: List of ports to check (defaults to camera ports)
            
        Returns:
            Dict with discovered devices
        """
        if ports is None:
            ports = CAMERA_PORTS
            
        logger.info(f"🔍 Starting network scan on {subnet}")
        
        # Parse subnet
        base_ip = subnet.rsplit('.', 1)[0]
        
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for i in range(1, 255):
                ip = f"{base_ip}.{i}"
                futures[executor.submit(self._scan_host, ip, ports)] = ip
                
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    self.discovered_devices[result.ip] = result
                    
        return {
            "status": "success",
            "scan_time": datetime.now().isoformat(),
            "subnet": subnet,
            "devices_found": len(results),
            "devices": [asdict(d) for d in results]
        }
    
    def _scan_host(self, ip: str, ports: List[int]) -> Optional[CameraDevice]:
        """Scan a single host for open camera ports"""
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                pass
                
        if open_ports:
            device = CameraDevice(ip=ip, open_ports=open_ports)
            logger.info(f"✅ Found device: {ip} - Ports: {open_ports}")
            return device
        return None
    
    # ------------------------------------------------------------------------
    # MCP TOOL: ARP Scan
    # ------------------------------------------------------------------------
    
    def mcp_arp_scan(self, interface: str = None) -> Dict:
        """
        MCP Tool: Perform ARP scan to discover devices and MAC addresses
        
        Args:
            interface: Network interface (optional)
            
        Returns:
            Dict with discovered devices and their MAC addresses
        """
        logger.info("📡 Starting ARP scan...")
        
        devices = []
        
        # Windows: Use arp -a
        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Parse ARP table
            for line in result.stdout.split('\n'):
                match = re.search(
                    r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})',
                    line
                )
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace('-', ':').upper()
                    manufacturer = self._identify_manufacturer(mac)
                    
                    devices.append({
                        "ip": ip,
                        "mac": mac,
                        "manufacturer": manufacturer
                    })
                    
                    if ip in self.discovered_devices:
                        self.discovered_devices[ip].mac = mac
                        self.discovered_devices[ip].manufacturer = manufacturer
                    else:
                        self.discovered_devices[ip] = CameraDevice(
                            ip=ip, mac=mac, manufacturer=manufacturer
                        )
                        
        except Exception as e:
            logger.error(f"ARP scan failed: {e}")
            
        # Filter camera manufacturers
        camera_devices = [
            d for d in devices 
            if d.get("manufacturer") and "Unknown" not in d.get("manufacturer", "Unknown")
        ]
        
        return {
            "status": "success",
            "scan_time": datetime.now().isoformat(),
            "total_devices": len(devices),
            "camera_devices": len(camera_devices),
            "devices": devices,
            "potential_cameras": camera_devices
        }
    
    def _identify_manufacturer(self, mac: str) -> str:
        """Identify device manufacturer from MAC address"""
        mac_prefix = mac[:8].upper()
        return MAC_MANUFACTURERS.get(mac_prefix, "Unknown")
    
    # ------------------------------------------------------------------------
    # MCP TOOL: RTSP Scanner
    # ------------------------------------------------------------------------
    
    def mcp_rtsp_scan(self, target: str, port: int = 554, 
                       credentials: List[Tuple[str, str]] = None) -> Dict:
        """
        MCP Tool: Scan for RTSP stream endpoints
        
        Args:
            target: IP address to scan
            port: RTSP port (default 554)
            credentials: List of (username, password) tuples to try
            
        Returns:
            Dict with discovered RTSP endpoints
        """
        if credentials is None:
            credentials = [
                ("", ""),
                ("admin", ""),
                ("admin", "admin"),
                ("admin", "12345"),
                ("admin", "admin123"),
            ]
            
        logger.info(f"📹 Scanning RTSP endpoints on {target}:{port}")
        
        valid_endpoints = []
        
        for path in RTSP_PATHS:
            for user, passwd in credentials:
                if user:
                    url = f"rtsp://{user}:{passwd}@{target}:{port}{path}"
                else:
                    url = f"rtsp://{target}:{port}{path}"
                    
                if self._test_rtsp_endpoint(url):
                    valid_endpoints.append({
                        "url": url,
                        "path": path,
                        "auth_required": bool(user),
                        "credentials": f"{user}:{passwd}" if user else None
                    })
                    logger.info(f"✅ Valid RTSP: {url}")
                    break  # Found valid creds for this path
                    
        if target in self.discovered_devices:
            self.discovered_devices[target].rtsp_endpoints = [
                e["url"] for e in valid_endpoints
            ]
            
        return {
            "status": "success",
            "target": target,
            "port": port,
            "endpoints_found": len(valid_endpoints),
            "endpoints": valid_endpoints
        }
    
    def _test_rtsp_endpoint(self, url: str) -> bool:
        """Test if an RTSP endpoint is accessible"""
        try:
            result = subprocess.run(
                ["ffprobe", "-v", "error", "-rtsp_transport", "tcp", 
                 "-i", url, "-show_entries", "stream=codec_type", 
                 "-of", "json"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    # ------------------------------------------------------------------------
    # MCP TOOL: HTTP Fingerprinter
    # ------------------------------------------------------------------------
    
    def mcp_http_fingerprint(self, target: str, port: int = 80) -> Dict:
        """
        MCP Tool: Fingerprint HTTP service for camera identification
        
        Args:
            target: IP address to fingerprint
            port: HTTP port (default 80)
            
        Returns:
            Dict with fingerprinting results
        """
        logger.info(f"🔎 Fingerprinting HTTP on {target}:{port}")
        
        fingerprint = {
            "target": target,
            "port": port,
            "server": None,
            "title": None,
            "manufacturer_hints": [],
            "paths_found": []
        }
        
        try:
            import urllib.request
            import ssl
            
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            url = f"http://{target}:{port}/"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            
            with urllib.request.urlopen(req, timeout=5, context=ctx) as response:
                # Get headers
                server = response.headers.get('Server', '')
                fingerprint['server'] = server
                
                # Read body for title
                body = response.read(4096).decode('utf-8', errors='ignore')
                title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE)
                if title_match:
                    fingerprint['title'] = title_match.group(1).strip()
                    
                # Check for manufacturer hints
                hints = []
                if 'hikvision' in body.lower() or 'DNVRS' in body:
                    hints.append("Hikvision")
                if 'dahua' in body.lower() or 'DH-' in body:
                    hints.append("Dahua")
                if 'axis' in body.lower():
                    hints.append("Axis")
                if 'foscam' in body.lower():
                    hints.append("Foscam")
                if 'reolink' in body.lower():
                    hints.append("Reolink")
                if 'tuya' in body.lower() or 'smart life' in body.lower():
                    hints.append("Tuya")
                    
                fingerprint['manufacturer_hints'] = hints
                
        except Exception as e:
            logger.warning(f"HTTP fingerprint failed: {e}")
            
        # Test common camera paths
        camera_paths = [
            "/login.htm", "/admin.html", "/cgi-bin/snapshot.cgi",
            "/ISAPI/System/deviceInfo", "/onvif/device_service",
            "/System/deviceInfo", "/device.rsp"
        ]
        
        for path in camera_paths:
            try:
                url = f"http://{target}:{port}{path}"
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    if resp.status == 200:
                        fingerprint['paths_found'].append(path)
            except Exception:
                pass
                
        return fingerprint
    
    # ------------------------------------------------------------------------
    # MCP TOOL: ONVIF Discovery
    # ------------------------------------------------------------------------
    
    def mcp_onvif_discover(self, target: str = None, 
                           timeout: int = 5) -> Dict:
        """
        MCP Tool: Discover ONVIF-compatible devices
        
        Args:
            target: Specific IP to check (optional, broadcasts if None)
            timeout: Discovery timeout in seconds
            
        Returns:
            Dict with ONVIF-compatible devices
        """
        logger.info("📡 Starting ONVIF discovery...")
        
        onvif_devices = []
        
        # WS-Discovery probe message
        probe_message = '''<?xml version="1.0" encoding="UTF-8"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
                       xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                       xmlns:tns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
            <soap:Header>
                <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
                <wsa:MessageID>urn:uuid:12345678-1234-1234-1234-123456789abc</wsa:MessageID>
                <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
            </soap:Header>
            <soap:Body>
                <tns:Probe>
                    <tns:Types>dn:NetworkVideoTransmitter</tns:Types>
                </tns:Probe>
            </soap:Body>
        </soap:Envelope>'''
        
        try:
            # Send multicast probe
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            # ONVIF WS-Discovery multicast address
            multicast_addr = ("239.255.255.250", 3702)
            sock.sendto(probe_message.encode(), multicast_addr)
            
            # Collect responses
            start_time = datetime.now()
            while (datetime.now() - start_time).seconds < timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]
                    
                    # Parse response for XAddrs
                    xaddr_match = re.search(r'XAddrs>([^<]+)<', data.decode())
                    if xaddr_match:
                        service_url = xaddr_match.group(1)
                        onvif_devices.append({
                            "ip": ip,
                            "onvif_url": service_url,
                            "discovered_via": "ws-discovery"
                        })
                        
                        if ip in self.discovered_devices:
                            self.discovered_devices[ip].onvif_supported = True
                        else:
                            self.discovered_devices[ip] = CameraDevice(
                                ip=ip, onvif_supported=True
                            )
                            
                        logger.info(f"✅ ONVIF device: {ip}")
                        
                except socket.timeout:
                    break
                except Exception:
                    continue
                    
            sock.close()
            
        except Exception as e:
            logger.error(f"ONVIF discovery failed: {e}")
            
        return {
            "status": "success",
            "scan_time": datetime.now().isoformat(),
            "devices_found": len(onvif_devices),
            "devices": onvif_devices
        }
    
    # ------------------------------------------------------------------------
    # MCP TOOL: Full Camera Audit
    # ------------------------------------------------------------------------
    
    def mcp_full_audit(self, subnet: str = "192.168.1.0/24",
                       include_rtsp: bool = True,
                       include_onvif: bool = True) -> Dict:
        """
        MCP Tool: Perform comprehensive camera audit
        
        Args:
            subnet: Network range to audit
            include_rtsp: Whether to scan RTSP endpoints
            include_onvif: Whether to discover ONVIF devices
            
        Returns:
            Complete audit report
        """
        logger.info(f"🔒 Starting full camera audit on {subnet}")
        
        report = {
            "audit_time": datetime.now().isoformat(),
            "subnet": subnet,
            "phases": {}
        }
        
        # Phase 1: Network scan
        logger.info("Phase 1: Network scanning...")
        report["phases"]["network_scan"] = self.mcp_network_scan(subnet)
        
        # Phase 2: ARP scan
        logger.info("Phase 2: ARP scanning...")
        report["phases"]["arp_scan"] = self.mcp_arp_scan()
        
        # Phase 3: ONVIF discovery
        if include_onvif:
            logger.info("Phase 3: ONVIF discovery...")
            report["phases"]["onvif_discovery"] = self.mcp_onvif_discover()
        
        # Phase 4: HTTP fingerprinting
        logger.info("Phase 4: HTTP fingerprinting...")
        fingerprints = []
        for ip, device in self.discovered_devices.items():
            if 80 in device.open_ports or 8080 in device.open_ports:
                port = 80 if 80 in device.open_ports else 8080
                fp = self.mcp_http_fingerprint(ip, port)
                fingerprints.append(fp)
        report["phases"]["http_fingerprint"] = fingerprints
        
        # Phase 5: RTSP enumeration
        if include_rtsp:
            logger.info("Phase 5: RTSP enumeration...")
            rtsp_results = []
            for ip, device in self.discovered_devices.items():
                if 554 in device.open_ports:
                    rtsp = self.mcp_rtsp_scan(ip)
                    rtsp_results.append(rtsp)
            report["phases"]["rtsp_scan"] = rtsp_results
        
        # Summary
        report["summary"] = {
            "total_devices": len(self.discovered_devices),
            "cameras_by_manufacturer": self._count_by_manufacturer(),
            "devices_with_rtsp": sum(
                1 for d in self.discovered_devices.values() 
                if d.rtsp_endpoints
            ),
            "onvif_devices": sum(
                1 for d in self.discovered_devices.values() 
                if d.onvif_supported
            )
        }
        
        return report
    
    def _count_by_manufacturer(self) -> Dict[str, int]:
        """Count devices by manufacturer"""
        counts = {}
        for device in self.discovered_devices.values():
            mfr = device.manufacturer or "Unknown"
            counts[mfr] = counts.get(mfr, 0) + 1
        return counts
    
    # ------------------------------------------------------------------------
    # EXPORT METHODS
    # ------------------------------------------------------------------------
    
    def export_report(self, report: Dict, filename: str = None) -> str:
        """Export audit report to JSON file"""
        if filename is None:
            filename = f"camera_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
            
        logger.info(f"📄 Report exported to {filename}")
        return filename
    
    def get_mcp_schema(self) -> Dict:
        """Return MCP tool schema for registration"""
        return {
            "name": "camera_scanner",
            "description": "Network IP Camera Discovery and Reconnaissance Tool",
            "version": "1.0.0",
            "tools": [
                {
                    "name": "network_scan",
                    "description": "Scan network for devices with camera-related ports open",
                    "parameters": {
                        "subnet": {"type": "string", "default": "192.168.1.0/24"},
                        "ports": {"type": "array", "items": {"type": "integer"}}
                    }
                },
                {
                    "name": "arp_scan",
                    "description": "Perform ARP scan to discover device MAC addresses",
                    "parameters": {
                        "interface": {"type": "string", "optional": True}
                    }
                },
                {
                    "name": "rtsp_scan",
                    "description": "Scan for accessible RTSP stream endpoints",
                    "parameters": {
                        "target": {"type": "string", "required": True},
                        "port": {"type": "integer", "default": 554}
                    }
                },
                {
                    "name": "http_fingerprint",
                    "description": "Fingerprint HTTP service for camera identification",
                    "parameters": {
                        "target": {"type": "string", "required": True},
                        "port": {"type": "integer", "default": 80}
                    }
                },
                {
                    "name": "onvif_discover",
                    "description": "Discover ONVIF-compatible devices via WS-Discovery",
                    "parameters": {
                        "timeout": {"type": "integer", "default": 5}
                    }
                },
                {
                    "name": "full_audit",
                    "description": "Perform comprehensive camera network audit",
                    "parameters": {
                        "subnet": {"type": "string", "default": "192.168.1.0/24"},
                        "include_rtsp": {"type": "boolean", "default": True},
                        "include_onvif": {"type": "boolean", "default": True}
                    }
                }
            ]
        }


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="MCP Camera Scanner - Network IP Camera Discovery Tool"
    )
    parser.add_argument(
        "--subnet", "-s",
        default="192.168.1.0/24",
        help="Network subnet to scan (default: 192.168.1.0/24)"
    )
    parser.add_argument(
        "--full-audit", "-f",
        action="store_true",
        help="Perform full audit including RTSP and ONVIF"
    )
    parser.add_argument(
        "--rtsp", "-r",
        help="Scan specific IP for RTSP endpoints"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file for report (JSON)"
    )
    parser.add_argument(
        "--mcp-schema",
        action="store_true",
        help="Print MCP tool schema"
    )
    
    args = parser.parse_args()
    
    scanner = MCPCameraScanner()
    
    if args.mcp_schema:
        print(json.dumps(scanner.get_mcp_schema(), indent=2))
        return
    
    if args.rtsp:
        result = scanner.mcp_rtsp_scan(args.rtsp)
    elif args.full_audit:
        result = scanner.mcp_full_audit(args.subnet)
    else:
        result = scanner.mcp_network_scan(args.subnet)
    
    if args.output:
        scanner.export_report(result, args.output)
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
