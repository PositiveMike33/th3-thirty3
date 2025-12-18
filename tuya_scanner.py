#!/usr/bin/env python3
"""
Tuya Device Scanner & Key Extractor
Scans local network for Tuya/EasyLife devices and helps extract Local Keys

Usage:
    python tuya_scanner.py scan          # Scan network for devices
    python tuya_scanner.py wizard        # Interactive setup wizard
    python tuya_scanner.py devices       # List registered devices
"""

import sys
import json
import os
from pathlib import Path

try:
    import tinytuya
except ImportError:
    print("Installing tinytuya...")
    os.system("pip install tinytuya")
    import tinytuya

# Output file for discovered devices
OUTPUT_FILE = Path(__file__).parent / "server" / "data" / "tuya_discovered.json"

def scan_network():
    """Scan local network for Tuya devices"""
    print("\n" + "="*60)
    print("🔍 SCANNING NETWORK FOR TUYA/EASYLIFE DEVICES")
    print("="*60)
    print("\nThis will broadcast on the local network to find Tuya devices.")
    print("Make sure your EasyLife cameras are powered on and connected to WiFi.\n")
    
    # Perform network scan
    devices = tinytuya.deviceScan(verbose=True, maxretry=3, byID=True)
    
    if not devices:
        print("\n❌ No Tuya devices found on the network.")
        print("\nTroubleshooting:")
        print("  1. Make sure devices are powered on")
        print("  2. Devices must be on the same network as this computer")
        print("  3. Some devices may not respond to broadcast scans")
        print("  4. Try running the wizard instead: python tuya_scanner.py wizard")
        return []
    
    print(f"\n✅ Found {len(devices)} device(s):\n")
    
    device_list = []
    for device_id, device_info in devices.items():
        print(f"  📹 Device ID: {device_id}")
        print(f"     IP Address: {device_info.get('ip', 'Unknown')}")
        print(f"     Version: {device_info.get('version', 'Unknown')}")
        print(f"     Product Key: {device_info.get('productKey', 'Unknown')}")
        print()
        
        device_list.append({
            "id": device_id,
            "ip": device_info.get('ip'),
            "version": device_info.get('version', '3.3'),
            "productKey": device_info.get('productKey'),
            "gwId": device_info.get('gwId'),
            "active": device_info.get('active'),
            "name": f"EasyLife Camera @ {device_info.get('ip', 'Unknown')}"
        })
    
    # Save to file
    if device_list:
        os.makedirs(OUTPUT_FILE.parent, exist_ok=True)
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(device_list, f, indent=2)
        print(f"💾 Saved to: {OUTPUT_FILE}")
    
    return device_list


def run_wizard():
    """Run TinyTuya wizard to get Local Keys from Tuya Cloud"""
    print("\n" + "="*60)
    print("🧙 TUYA LOCAL KEY WIZARD")
    print("="*60)
    print("""
This wizard will help you get the Local Keys for your EasyLife cameras.

PREREQUISITES:
1. Create a Tuya IoT Developer account at https://iot.tuya.com
2. Create a Cloud Project with these APIs enabled:
   - Smart Home Family Management
   - Smart Home Device Manager
3. Link your Ease Life app account to the project
4. Get your API credentials from the project settings

You will need:
- API ID (Access ID / Client ID)
- API Secret (Access Secret / Client Secret)  
- Region (us, eu, cn)

Press Enter to continue or Ctrl+C to cancel...
""")
    input()
    
    # Run the wizard
    print("\nStarting TinyTuya Wizard...\n")
    tinytuya.wizard.wizard()
    
    # Check for generated files
    devices_file = Path("devices.json")
    if devices_file.exists():
        print("\n✅ Devices file generated!")
        with open(devices_file) as f:
            devices = json.load(f)
        
        print(f"\nFound {len(devices)} device(s):\n")
        for dev in devices:
            print(f"  📹 {dev.get('name', 'Unknown')}")
            print(f"     Device ID: {dev.get('id')}")
            print(f"     Local Key: {dev.get('key', '❌ Not found')}")
            print(f"     IP: {dev.get('ip', 'Unknown')}")
            print()
        
        # Copy to server data folder
        import shutil
        os.makedirs(OUTPUT_FILE.parent, exist_ok=True)
        shutil.copy(devices_file, OUTPUT_FILE.parent / "tuya_keys.json")
        print(f"💾 Keys saved to: {OUTPUT_FILE.parent / 'tuya_keys.json'}")


def list_devices():
    """List previously discovered devices"""
    print("\n" + "="*60)
    print("📋 REGISTERED TUYA DEVICES")
    print("="*60 + "\n")
    
    files_to_check = [
        OUTPUT_FILE,
        OUTPUT_FILE.parent / "tuya_devices.json",
        OUTPUT_FILE.parent / "tuya_keys.json",
        Path("devices.json")
    ]
    
    found_any = False
    
    for file_path in files_to_check:
        if file_path.exists():
            print(f"📁 {file_path}:\n")
            with open(file_path) as f:
                devices = json.load(f)
            
            if isinstance(devices, dict):
                devices = list(devices.values())
            
            for dev in devices:
                if isinstance(dev, dict):
                    print(f"  📹 {dev.get('name', 'Unknown Device')}")
                    print(f"     ID: {dev.get('id', dev.get('deviceId', 'Unknown'))}")
                    print(f"     IP: {dev.get('ip', 'Unknown')}")
                    local_key = dev.get('key', dev.get('localKey', ''))
                    if local_key:
                        print(f"     Local Key: {local_key}")
                    else:
                        print(f"     Local Key: ❌ Not available (run wizard)")
                    print()
            
            found_any = True
            print()
    
    if not found_any:
        print("No devices found.\n")
        print("Run one of these commands first:")
        print("  python tuya_scanner.py scan    - Scan network")
        print("  python tuya_scanner.py wizard  - Get keys from Tuya Cloud")


def generate_config_for_server(device_id: str, local_key: str, ip: str, name: str = "EasyLife Camera"):
    """Generate config JSON for the Th3 Thirty3 server"""
    config = {
        "id": device_id,
        "name": name,
        "ip": ip,
        "localKey": local_key,
        "version": "3.3",
        "port": 6668,
        "type": "camera",
        "hasPTZ": True
    }
    
    print("\n📋 Configuration for Th3 Thirty3 Server:\n")
    print(json.dumps(config, indent=2))
    print("\n")
    print("To add to server, run:")
    print(f'curl -X POST http://localhost:3000/api/tuya/devices -H "Content-Type: application/json" -d \'{json.dumps(config)}\'')


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nCommands:")
        print("  scan    - Scan local network for Tuya devices")
        print("  wizard  - Run TinyTuya wizard to get Local Keys")
        print("  devices - List registered devices")
        print()
        return
    
    command = sys.argv[1].lower()
    
    if command == "scan":
        scan_network()
    elif command == "wizard":
        run_wizard()
    elif command == "devices":
        list_devices()
    else:
        print(f"Unknown command: {command}")
        print("Use: scan, wizard, or devices")


if __name__ == "__main__":
    main()
