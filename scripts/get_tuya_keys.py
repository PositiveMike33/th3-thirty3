#!/usr/bin/env python3
"""
Script pour récupérer les Local Keys des caméras Tuya/EasyLife
Utilise l'API Tuya Cloud pour obtenir les clés nécessaires à la connexion locale

Usage:
    python get_tuya_keys.py

Prérequis:
    1. Créer un compte sur https://iot.tuya.com
    2. Créer un projet Cloud avec les APIs:
       - Smart Home Family Management  
       - Smart Home Device Manager
       - Smart Home Basic Service
    3. Lier votre compte EasyLife app au projet
"""

import os
import json
import sys

try:
    import tinytuya
    from tinytuya import Cloud
except ImportError:
    print("Installing tinytuya...")
    os.system("pip install tinytuya")
    import tinytuya
    from tinytuya import Cloud

# Configuration - À REMPLIR avec vos credentials Tuya IoT Platform
TUYA_CONFIG = {
    "apiRegion": "us",  # us, eu, cn
    "apiKey": "",       # Access ID / Client ID
    "apiSecret": "",    # Access Secret / Client Secret
    "apiDeviceID": ""   # Un Device ID de votre réseau (optionnel)
}

# Fichier de sortie
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "..", "server", "config", "tuya_local_keys.json")

# Caméras connues
KNOWN_CAMERAS = {
    "131400200201030": {
        "name": "EasyLife Camera 1",
        "ip": "192.168.1.165",
        "mac": "98:A8:29:80:0F:68"
    },
    "131400200165748": {
        "name": "EasyLife Camera 2", 
        "ip": "192.168.1.235",
        "mac": "20:98:ED:92:07:B9"
    }
}


def check_credentials():
    """Vérifie si les credentials sont configurés"""
    if not TUYA_CONFIG["apiKey"] or not TUYA_CONFIG["apiSecret"]:
        print("\n" + "="*60)
        print("⚠️  CONFIGURATION REQUISE")
        print("="*60)
        print("""
Pour obtenir les Local Keys, vous devez configurer vos credentials Tuya IoT.

ÉTAPES:
1. Allez sur https://iot.tuya.com et créez un compte
2. Cliquez sur "Cloud" > "Create Cloud Project"
3. Nommez le projet (ex: "EasyLife Local Control")
4. Sélectionnez votre région (Americas = us)
5. Dans le projet, allez dans "API Explorer" > "Authorization"
6. Abonnez-vous aux APIs:
   - Smart Home Family Management
   - Smart Home Device Manager  
   - Smart Home Basic Service
7. Allez dans "Devices" > "Link Tuya App Account"
8. Scannez le QR code avec l'app EasyLife (ou Tuya Smart)
9. Récupérez vos credentials dans "Overview":
   - Access ID/Client ID
   - Access Secret/Client Secret

Puis modifiez ce script avec vos credentials.
""")
        
        # Demander les credentials interactivement
        print("\nOu entrez vos credentials maintenant:")
        api_key = input("Access ID/Client ID: ").strip()
        api_secret = input("Access Secret/Client Secret: ").strip()
        region = input("Region (us/eu/cn) [us]: ").strip() or "us"
        
        if api_key and api_secret:
            TUYA_CONFIG["apiKey"] = api_key
            TUYA_CONFIG["apiSecret"] = api_secret
            TUYA_CONFIG["apiRegion"] = region
            return True
        
        return False
    return True


def get_local_keys():
    """Récupère les Local Keys depuis Tuya Cloud"""
    print("\n🔐 Connexion à Tuya Cloud...")
    
    try:
        cloud = Cloud(
            apiRegion=TUYA_CONFIG["apiRegion"],
            apiKey=TUYA_CONFIG["apiKey"],
            apiSecret=TUYA_CONFIG["apiSecret"]
        )
        
        # Récupérer la liste des appareils
        print("📡 Récupération des appareils...")
        devices = cloud.getdevices()
        
        if not devices:
            print("❌ Aucun appareil trouvé. Vérifiez que votre compte app est bien lié.")
            return None
        
        print(f"\n✅ {len(devices)} appareil(s) trouvé(s):\n")
        
        results = []
        for device in devices:
            device_id = device.get('id', '')
            local_key = device.get('key', '')
            name = device.get('name', 'Unknown')
            
            # Vérifier si c'est une de nos caméras connues
            is_known = device_id in KNOWN_CAMERAS
            camera_info = KNOWN_CAMERAS.get(device_id, {})
            
            device_data = {
                "deviceId": device_id,
                "name": name,
                "localKey": local_key,
                "ip": camera_info.get("ip", device.get("ip", "Unknown")),
                "mac": camera_info.get("mac", ""),
                "category": device.get("category", ""),
                "product_name": device.get("product_name", ""),
                "online": device.get("online", False),
                "local_key_found": bool(local_key)
            }
            
            results.append(device_data)
            
            # Affichage
            status = "⭐" if is_known else "  "
            key_status = f"🔑 {local_key[:8]}..." if local_key else "❌ Pas de clé"
            online = "🟢 Online" if device.get("online") else "🔴 Offline"
            
            print(f"{status} {name}")
            print(f"    ID: {device_id}")
            print(f"    Local Key: {key_status}")
            print(f"    Status: {online}")
            if is_known:
                print(f"    IP: {camera_info.get('ip', 'Unknown')}")
            print()
        
        return results
        
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return None


def save_keys(devices):
    """Sauvegarde les clés dans un fichier JSON"""
    if not devices:
        return
    
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    # Filtrer pour ne garder que les appareils avec des clés
    cameras_with_keys = []
    for device in devices:
        if device["deviceId"] in KNOWN_CAMERAS and device["localKey"]:
            camera = KNOWN_CAMERAS[device["deviceId"]].copy()
            camera["deviceId"] = device["deviceId"]
            camera["localKey"] = device["localKey"]
            camera["online"] = device["online"]
            cameras_with_keys.append(camera)
    
    output = {
        "cameras": cameras_with_keys,
        "all_devices": devices
    }
    
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\n💾 Clés sauvegardées dans: {OUTPUT_FILE}")
    
    # Mettre à jour le fichier de config des caméras
    config_file = os.path.join(os.path.dirname(__file__), "..", "server", "config", "easylife_cameras.json")
    if os.path.exists(config_file) and cameras_with_keys:
        with open(config_file) as f:
            config = json.load(f)
        
        for cam in config.get("cameras", []):
            for key_data in cameras_with_keys:
                if cam.get("deviceId") == key_data.get("deviceId"):
                    cam["localKey"] = key_data["localKey"]
                    cam["status"] = "ready"
                    print(f"✅ Clé mise à jour pour {cam.get('name')}")
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"💾 Configuration mise à jour: {config_file}")


def run_wizard():
    """Lance le wizard TinyTuya interactif"""
    print("\n🧙 Lancement du wizard TinyTuya...")
    print("Suivez les instructions pour lier votre compte.\n")
    tinytuya.wizard.wizard()


def main():
    print("="*60)
    print("🔐 TUYA LOCAL KEY EXTRACTOR")
    print("   Pour caméras EasyLife / Tuya Smart")
    print("="*60)
    
    if len(sys.argv) > 1 and sys.argv[1] == "wizard":
        run_wizard()
        return
    
    if not check_credentials():
        print("\n💡 Alternativement, lancez: python get_tuya_keys.py wizard")
        return
    
    devices = get_local_keys()
    
    if devices:
        save_keys(devices)
        
        # Vérifier si on a trouvé les clés des caméras
        found_cameras = [d for d in devices if d["deviceId"] in KNOWN_CAMERAS and d["localKey"]]
        
        if found_cameras:
            print("\n" + "="*60)
            print("✅ SUCCÈS! Clés trouvées pour les caméras:")
            for cam in found_cameras:
                print(f"   - {cam['name']}: {cam['localKey'][:8]}...")
            print("\nVous pouvez maintenant contrôler les caméras localement!")
        else:
            print("\n⚠️  Les Device IDs des caméras n'ont pas été trouvés dans votre compte.")
            print("    Vérifiez que les caméras sont bien liées à votre app EasyLife.")


if __name__ == "__main__":
    main()
