import tinytuya
from tinytuya import Cloud
import json
import os

# Tuya API Credentials
API_KEY = 'd3kkrderuvnuh99mqxkc'
API_SECRET = '0c572dcb06dd40dca0bad623469f7d13'
REGION = 'us'

print('Connecting to Tuya Cloud...')

try:
    cloud = Cloud(
        apiRegion=REGION,
        apiKey=API_KEY,
        apiSecret=API_SECRET
    )
    
    print('Fetching devices...')
    devices = cloud.getdevices()
    
    if devices:
        print(f'SUCCESS! Found {len(devices)} device(s):\n')
        for dev in devices:
            name = dev.get('name', 'Unknown')
            dev_id = dev.get('id', 'Unknown')
            local_key = dev.get('key', 'NOT FOUND')
            ip = dev.get('ip', 'Unknown')
            category = dev.get('category', 'Unknown')
            online = dev.get('online', False)
            
            print(f'  Device: {name}')
            print(f'  ID: {dev_id}')
            print(f'  Local Key: {local_key}')
            print(f'  IP: {ip}')
            print(f'  Category: {category}')
            print(f'  Online: {online}')
            print()
        
        # Save to file
        output_path = os.path.join(os.path.dirname(__file__), 'server', 'config', 'tuya_devices.json')
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(devices, f, indent=2)
        print(f'Saved to {output_path}')
    else:
        print('No devices found yet. The account may need a moment to sync.')
    
except Exception as e:
    print(f'Error: {e}')
    import traceback
    traceback.print_exc()
