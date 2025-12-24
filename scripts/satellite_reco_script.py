#!/usr/bin/env python3
"""
SATELLITE RECONNAISSANCE SCRIPT - Sentinel Hub Integration
==========================================================

Geo-OSINT tool for Bug Bounty reconnaissance.
Uses Sentinel Hub API (free, Copernicus data) to fetch satellite imagery
for physical location reconnaissance of targets.

Usage:
    python satellite_reco_script.py <lat> <lon> <date>
    
Example:
    python satellite_reco_script.py 48.8566 2.3522 2024-01-15
    
Environment Variables Required:
    SENTINEL_HUB_CLIENT_ID - OAuth Client ID
    SENTINEL_HUB_CLIENT_SECRET - OAuth Client Secret
    SENTINEL_HUB_INSTANCE_ID - Instance ID (optional)

Output:
    - satellite_<lat>_<lon>_<date>.png - Satellite image
    - satellite_<lat>_<lon>_<date>_analysis.json - Basic metadata

Ethical Use:
    - Only use for authorized bug bounty programs
    - Respect API rate limits (free tier: 100 requests/month)
    - No surveillance of individuals
    - Document all usage
"""

import os
import sys
import json
import base64
import requests
from datetime import datetime, timedelta
from pathlib import Path

# Configuration
SENTINEL_HUB_AUTH_URL = "https://identity.dataspace.copernicus.eu/auth/realms/CDSE/protocol/openid-connect/token"
SENTINEL_HUB_API_URL = "https://sh.dataspace.copernicus.eu/api/v1/process"

# Default output directory
OUTPUT_DIR = Path(__file__).parent / "satellite_output"

class SentinelHubClient:
    """Client for Sentinel Hub API (Copernicus Data Space Ecosystem)"""
    
    def __init__(self):
        self.client_id = os.environ.get("SENTINEL_HUB_CLIENT_ID")
        self.client_secret = os.environ.get("SENTINEL_HUB_CLIENT_SECRET")
        self.access_token = None
        self.token_expiry = None
        
        if not self.client_id or not self.client_secret:
            print("[!] Warning: SENTINEL_HUB_CLIENT_ID and SENTINEL_HUB_CLIENT_SECRET not set")
            print("[*] Register at: https://dataspace.copernicus.eu/")
            print("[*] Create OAuth Client in Dashboard > User Settings")
            
    def authenticate(self):
        """Get OAuth2 access token"""
        if not self.client_id or not self.client_secret:
            return False
            
        # Check if token is still valid
        if self.access_token and self.token_expiry and datetime.now() < self.token_expiry:
            return True
            
        try:
            response = requests.post(
                SENTINEL_HUB_AUTH_URL,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code == 200:
                data = response.json()
                self.access_token = data["access_token"]
                # Token expires in 'expires_in' seconds, subtract 60 for safety
                self.token_expiry = datetime.now() + timedelta(seconds=data.get("expires_in", 300) - 60)
                print("[+] Authentication successful")
                return True
            else:
                print(f"[-] Authentication failed: {response.status_code}")
                print(response.text)
                return False
                
        except Exception as e:
            print(f"[-] Authentication error: {e}")
            return False
    
    def get_satellite_image(self, lat: float, lon: float, date: str, 
                           resolution: int = 10, size: tuple = (512, 512)):
        """
        Fetch satellite image for given coordinates
        
        Args:
            lat: Latitude (-90 to 90)
            lon: Longitude (-180 to 180)
            date: Date in YYYY-MM-DD format
            resolution: Meters per pixel (10, 20, or 60 for Sentinel-2)
            size: Image size in pixels (width, height)
            
        Returns:
            dict with image data and metadata
        """
        # Validate inputs
        if not self._validate_coords(lat, lon):
            return {"error": "Invalid coordinates"}
            
        if not self._validate_date(date):
            return {"error": "Invalid date format (use YYYY-MM-DD)"}
            
        if not self.authenticate():
            return {"error": "Authentication failed - check API credentials"}
        
        # Calculate bounding box (approximately 1km x 1km area)
        # 0.01 degrees ≈ 1.1km at equator
        bbox_offset = 0.005 * (resolution / 10)  # Adjust for resolution
        bbox = [
            lon - bbox_offset,  # West
            lat - bbox_offset,  # South
            lon + bbox_offset,  # East
            lat + bbox_offset   # North
        ]
        
        # Evalscript for true color image (Sentinel-2)
        evalscript = """
        //VERSION=3
        function setup() {
            return {
                input: [{
                    bands: ["B04", "B03", "B02"],  // RGB bands
                    units: "DN"
                }],
                output: {
                    bands: 3,
                    sampleType: "AUTO"
                }
            };
        }
        
        function evaluatePixel(sample) {
            return [
                sample.B04 / 3000,  // Red
                sample.B03 / 3000,  // Green
                sample.B02 / 3000   // Blue
            ];
        }
        """
        
        # Calculate time range (±5 days from target date)
        target_date = datetime.strptime(date, "%Y-%m-%d")
        from_date = (target_date - timedelta(days=5)).strftime("%Y-%m-%dT00:00:00Z")
        to_date = (target_date + timedelta(days=5)).strftime("%Y-%m-%dT23:59:59Z")
        
        # API request payload
        payload = {
            "input": {
                "bounds": {
                    "bbox": bbox,
                    "properties": {
                        "crs": "http://www.opengis.net/def/crs/EPSG/0/4326"
                    }
                },
                "data": [{
                    "type": "sentinel-2-l2a",
                    "dataFilter": {
                        "timeRange": {
                            "from": from_date,
                            "to": to_date
                        },
                        "maxCloudCoverage": 30
                    }
                }]
            },
            "output": {
                "width": size[0],
                "height": size[1],
                "responses": [{
                    "identifier": "default",
                    "format": {
                        "type": "image/png"
                    }
                }]
            },
            "evalscript": evalscript
        }
        
        try:
            response = requests.post(
                SENTINEL_HUB_API_URL,
                headers={
                    "Authorization": f"Bearer {self.access_token}",
                    "Content-Type": "application/json"
                },
                json=payload
            )
            
            if response.status_code == 200:
                return {
                    "success": True,
                    "image_data": response.content,
                    "metadata": {
                        "lat": lat,
                        "lon": lon,
                        "date": date,
                        "bbox": bbox,
                        "resolution": resolution,
                        "size": size,
                        "time_range": {"from": from_date, "to": to_date}
                    }
                }
            else:
                return {
                    "error": f"API request failed: {response.status_code}",
                    "details": response.text
                }
                
        except Exception as e:
            return {"error": str(e)}
    
    def _validate_coords(self, lat: float, lon: float) -> bool:
        """Validate GPS coordinates"""
        try:
            lat = float(lat)
            lon = float(lon)
            return -90 <= lat <= 90 and -180 <= lon <= 180
        except (ValueError, TypeError):
            return False
    
    def _validate_date(self, date: str) -> bool:
        """Validate date format"""
        try:
            datetime.strptime(date, "%Y-%m-%d")
            return True
        except ValueError:
            return False


def analyze_location(lat: float, lon: float, date: str, output_dir: Path = OUTPUT_DIR):
    """
    Main function to fetch and analyze satellite imagery
    
    Returns analysis results and saves image to disk
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    
    client = SentinelHubClient()
    
    print(f"[*] Fetching satellite imagery for: {lat}, {lon} (date: {date})")
    
    result = client.get_satellite_image(lat, lon, date)
    
    if "error" in result:
        print(f"[-] Error: {result['error']}")
        if "details" in result:
            print(f"    Details: {result['details']}")
        return result
    
    # Save image
    safe_lat = str(lat).replace(".", "_").replace("-", "m")
    safe_lon = str(lon).replace(".", "_").replace("-", "m")
    safe_date = date.replace("-", "")
    
    image_filename = f"satellite_{safe_lat}_{safe_lon}_{safe_date}.png"
    image_path = output_dir / image_filename
    
    with open(image_path, "wb") as f:
        f.write(result["image_data"])
    
    print(f"[+] Image saved: {image_path}")
    
    # Save metadata
    metadata_filename = f"satellite_{safe_lat}_{safe_lon}_{safe_date}_metadata.json"
    metadata_path = output_dir / metadata_filename
    
    analysis = {
        "timestamp": datetime.now().isoformat(),
        "target": {
            "latitude": lat,
            "longitude": lon,
            "date_requested": date
        },
        "image": {
            "path": str(image_path),
            "filename": image_filename,
            "size_bytes": len(result["image_data"])
        },
        "metadata": result["metadata"],
        "analysis_notes": [
            "Manual analysis required for:",
            "- Visible infrastructure (buildings, antennas, parking lots)",
            "- Security features (fences, guard posts, cameras)",
            "- Access points (roads, entrances)",
            "- Nearby assets (power lines, data centers)",
            "- Changes over time (compare with historical imagery)"
        ],
        "osint_recommendations": [
            "Cross-reference with Google Maps/Street View",
            "Check OpenStreetMap for building metadata",
            "Look for publicly available floor plans",
            "Search for news about the location",
            "Check building permits/public records"
        ]
    }
    
    with open(metadata_path, "w") as f:
        json.dump(analysis, f, indent=2)
    
    print(f"[+] Metadata saved: {metadata_path}")
    print("[+] Analysis complete!")
    print(f"\n[*] OSINT Notes:")
    for note in analysis["analysis_notes"]:
        print(f"    {note}")
    
    return {
        "success": True,
        "image_path": str(image_path),
        "metadata_path": str(metadata_path),
        "analysis": analysis
    }


def demo_mode():
    """Demo mode without API - generates placeholder"""
    print("[!] DEMO MODE - No API credentials configured")
    print("[*] To enable real satellite imagery:")
    print("    1. Register at https://dataspace.copernicus.eu/")
    print("    2. Go to Dashboard > User Settings > OAuth Clients")
    print("    3. Create a new OAuth Client")
    print("    4. Set environment variables:")
    print("       SENTINEL_HUB_CLIENT_ID=your_client_id")
    print("       SENTINEL_HUB_CLIENT_SECRET=your_client_secret")
    print("")
    
    # Return demo data structure
    return {
        "demo": True,
        "message": "API credentials required for real imagery",
        "setup_url": "https://dataspace.copernicus.eu/"
    }


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python satellite_reco_script.py <lat> <lon> <date>")
        print("Example: python satellite_reco_script.py 48.8566 2.3522 2024-01-15")
        print("")
        print("Environment variables required:")
        print("  SENTINEL_HUB_CLIENT_ID")
        print("  SENTINEL_HUB_CLIENT_SECRET")
        sys.exit(1)
    
    lat = float(sys.argv[1])
    lon = float(sys.argv[2])
    date = sys.argv[3]
    
    # Check for API credentials
    if not os.environ.get("SENTINEL_HUB_CLIENT_ID"):
        result = demo_mode()
    else:
        result = analyze_location(lat, lon, date)
    
    print(json.dumps(result, indent=2, default=str))
