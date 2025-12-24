/**
 * SATELLITE GEO-OSINT SERVICE
 * 
 * Service for fetching satellite imagery via Sentinel Hub API
 * Used for physical reconnaissance in bug bounty programs
 * 
 * Features:
 * - Sentinel Hub API integration (Copernicus Data Space)
 * - Image caching to respect rate limits
 * - Coordinate validation and sanitization
 * - Ethical usage tracking
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

class SatelliteOSINTService {
    constructor() {
        this.clientId = process.env.SENTINEL_HUB_CLIENT_ID;
        this.clientSecret = process.env.SENTINEL_HUB_CLIENT_SECRET;
        this.accessToken = null;
        this.tokenExpiry = null;
        
        this.authUrl = 'https://identity.dataspace.copernicus.eu/auth/realms/CDSE/protocol/openid-connect/token';
        this.apiUrl = 'https://sh.dataspace.copernicus.eu/api/v1/process';
        
        this.cacheDir = path.join(__dirname, 'data', 'satellite_cache');
        this.usageLog = path.join(__dirname, 'data', 'satellite_usage.json');
        
        this.ensureDirs();
        this.usage = this.loadUsage();
        
        if (this.clientId && this.clientSecret) {
            console.log('[SATELLITE-OSINT] Service initialized (API configured)');
        } else {
            console.log('[SATELLITE-OSINT] Service initialized (No API - register at dataspace.copernicus.eu)');
        }
    }

    ensureDirs() {
        if (!fs.existsSync(this.cacheDir)) {
            fs.mkdirSync(this.cacheDir, { recursive: true });
        }
    }

    loadUsage() {
        try {
            if (fs.existsSync(this.usageLog)) {
                return JSON.parse(fs.readFileSync(this.usageLog, 'utf8'));
            }
        } catch (e) {
            console.error('[SATELLITE-OSINT] Error loading usage:', e.message);
        }
        return { requests: [], totalRequests: 0, lastReset: new Date().toISOString() };
    }

    saveUsage() {
        try {
            fs.writeFileSync(this.usageLog, JSON.stringify(this.usage, null, 2));
        } catch (e) {
            console.error('[SATELLITE-OSINT] Error saving usage:', e.message);
        }
    }

    /**
     * Get service status
     */
    getStatus() {
        return {
            configured: !!(this.clientId && this.clientSecret),
            authenticated: !!this.accessToken,
            cacheDir: this.cacheDir,
            totalRequests: this.usage.totalRequests,
            monthlyLimit: 100, // Free tier limit
            remainingEstimate: Math.max(0, 100 - this.usage.totalRequests),
            registrationUrl: 'https://dataspace.copernicus.eu/'
        };
    }

    /**
     * Validate coordinates
     */
    validateCoords(lat, lon) {
        lat = parseFloat(lat);
        lon = parseFloat(lon);
        
        if (isNaN(lat) || isNaN(lon)) {
            return { valid: false, error: 'Invalid coordinate format' };
        }
        
        if (lat < -90 || lat > 90) {
            return { valid: false, error: 'Latitude must be between -90 and 90' };
        }
        
        if (lon < -180 || lon > 180) {
            return { valid: false, error: 'Longitude must be between -180 and 180' };
        }
        
        return { valid: true, lat, lon };
    }

    /**
     * Validate date format
     */
    validateDate(dateStr) {
        const regex = /^\d{4}-\d{2}-\d{2}$/;
        if (!regex.test(dateStr)) {
            return { valid: false, error: 'Date must be in YYYY-MM-DD format' };
        }
        
        const date = new Date(dateStr);
        if (isNaN(date.getTime())) {
            return { valid: false, error: 'Invalid date' };
        }
        
        // Don't allow future dates for satellite imagery
        if (date > new Date()) {
            return { valid: false, error: 'Cannot request future satellite imagery' };
        }
        
        return { valid: true, date: dateStr };
    }

    /**
     * Authenticate with Sentinel Hub
     */
    async authenticate() {
        if (!this.clientId || !this.clientSecret) {
            throw new Error('Sentinel Hub credentials not configured');
        }

        // Check if token is still valid
        if (this.accessToken && this.tokenExpiry && new Date() < this.tokenExpiry) {
            return true;
        }

        return new Promise((resolve, reject) => {
            const postData = new URLSearchParams({
                grant_type: 'client_credentials',
                client_id: this.clientId,
                client_secret: this.clientSecret
            }).toString();

            const url = new URL(this.authUrl);
            const options = {
                hostname: url.hostname,
                port: 443,
                path: url.pathname,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Length': Buffer.byteLength(postData)
                }
            };

            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        if (res.statusCode === 200) {
                            const json = JSON.parse(data);
                            this.accessToken = json.access_token;
                            this.tokenExpiry = new Date(Date.now() + (json.expires_in - 60) * 1000);
                            console.log('[SATELLITE-OSINT] Authentication successful');
                            resolve(true);
                        } else {
                            console.error('[SATELLITE-OSINT] Auth failed:', res.statusCode);
                            reject(new Error(`Authentication failed: ${res.statusCode}`));
                        }
                    } catch (e) {
                        reject(e);
                    }
                });
            });

            req.on('error', reject);
            req.write(postData);
            req.end();
        });
    }

    /**
     * Get satellite image for coordinates
     */
    async fetchImage(lat, lon, date, options = {}) {
        // Validate inputs
        const coordCheck = this.validateCoords(lat, lon);
        if (!coordCheck.valid) {
            return { success: false, error: coordCheck.error };
        }

        const dateCheck = this.validateDate(date);
        if (!dateCheck.valid) {
            return { success: false, error: dateCheck.error };
        }

        lat = coordCheck.lat;
        lon = coordCheck.lon;

        // Check cache first
        const cacheKey = `${lat}_${lon}_${date}`.replace(/\./g, 'd').replace(/-/g, '');
        const cachePath = path.join(this.cacheDir, `satellite_${cacheKey}.json`);
        
        if (fs.existsSync(cachePath)) {
            console.log('[SATELLITE-OSINT] Returning cached result');
            return JSON.parse(fs.readFileSync(cachePath, 'utf8'));
        }

        // Check rate limits
        if (this.usage.totalRequests >= 100) {
            return { 
                success: false, 
                error: 'Monthly rate limit reached (100 requests)',
                suggestion: 'Wait for monthly reset or upgrade to paid tier'
            };
        }

        try {
            await this.authenticate();
        } catch (authError) {
            return { 
                success: false, 
                error: 'Authentication failed', 
                details: authError.message,
                demo: this.getDemoData(lat, lon, date)
            };
        }

        // Calculate bounding box (~1km area)
        const resolution = options.resolution || 10;
        const bboxOffset = 0.005 * (resolution / 10);
        const bbox = [
            lon - bboxOffset,
            lat - bboxOffset,
            lon + bboxOffset,
            lat + bboxOffset
        ];

        // Build request
        const targetDate = new Date(date);
        const fromDate = new Date(targetDate);
        fromDate.setDate(fromDate.getDate() - 5);
        const toDate = new Date(targetDate);
        toDate.setDate(toDate.getDate() + 5);

        const evalscript = `
            //VERSION=3
            function setup() {
                return {
                    input: [{bands: ["B04", "B03", "B02"], units: "DN"}],
                    output: {bands: 3, sampleType: "AUTO"}
                };
            }
            function evaluatePixel(sample) {
                return [sample.B04/3000, sample.B03/3000, sample.B02/3000];
            }
        `;

        const payload = {
            input: {
                bounds: {
                    bbox,
                    properties: { crs: "http://www.opengis.net/def/crs/EPSG/0/4326" }
                },
                data: [{
                    type: "sentinel-2-l2a",
                    dataFilter: {
                        timeRange: {
                            from: fromDate.toISOString(),
                            to: toDate.toISOString()
                        },
                        maxCloudCoverage: options.maxCloud || 30
                    }
                }]
            },
            output: {
                width: options.width || 512,
                height: options.height || 512,
                responses: [{ identifier: "default", format: { type: "image/png" } }]
            },
            evalscript
        };

        return new Promise((resolve) => {
            const url = new URL(this.apiUrl);
            const postData = JSON.stringify(payload);
            
            const reqOptions = {
                hostname: url.hostname,
                port: 443,
                path: url.pathname,
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.accessToken}`,
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(postData)
                }
            };

            const req = https.request(reqOptions, (res) => {
                const chunks = [];
                res.on('data', chunk => chunks.push(chunk));
                res.on('end', () => {
                    if (res.statusCode === 200) {
                        const imageBuffer = Buffer.concat(chunks);
                        const imagePath = path.join(this.cacheDir, `satellite_${cacheKey}.png`);
                        
                        fs.writeFileSync(imagePath, imageBuffer);
                        
                        // Log usage
                        this.usage.requests.push({
                            lat, lon, date,
                            timestamp: new Date().toISOString()
                        });
                        this.usage.totalRequests++;
                        this.saveUsage();

                        const result = {
                            success: true,
                            imagePath,
                            imageBase64: imageBuffer.toString('base64'),
                            metadata: {
                                lat, lon, date,
                                bbox,
                                resolution,
                                size: { width: payload.output.width, height: payload.output.height },
                                timeRange: {
                                    from: fromDate.toISOString(),
                                    to: toDate.toISOString()
                                }
                            },
                            osintNotes: [
                                'Analyze for: buildings, antennas, parking lots',
                                'Look for: security features, access points, perimeter',
                                'Cross-reference: Google Maps, OpenStreetMap',
                                'Compare: historical imagery for changes'
                            ]
                        };

                        // Cache result
                        fs.writeFileSync(cachePath, JSON.stringify({
                            ...result,
                            imageBase64: '[cached - load from file]'
                        }, null, 2));

                        resolve(result);
                    } else {
                        resolve({
                            success: false,
                            error: `API request failed: ${res.statusCode}`,
                            demo: this.getDemoData(lat, lon, date)
                        });
                    }
                });
            });

            req.on('error', (e) => {
                resolve({
                    success: false,
                    error: e.message,
                    demo: this.getDemoData(lat, lon, date)
                });
            });

            req.write(postData);
            req.end();
        });
    }

    /**
     * Get demo data when API is not configured
     */
    getDemoData(lat, lon, date) {
        return {
            mode: 'demo',
            message: 'API credentials required for real imagery',
            coordinates: { lat, lon, date },
            setupSteps: [
                '1. Register at https://dataspace.copernicus.eu/',
                '2. Go to Dashboard > User Settings > OAuth Clients',
                '3. Create a new OAuth Client',
                '4. Add to .env: SENTINEL_HUB_CLIENT_ID and SENTINEL_HUB_CLIENT_SECRET'
            ],
            simulatedAnalysis: {
                location: `${lat}, ${lon}`,
                potentialFindings: [
                    'Building footprints visible',
                    'Parking lot capacity estimatable',
                    'Perimeter security features',
                    'Access roads and entry points',
                    'Antenna/satellite dish locations',
                    'Nearby infrastructure'
                ]
            }
        };
    }

    /**
     * Get known interesting targets for training
     */
    getTrainingTargets() {
        return [
            { name: 'Test Target - Paris', lat: 48.8566, lon: 2.3522, note: 'Major city center' },
            { name: 'Test Target - London', lat: 51.5074, lon: -0.1278, note: 'Major city center' },
            { name: 'Test Target - NYC', lat: 40.7128, lon: -74.0060, note: 'Major city center' },
            { name: 'Test Target - Tokyo', lat: 35.6762, lon: 139.6503, note: 'Major city center' }
        ];
    }
}

// Singleton
let instance = null;

function getSatelliteOSINTService() {
    if (!instance) {
        instance = new SatelliteOSINTService();
    }
    return instance;
}

module.exports = { SatelliteOSINTService, getSatelliteOSINTService };
