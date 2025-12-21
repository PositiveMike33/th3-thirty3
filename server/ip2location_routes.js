/**
 * IP2Location API Routes
 * Comprehensive IP Geolocation using ip2location.io
 * 
 * API: https://api.ip2location.io
 * Features: City, Region, Coordinates, Timezone, Proxy Detection
 */

const express = require('express');
const router = express.Router();

// IP2Location API Key
const API_KEY = process.env.IP2LOCATION_API_KEY || '7CB97DB64402CC3F7649A43BD6C2C9B9';
const BASE_URL = 'https://api.ip2location.io';

/**
 * GET /api/ip2location
 * Get geolocation for current IP (auto-detect)
 */
router.get('/', async (req, res) => {
    try {
        const response = await fetch(`${BASE_URL}/?key=${API_KEY}`);
        const data = await response.json();

        if (data.error) {
            return res.status(400).json({
                success: false,
                error: data.error.error_message || 'API request failed'
            });
        }

        res.json({ success: true, data });
    } catch (error) {
        console.error('[IP2Location] Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/ip2location/lookup
 * Get detailed geolocation for a specific IP
 * Query params: ip (required)
 * Example: /api/ip2location/lookup?ip=8.8.8.8
 */
router.get('/lookup', async (req, res) => {
    try {
        const { ip } = req.query;

        if (!ip) {
            return res.status(400).json({ 
                success: false, 
                error: 'IP address parameter is required' 
            });
        }

        const response = await fetch(`${BASE_URL}/?key=${API_KEY}&ip=${ip}`);
        const data = await response.json();

        if (data.error) {
            return res.status(400).json({
                success: false,
                error: data.error.error_message || 'API request failed'
            });
        }

        // Enhanced response with formatted data
        res.json({ 
            success: true, 
            data: {
                ip: data.ip,
                country: {
                    code: data.country_code,
                    name: data.country_name
                },
                region: data.region_name,
                city: data.city_name,
                coordinates: {
                    latitude: data.latitude,
                    longitude: data.longitude
                },
                zip_code: data.zip_code,
                timezone: data.time_zone,
                network: {
                    asn: data.asn,
                    as_name: data.as
                },
                security: {
                    is_proxy: data.is_proxy
                }
            }
        });
    } catch (error) {
        console.error('[IP2Location] Lookup Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/ip2location/raw
 * Get raw API response for a specific IP
 */
router.get('/raw', async (req, res) => {
    try {
        const { ip } = req.query;
        const url = ip ? `${BASE_URL}/?key=${API_KEY}&ip=${ip}` : `${BASE_URL}/?key=${API_KEY}`;
        
        const response = await fetch(url);
        const data = await response.json();

        res.json({ success: true, raw: data });
    } catch (error) {
        console.error('[IP2Location] Raw Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/ip2location/batch
 * Lookup multiple IPs at once
 * Body: { ips: ["8.8.8.8", "1.1.1.1"] }
 */
router.post('/batch', async (req, res) => {
    try {
        const { ips } = req.body;

        if (!ips || !Array.isArray(ips) || ips.length === 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'Array of IP addresses required' 
            });
        }

        // Limit to 20 IPs per batch
        const limitedIps = ips.slice(0, 20);
        
        const results = await Promise.all(
            limitedIps.map(async (ip) => {
                try {
                    const response = await fetch(`${BASE_URL}/?key=${API_KEY}&ip=${ip}`);
                    const data = await response.json();
                    
                    if (data.error) {
                        return { ip, success: false, error: data.error.error_message };
                    }
                    
                    return {
                        ip: data.ip,
                        country: data.country_name,
                        country_code: data.country_code,
                        region: data.region_name,
                        city: data.city_name,
                        lat: data.latitude,
                        lon: data.longitude,
                        isp: data.as,
                        is_proxy: data.is_proxy,
                        success: true
                    };
                } catch (err) {
                    return { ip, success: false, error: err.message };
                }
            })
        );

        res.json({ 
            success: true, 
            count: results.length,
            results 
        });
    } catch (error) {
        console.error('[IP2Location] Batch Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/ip2location/status
 * Check API status and configuration
 */
router.get('/status', (req, res) => {
    res.json({
        success: true,
        service: 'ip2location.io',
        configured: !!API_KEY,
        endpoints: [
            'GET /api/ip2location - Current IP geolocation',
            'GET /api/ip2location/lookup?ip=X.X.X.X - Lookup specific IP',
            'GET /api/ip2location/raw?ip=X.X.X.X - Raw API response',
            'POST /api/ip2location/batch - Batch lookup (max 20 IPs)'
        ],
        dataProvided: [
            'IP Address',
            'Country (code + name)',
            'Region/State',
            'City',
            'Latitude/Longitude',
            'ZIP/Postal Code',
            'Timezone',
            'ASN & ISP Name',
            'Proxy Detection'
        ]
    });
});

module.exports = router;
