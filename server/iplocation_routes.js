/**
 * IP Location API Routes
 * Free IP Geolocation using iplocation.net (no API key required)
 * 
 * API: https://api.iplocation.net
 */

const express = require('express');
const router = express.Router();

const BASE_URL = 'https://api.iplocation.net';

/**
 * GET /api/iplocation
 * Get current public IP
 */
router.get('/', async (req, res) => {
    try {
        const response = await fetch(`${BASE_URL}/?cmd=get-ip`);
        const data = await response.json();

        if (data.response_code !== '200' && data.response_code !== 200) {
            return res.status(400).json({
                success: false,
                error: data.response_message || 'API request failed'
            });
        }

        res.json({ 
            success: true, 
            data: {
                ip: data.ip,
                ip_version: data.ip_version
            }
        });
    } catch (error) {
        console.error('[IPLocation] Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/iplocation/lookup
 * Get geolocation data for a specific IP
 * Query params: ip (required)
 * Example: /api/iplocation/lookup?ip=8.8.8.8
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

        const response = await fetch(`${BASE_URL}/?ip=${ip}`);
        const data = await response.json();

        if (data.response_code !== '200' && data.response_code !== 200) {
            return res.status(400).json({
                success: false,
                error: data.response_message || 'API request failed'
            });
        }

        res.json({ 
            success: true, 
            data: {
                ip: data.ip,
                ip_number: data.ip_number,
                ip_version: data.ip_version,
                country_name: data.country_name,
                country_code: data.country_code2,
                isp: data.isp
            }
        });
    } catch (error) {
        console.error('[IPLocation] Lookup Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/iplocation/batch
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

        // Limit to 10 IPs to avoid abuse
        const limitedIps = ips.slice(0, 10);
        
        const results = await Promise.all(
            limitedIps.map(async (ip) => {
                try {
                    const response = await fetch(`${BASE_URL}/?ip=${ip}`);
                    const data = await response.json();
                    return {
                        ip: data.ip,
                        country_name: data.country_name,
                        country_code: data.country_code2,
                        isp: data.isp,
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
        console.error('[IPLocation] Batch Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/iplocation/status
 * Check API status
 */
router.get('/status', (req, res) => {
    res.json({
        success: true,
        service: 'iplocation.net',
        requiresApiKey: false,
        endpoints: [
            'GET /api/iplocation - Get current public IP',
            'GET /api/iplocation/lookup?ip=X.X.X.X - Lookup IP geolocation',
            'POST /api/iplocation/batch - Lookup multiple IPs (max 10)'
        ],
        dataProvided: [
            'IP address',
            'Country name & code',
            'ISP (Internet Service Provider)'
        ]
    });
});

module.exports = router;
