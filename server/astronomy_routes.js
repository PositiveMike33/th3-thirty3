/**
 * IPGeolocation Astronomy API Routes
 * Provides solar/lunar position data for Space Dashboard
 * 
 * API: https://api.ipgeolocation.io/v2/astronomy
 */

const express = require('express');
const router = express.Router();

// IPGeolocation API Key (set in .env as IPGEOLOCATION_API_KEY)
const API_KEY = process.env.IPGEOLOCATION_API_KEY || '';
const BASE_URL = 'https://api.ipgeolocation.io/v2/astronomy';

/**
 * GET /api/astronomy
 * Get astronomy data for current location (auto-detected by IP)
 */
router.get('/', async (req, res) => {
    try {
        if (!API_KEY) {
            return res.status(500).json({ 
                success: false, 
                error: 'IPGEOLOCATION_API_KEY not configured' 
            });
        }

        const response = await fetch(`${BASE_URL}?apiKey=${API_KEY}`);
        const data = await response.json();

        if (!response.ok) {
            return res.status(response.status).json({
                success: false,
                error: data.message || 'API request failed'
            });
        }

        res.json({ success: true, data });
    } catch (error) {
        console.error('[Astronomy] Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/astronomy/location
 * Get astronomy data for a specific location
 * Query params: location (required), elevation (optional)
 * Example: /api/astronomy/location?location=New York, US&elevation=10
 */
router.get('/location', async (req, res) => {
    try {
        if (!API_KEY) {
            return res.status(500).json({ 
                success: false, 
                error: 'IPGEOLOCATION_API_KEY not configured' 
            });
        }

        const { location, elevation } = req.query;

        if (!location) {
            return res.status(400).json({ 
                success: false, 
                error: 'Location parameter is required' 
            });
        }

        let url = `${BASE_URL}?apiKey=${API_KEY}&location=${encodeURIComponent(location)}`;
        if (elevation) {
            url += `&elevation=${elevation}`;
        }

        const response = await fetch(url);
        const data = await response.json();

        if (!response.ok) {
            return res.status(response.status).json({
                success: false,
                error: data.message || 'API request failed'
            });
        }

        res.json({ success: true, data });
    } catch (error) {
        console.error('[Astronomy] Location Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/astronomy/ip
 * Get astronomy data based on IP geolocation
 * Query params: ip (required)
 * Example: /api/astronomy/ip?ip=8.8.8.8
 */
router.get('/ip', async (req, res) => {
    try {
        if (!API_KEY) {
            return res.status(500).json({ 
                success: false, 
                error: 'IPGEOLOCATION_API_KEY not configured' 
            });
        }

        const { ip } = req.query;

        if (!ip) {
            return res.status(400).json({ 
                success: false, 
                error: 'IP address parameter is required' 
            });
        }

        const url = `${BASE_URL}?apiKey=${API_KEY}&ip=${ip}`;
        const response = await fetch(url);
        const data = await response.json();

        if (!response.ok) {
            return res.status(response.status).json({
                success: false,
                error: data.message || 'API request failed'
            });
        }

        res.json({ success: true, data });
    } catch (error) {
        console.error('[Astronomy] IP Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/astronomy/coords
 * Get astronomy data for specific coordinates
 * Query params: lat, long (required), elevation (optional)
 * Example: /api/astronomy/coords?lat=40.7128&long=-74.0060&elevation=10
 */
router.get('/coords', async (req, res) => {
    try {
        if (!API_KEY) {
            return res.status(500).json({ 
                success: false, 
                error: 'IPGEOLOCATION_API_KEY not configured' 
            });
        }

        const { lat, long, elevation } = req.query;

        if (!lat || !long) {
            return res.status(400).json({ 
                success: false, 
                error: 'Latitude and longitude are required' 
            });
        }

        let url = `${BASE_URL}?apiKey=${API_KEY}&lat=${lat}&long=${long}`;
        if (elevation) {
            url += `&elevation=${elevation}`;
        }

        const response = await fetch(url);
        const data = await response.json();

        if (!response.ok) {
            return res.status(response.status).json({
                success: false,
                error: data.message || 'API request failed'
            });
        }

        res.json({ success: true, data });
    } catch (error) {
        console.error('[Astronomy] Coords Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/astronomy/status
 * Check API status and configuration
 */
router.get('/status', (req, res) => {
    res.json({
        success: true,
        configured: !!API_KEY,
        endpoints: [
            'GET /api/astronomy - Current location (auto-detect)',
            'GET /api/astronomy/location?location=City,Country - By location name',
            'GET /api/astronomy/ip?ip=8.8.8.8 - By IP geolocation',
            'GET /api/astronomy/coords?lat=X&long=Y - By coordinates'
        ],
        dataProvided: [
            'Sun/Moon rise/set times',
            'Sun/Moon altitude & azimuth',
            'Moon illumination percentage',
            'Moon phase name',
            'Solar noon',
            'Day length'
        ]
    });
});

module.exports = router;
