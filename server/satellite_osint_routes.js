/**
 * SATELLITE GEO-OSINT API ROUTES
 * 
 * REST API for satellite imagery reconnaissance
 * Used by Bug Bounty agents for physical reconnaissance
 */

const express = require('express');
const router = express.Router();
const { getSatelliteOSINTService } = require('./satellite_osint_service');

// Lazy load service
let service = null;
function getService() {
    if (!service) {
        service = getSatelliteOSINTService();
    }
    return service;
}

/**
 * GET /api/satellite/status
 * Get satellite OSINT service status
 */
router.get('/status', (req, res) => {
    try {
        const status = getService().getStatus();
        res.json({ success: true, ...status });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/satellite/fetch
 * Fetch satellite imagery for coordinates
 * 
 * Body: {
 *   lat: 48.8566,
 *   lon: 2.3522,
 *   date: "2024-01-15",
 *   options: {
 *     resolution: 10,      // meters per pixel
 *     width: 512,          // image width
 *     height: 512,         // image height
 *     maxCloud: 30         // max cloud coverage %
 *   }
 * }
 */
router.post('/fetch', async (req, res) => {
    try {
        const { lat, lon, date, options = {} } = req.body;
        
        if (!lat || !lon || !date) {
            return res.status(400).json({
                success: false,
                error: 'lat, lon, and date are required',
                example: {
                    lat: 48.8566,
                    lon: 2.3522,
                    date: '2024-01-15'
                }
            });
        }

        const result = await getService().fetchImage(lat, lon, date, options);
        
        // Don't send base64 image in JSON (too large), just metadata and path
        if (result.success && result.imageBase64) {
            res.json({
                ...result,
                imageBase64: `[${result.imageBase64.length} bytes - use /api/satellite/image endpoint]`
            });
        } else {
            res.json(result);
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/satellite/image/:cacheKey
 * Get cached satellite image
 */
router.get('/image/:cacheKey', (req, res) => {
    try {
        const path = require('path');
        const fs = require('fs');
        
        const cacheKey = req.params.cacheKey.replace(/[^a-zA-Z0-9_d]/g, '');
        const imagePath = path.join(__dirname, 'data', 'satellite_cache', `satellite_${cacheKey}.png`);
        
        if (fs.existsSync(imagePath)) {
            res.setHeader('Content-Type', 'image/png');
            res.sendFile(imagePath);
        } else {
            res.status(404).json({ success: false, error: 'Image not found in cache' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/satellite/training-targets
 * Get known targets for training
 */
router.get('/training-targets', (req, res) => {
    try {
        const targets = getService().getTrainingTargets();
        res.json({ 
            success: true, 
            targets,
            disclaimer: 'These are public city centers for testing only. Do not use for surveillance.'
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/satellite/analyze
 * Request analysis of satellite imagery (integrate with LLM)
 */
router.post('/analyze', async (req, res) => {
    try {
        const { lat, lon, date, analysisType = 'general' } = req.body;
        
        if (!lat || !lon || !date) {
            return res.status(400).json({
                success: false,
                error: 'lat, lon, and date are required'
            });
        }

        // First fetch the image
        const imageResult = await getService().fetchImage(lat, lon, date);
        
        if (!imageResult.success) {
            return res.json(imageResult);
        }

        // Return analysis prompts for LLM
        const analysisPrompts = {
            general: `Analyze this satellite image of coordinates ${lat}, ${lon} taken around ${date}. 
                Identify: buildings, roads, parking areas, security features, access points.`,
            security: `Security analysis for ${lat}, ${lon}: 
                Identify perimeter fencing, guard posts, cameras, entry/exit points, 
                lighting infrastructure, and potential blind spots.`,
            infrastructure: `Infrastructure analysis for ${lat}, ${lon}: 
                Identify buildings, antenna arrays, satellite dishes, power lines, 
                data center cooling units, backup generators.`,
            changes: `Change detection for ${lat}, ${lon}: 
                Compare with previous imagery to identify new construction, 
                removed structures, or modifications to the site.`
        };

        res.json({
            success: true,
            imagePath: imageResult.imagePath,
            metadata: imageResult.metadata,
            analysisPrompt: analysisPrompts[analysisType] || analysisPrompts.general,
            osintNotes: imageResult.osintNotes,
            nextSteps: [
                'Send image to vision-capable LLM for analysis',
                'Cross-reference with Google Maps Street View',
                'Check OpenStreetMap for building tags',
                'Search for public building permits or news'
            ]
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/satellite/usage
 * Get API usage statistics
 */
router.get('/usage', (req, res) => {
    try {
        const status = getService().getStatus();
        res.json({
            success: true,
            totalRequests: status.totalRequests,
            monthlyLimit: status.monthlyLimit,
            remaining: status.remainingEstimate,
            resetNote: 'Monthly limit resets at the start of each month'
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;
