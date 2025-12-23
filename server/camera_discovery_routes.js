/**
 * Camera Discovery API Routes
 * Passive camera discovery endpoints for personal network
 * 
 * Base path: /api/camera-discovery
 */

const express = require('express');
const router = express.Router();

// Service will be injected
let discoveryService = null;

/**
 * Initialize routes with service instance
 */
function initRoutes(cameraDiscoveryService) {
    discoveryService = cameraDiscoveryService;
    return router;
}

// ============================================
// Discovery Endpoints
// ============================================

/**
 * GET /api/camera-discovery/status
 * Get discovery service status
 */
router.get('/status', (req, res) => {
    try {
        const status = discoveryService.getStatus();
        res.json({
            success: true,
            ...status
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /api/camera-discovery/scan
 * Start full network scan for cameras
 * 
 * Body: { networkRange?: string } (default: auto-detect)
 */
router.post('/scan', async (req, res) => {
    try {
        const { networkRange } = req.body;
        
        // Check if scan already running
        if (discoveryService.isScanning) {
            return res.status(409).json({
                success: false,
                error: 'Scan already in progress',
                message: 'Please wait for current scan to complete'
            });
        }
        
        // Start scan (don't wait for completion)
        const result = await discoveryService.discover(networkRange);
        
        res.json(result);
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /api/camera-discovery/quick-scan
 * Quick scan specific IP for camera
 * 
 * Body: { ip: string }
 */
router.post('/quick-scan', async (req, res) => {
    try {
        const { ip } = req.body;
        
        if (!ip) {
            return res.status(400).json({
                success: false,
                error: 'IP address required'
            });
        }
        
        // Validate IP format
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(ip)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid IP address format'
            });
        }
        
        const result = await discoveryService.quickScan(ip);
        res.json(result);
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /api/camera-discovery/results
 * Get last scan results
 */
router.get('/results', (req, res) => {
    try {
        const results = discoveryService.getLastScanResults();
        res.json({
            success: true,
            ...results
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /api/camera-discovery/cameras
 * Get list of discovered cameras
 */
router.get('/cameras', (req, res) => {
    try {
        const cameras = discoveryService.discoveredCameras;
        res.json({
            success: true,
            count: cameras.length,
            cameras
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /api/camera-discovery/network-range
 * Get default network range based on system
 */
router.get('/network-range', async (req, res) => {
    try {
        const range = await discoveryService.getDefaultNetworkRange();
        res.json({
            success: true,
            networkRange: range
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ============================================
// Script Execution Endpoints
// ============================================

/**
 * POST /api/camera-discovery/python
 * Run Python discovery script (cam_discover.py)
 * 
 * Body: { networkRange?: string }
 */
router.post('/python', async (req, res) => {
    try {
        const { networkRange } = req.body;
        const result = await discoveryService.runPythonDiscovery(networkRange);
        res.json(result);
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /api/camera-discovery/bash
 * Run Bash discovery script via WSL (find_cams.sh)
 * 
 * Body: { networkRange?: string }
 */
router.post('/bash', async (req, res) => {
    try {
        const { networkRange } = req.body;
        const result = await discoveryService.runBashDiscovery(networkRange);
        res.json(result);
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ============================================
// Management Endpoints
// ============================================

/**
 * DELETE /api/camera-discovery/history
 * Clear scan history
 */
router.delete('/history', (req, res) => {
    try {
        const result = discoveryService.clearHistory();
        res.json(result);
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /api/camera-discovery/help
 * Get usage instructions
 */
router.get('/help', (req, res) => {
    res.json({
        service: 'Camera Discovery Service',
        description: 'Passive camera discovery for personal EasyLife/Tuya cameras',
        disclaimer: '⚠️ For authorized use on YOUR OWN network only!',
        endpoints: {
            'GET /status': 'Get service status and discovered cameras',
            'POST /scan': 'Start full network scan (body: { networkRange?: string })',
            'POST /quick-scan': 'Quick scan specific IP (body: { ip: string })',
            'GET /results': 'Get last scan results',
            'GET /cameras': 'Get list of discovered cameras',
            'GET /network-range': 'Get default network range',
            'POST /python': 'Run Python discovery script',
            'POST /bash': 'Run Bash discovery script via WSL',
            'DELETE /history': 'Clear scan history'
        },
        detectedPorts: {
            80: 'HTTP (Web Interface)',
            554: 'RTSP (Video Stream)',
            8080: 'HTTP Alt (Web Interface)',
            8081: 'HTTP Alt 2',
            6668: 'Tuya Local Control',
            37777: 'Dahua Protocol',
            34567: 'XiongMai Protocol'
        },
        examples: {
            fullScan: 'POST /api/camera-discovery/scan { "networkRange": "192.168.1.0/24" }',
            quickScan: 'POST /api/camera-discovery/quick-scan { "ip": "192.168.1.165" }'
        }
    });
});

module.exports = initRoutes;
