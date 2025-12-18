/**
 * Camera Control Routes
 * API endpoints for EasyLife camera management
 */

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const CameraService = require('./camera_service');

const cameraService = new CameraService();

// ==========================================
// CAMERA MANAGEMENT
// ==========================================

/**
 * GET /cameras
 * Get all registered cameras
 */
router.get('/', (req, res) => {
    try {
        const cameras = cameraService.getAllCameras();
        res.json({
            success: true,
            count: cameras.length,
            cameras
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /cameras/status
 * Get camera service status
 */
router.get('/status', (req, res) => {
    try {
        const status = cameraService.getStatus();
        res.json({ success: true, ...status });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /cameras
 * Add a new camera
 */
router.post('/', (req, res) => {
    try {
        const { name, ip, username, password, rtspPort, httpPort, rtspPath, hasPTZ, supportsONVIF, model } = req.body;
        
        if (!ip) {
            return res.status(400).json({ error: 'IP address required' });
        }
        
        const camera = cameraService.addCamera({
            name,
            ip,
            username,
            password,
            rtspPort,
            httpPort,
            rtspPath,
            hasPTZ,
            supportsONVIF,
            model
        });
        
        res.json({ success: true, camera });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /cameras/:id
 * Get a specific camera
 */
router.get('/:id', (req, res) => {
    try {
        const camera = cameraService.getCamera(req.params.id);
        if (!camera) {
            return res.status(404).json({ error: 'Camera not found' });
        }
        res.json({ success: true, camera });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * DELETE /cameras/:id
 * Remove a camera
 */
router.delete('/:id', (req, res) => {
    try {
        const deleted = cameraService.removeCamera(req.params.id);
        res.json({ success: deleted });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /cameras/:id/stream
 * Get stream info for a camera
 */
router.get('/:id/stream', (req, res) => {
    try {
        const streamInfo = cameraService.getStreamInfo(req.params.id);
        if (!streamInfo) {
            return res.status(404).json({ error: 'Camera not found' });
        }
        res.json({ success: true, ...streamInfo });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// CAMERA CONTROL
// ==========================================

/**
 * POST /cameras/:id/test
 * Test camera connection
 */
router.post('/:id/test', async (req, res) => {
    try {
        const result = await cameraService.testConnection(req.params.id);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /cameras/:id/snapshot
 * Capture a snapshot from camera
 */
router.post('/:id/snapshot', async (req, res) => {
    try {
        const result = await cameraService.captureSnapshot(req.params.id);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /cameras/:id/snapshot
 * Get latest snapshot (alias for capture)
 */
router.get('/:id/snapshot', async (req, res) => {
    try {
        const result = await cameraService.captureSnapshot(req.params.id);
        
        if (result.success && result.filepath) {
            res.sendFile(result.filepath);
        } else {
            res.status(500).json(result);
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /cameras/:id/ptz
 * Control PTZ (Pan-Tilt-Zoom)
 * Body: { direction: 'up'|'down'|'left'|'right'|'home'|'zoomin'|'zoomout'|'stop', speed: 1-10 }
 */
router.post('/:id/ptz', async (req, res) => {
    try {
        const { direction, speed = 5 } = req.body;
        
        if (!direction) {
            return res.status(400).json({ error: 'Direction required (up, down, left, right, home, zoomin, zoomout, stop)' });
        }
        
        const result = await cameraService.ptzControl(req.params.id, direction, speed);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// DISCOVERY & SNAPSHOTS
// ==========================================

/**
 * POST /cameras/discover
 * Discover cameras on local network
 */
router.post('/discover', async (req, res) => {
    try {
        const { subnet = '192.168.1' } = req.body;
        
        res.json({
            success: true,
            message: 'Discovery started',
            note: 'This may take 1-2 minutes...'
        });
        
        // Run discovery in background
        cameraService.discoverCameras(subnet).then(discovered => {
            console.log('[CAMERA] Discovery complete:', discovered);
            cameraService.emit('discovery-complete', discovered);
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /cameras/snapshots/:filename
 * Serve snapshot images
 */
router.get('/snapshots/:filename', (req, res) => {
    try {
        const filepath = path.join(__dirname, 'data', 'camera_snapshots', req.params.filename);
        
        if (fs.existsSync(filepath)) {
            res.sendFile(filepath);
        } else {
            res.status(404).json({ error: 'Snapshot not found' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /cameras/quick-add
 * Quick add camera with auto-detection of settings
 */
router.post('/quick-add', async (req, res) => {
    try {
        const { ip, username = 'admin', password = 'admin', name } = req.body;
        
        if (!ip) {
            return res.status(400).json({ error: 'IP address required' });
        }
        
        // Add camera with defaults
        const camera = cameraService.addCamera({
            name: name || `EasyLife @ ${ip}`,
            ip,
            username,
            password,
            hasPTZ: true,  // Assume PTZ support
            supportsONVIF: true
        });
        
        // Auto-test connection
        const testResult = await cameraService.testConnection(camera.id);
        
        res.json({
            success: true,
            camera,
            connectionTest: testResult
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
