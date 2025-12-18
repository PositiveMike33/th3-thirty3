/**
 * Tuya Camera Routes
 * API endpoints for EasyLife/Tuya camera control
 */

const express = require('express');
const router = express.Router();
const TuyaCameraService = require('./tuya_camera_service');

const tuyaService = new TuyaCameraService();

// ==========================================
// DEVICE MANAGEMENT
// ==========================================

/**
 * GET /tuya/status
 * Get service status
 */
router.get('/status', (req, res) => {
    try {
        const status = tuyaService.getStatus();
        res.json({ success: true, ...status });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /tuya/devices
 * Get all Tuya devices
 */
router.get('/devices', (req, res) => {
    try {
        const devices = tuyaService.getAllDevices();
        res.json({
            success: true,
            count: devices.length,
            devices
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /tuya/devices
 * Add a new Tuya device
 * Body: { deviceId, localKey, ip, name, version }
 */
router.post('/devices', (req, res) => {
    try {
        const { deviceId, localKey, ip, name, version, hasPTZ } = req.body;
        
        if (!deviceId || !ip) {
            return res.status(400).json({ 
                error: 'deviceId and ip are required',
                hint: 'Get deviceId and localKey from Tuya IoT Developer Platform'
            });
        }
        
        const device = tuyaService.addDevice({
            deviceId,
            localKey,
            ip,
            name,
            version,
            hasPTZ
        });
        
        res.json({ success: true, device });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /tuya/devices/:id
 * Get a specific device
 */
router.get('/devices/:id', (req, res) => {
    try {
        const device = tuyaService.getDevice(req.params.id);
        if (!device) {
            return res.status(404).json({ error: 'Device not found' });
        }
        res.json({ success: true, device });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * DELETE /tuya/devices/:id
 * Remove a device
 */
router.delete('/devices/:id', (req, res) => {
    try {
        const deleted = tuyaService.removeDevice(req.params.id);
        res.json({ success: deleted });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /tuya/devices/:id/test
 * Test device connection
 */
router.post('/devices/:id/test', async (req, res) => {
    try {
        const result = await tuyaService.testConnection(req.params.id);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// CAMERA CONTROL
// ==========================================

/**
 * POST /tuya/devices/:id/ptz
 * Control PTZ (Pan-Tilt-Zoom)
 * Body: { direction: 'up'|'down'|'left'|'right'|'stop', duration: 500 }
 */
router.post('/devices/:id/ptz', async (req, res) => {
    try {
        const { direction, duration = 500 } = req.body;
        
        if (!direction) {
            return res.status(400).json({ 
                error: 'Direction required',
                validDirections: ['up', 'down', 'left', 'right', 'stop']
            });
        }
        
        const result = await tuyaService.ptzControl(req.params.id, direction, duration);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /tuya/devices/:id/night-vision
 * Set night vision mode
 * Body: { mode: 'auto'|'on'|'off' }
 */
router.post('/devices/:id/night-vision', async (req, res) => {
    try {
        const { mode = 'auto' } = req.body;
        const result = await tuyaService.setNightVision(req.params.id, mode);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /tuya/devices/:id/motion-detection
 * Toggle motion detection
 * Body: { enabled: true|false }
 */
router.post('/devices/:id/motion-detection', async (req, res) => {
    try {
        const { enabled = true } = req.body;
        const result = await tuyaService.setMotionDetection(req.params.id, enabled);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /tuya/devices/:id/recording
 * Toggle recording
 * Body: { enabled: true|false }
 */
router.post('/devices/:id/recording', async (req, res) => {
    try {
        const { enabled = true } = req.body;
        const result = await tuyaService.setRecording(req.params.id, enabled);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /tuya/devices/:id/power
 * Toggle camera power
 * Body: { on: true|false }
 */
router.post('/devices/:id/power', async (req, res) => {
    try {
        const { on = true } = req.body;
        const result = await tuyaService.setPower(req.params.id, on);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /tuya/devices/:id/query
 * Query device status (all data points)
 */
router.get('/devices/:id/query', async (req, res) => {
    try {
        const result = await tuyaService.queryStatus(req.params.id);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// DISCOVERY & HELP
// ==========================================

/**
 * POST /tuya/discover
 * Discover Tuya devices on network
 */
router.post('/discover', async (req, res) => {
    try {
        const { timeout = 10000 } = req.body;
        
        res.json({
            success: true,
            message: 'Discovery started. This may take 10-30 seconds.',
            note: 'Results will be logged to console'
        });
        
        // Run discovery in background
        tuyaService.discoverDevices(timeout).then(devices => {
            console.log('[TUYA] Discovered devices:', devices);
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /tuya/help/local-key
 * Get instructions for obtaining Local Key
 */
router.get('/help/local-key', (req, res) => {
    try {
        const instructions = tuyaService.getLocalKeyInstructions();
        res.json({ success: true, ...instructions });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /tuya/quick-setup
 * Quick setup with known device info from network scan
 */
router.post('/quick-setup', async (req, res) => {
    try {
        const { ip, name, deviceId, localKey } = req.body;
        
        if (!ip) {
            return res.status(400).json({ error: 'IP address required' });
        }
        
        // Generate a temporary device ID if not provided
        const devId = deviceId || `easylife_${ip.replace(/\./g, '_')}`;
        
        const device = tuyaService.addDevice({
            deviceId: devId,
            ip,
            name: name || `EasyLife Camera @ ${ip}`,
            localKey: localKey || null, // Will need to be added later
            hasPTZ: true
        });
        
        // Test connection
        const testResult = await tuyaService.testConnection(device.id);
        
        res.json({
            success: true,
            device,
            connectionTest: testResult,
            nextStep: localKey ? 
                'Device configured and ready for control' :
                'Device added. Get Local Key from Tuya IoT Platform: GET /api/tuya/help/local-key'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
