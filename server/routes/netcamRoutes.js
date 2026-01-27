/**
 * Netcam Studio API Routes
 */
const express = require('express');
const router = express.Router();
const netcamService = require('../services/netcamService');

// Test connection
router.get('/status', async (req, res) => {
    try {
        const status = await netcamService.testConnection();
        res.json(status);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Login to Netcam Studio
router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const result = await netcamService.login(username, password);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get all cameras
router.get('/cameras', async (req, res) => {
    try {
        const result = await netcamService.getCameras();
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get camera status
router.get('/cameras/:id/status', async (req, res) => {
    try {
        const result = await netcamService.getCameraStatus(req.params.id);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Toggle recording
router.post('/cameras/:id/recording', async (req, res) => {
    try {
        const { start } = req.body;
        const result = await netcamService.toggleRecording(req.params.id, start !== false);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Toggle motion detection
router.post('/cameras/:id/motion', async (req, res) => {
    try {
        const { enable } = req.body;
        const result = await netcamService.toggleMotionDetection(req.params.id, enable !== false);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// PTZ Control
router.post('/cameras/:id/ptz', async (req, res) => {
    try {
        const { command } = req.body;
        if (!command) {
            return res.status(400).json({ success: false, error: 'Command required' });
        }
        const result = await netcamService.ptzControl(req.params.id, command);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get recordings
router.get('/recordings', async (req, res) => {
    try {
        const { cameraId, startDate, endDate } = req.query;
        const result = await netcamService.getRecordings(cameraId, startDate, endDate);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get system status
router.get('/system', async (req, res) => {
    try {
        const result = await netcamService.getSystemStatus();
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get stream URL for camera
router.get('/cameras/:id/stream-url', async (req, res) => {
    try {
        await netcamService.ensureAuthenticated();
        const streamUrl = netcamService.getStreamUrl(req.params.id);
        const snapshotUrl = netcamService.getSnapshotUrl(req.params.id);
        res.json({ success: true, streamUrl, snapshotUrl });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Disconnect
router.post('/disconnect', async (req, res) => {
    try {
        await netcamService.disconnect();
        res.json({ success: true, message: 'Disconnected' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;
