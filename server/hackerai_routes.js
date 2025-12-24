/**
 * HACKERAI API ROUTES
 * 
 * REST API for HackerAI integration
 */

const express = require('express');
const router = express.Router();
const { getHackerAIService } = require('./hackerai_service');

// Lazy load service
let service = null;
function getService() {
    if (!service) {
        service = getHackerAIService();
    }
    return service;
}

/**
 * GET /api/hackerai/status
 * Get HackerAI service status
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
 * GET /api/hackerai/commands
 * Get quick start commands
 */
router.get('/commands', (req, res) => {
    try {
        const commands = getService().getQuickStartCommands();
        res.json({ success: true, commands });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hackerai/agent/start
 * Start the local HackerAI agent
 */
router.post('/agent/start', async (req, res) => {
    try {
        const { name, image, hostMode } = req.body;
        const result = await getService().startAgent({ name, image, hostMode });
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hackerai/agent/start-kali
 * Start with Kali Linux image
 */
router.post('/agent/start-kali', async (req, res) => {
    try {
        const { name } = req.body;
        const result = await getService().startKaliAgent(name);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hackerai/agent/stop
 * Stop the running agent
 */
router.post('/agent/stop', async (req, res) => {
    try {
        const result = await getService().stopAgent();
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/hackerai/logs
 * Get agent logs
 */
router.get('/logs', (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const logs = getService().getLogs(limit);
        res.json({ success: true, logs });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * DELETE /api/hackerai/logs
 * Clear logs
 */
router.delete('/logs', (req, res) => {
    try {
        getService().clearLogs();
        res.json({ success: true, message: 'Logs cleared' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/hackerai/check
 * Check if HackerAI is installed
 */
router.get('/check', async (req, res) => {
    try {
        const result = await getService().checkInstallation();
        res.json({ success: true, ...result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;
