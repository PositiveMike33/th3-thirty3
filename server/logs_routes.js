/**
 * Logs API Routes
 * Endpoints for viewing and managing logs
 */

const express = require('express');
const router = express.Router();
const logger = require('./logging_service');

// GET /api/logs - Get recent logs
router.get('/', (req, res) => {
    const lines = parseInt(req.query.lines) || 100;
    const logs = logger.getRecentLogs(lines);
    res.json({ success: true, logs, count: logs.length });
});

// GET /api/logs/recent - Frontend compatibility route
router.get('/recent', (req, res) => {
    const limit = parseInt(req.query.limit) || 100;
    const logs = logger.getRecentLogs(limit);
    res.json({ success: true, logs, count: logs.length });
});

// GET /api/logs/stats - Get log statistics
router.get('/stats', (req, res) => {
    const stats = logger.getStats();
    res.json({ success: true, stats });
});

// POST /api/logs/write - Write a log entry (for frontend logging)
router.post('/write', (req, res) => {
    const { level = 'INFO', component = 'frontend', message, data } = req.body;

    if (!message) {
        return res.status(400).json({ success: false, error: 'Message required' });
    }

    switch (level.toUpperCase()) {
        case 'DEBUG':
            logger.debug(component, message, data);
            break;
        case 'WARN':
            logger.warn(component, message, data);
            break;
        case 'ERROR':
            logger.error(component, message, data);
            break;
        default:
            logger.info(component, message, data);
    }

    res.json({ success: true });
});

module.exports = router;
