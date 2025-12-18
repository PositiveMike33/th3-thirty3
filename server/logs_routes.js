/**
 * Server Logs Routes - REAL-TIME VERSION
 * Captures console output and streams to frontend via Socket.io
 */

const express = require('express');
const router = express.Router();

// In-memory log buffer (circular buffer of last 500 logs)
const MAX_LOGS = 500;
let logBuffer = [];
let logId = 0;
let socketService = null;

// Set socket service reference
const setSocketService = (socket) => {
    socketService = socket;
    console.log('[LOGS] Socket service connected for real-time logs');
};

// Override console methods to capture logs
const originalConsole = {
    log: console.log,
    warn: console.warn,
    error: console.error,
    info: console.info
};

// Capture log function with real-time emission
const captureLog = (level, ...args) => {
    const message = args.map(arg => 
        typeof arg === 'object' ? JSON.stringify(arg) : String(arg)
    ).join(' ');
    
    const logEntry = {
        id: ++logId,
        timestamp: new Date().toISOString(),
        level,
        message
    };
    
    logBuffer.push(logEntry);
    
    // Keep buffer at max size
    if (logBuffer.length > MAX_LOGS) {
        logBuffer = logBuffer.slice(-MAX_LOGS);
    }
    
    // Emit to all connected clients via Socket.io
    if (socketService && socketService.io) {
        socketService.io.emit('server:log', logEntry);
    }
    
    // Call original console method
    originalConsole[level](...args);
};

// Start capturing logs
const startCapture = () => {
    console.log = (...args) => captureLog('log', ...args);
    console.warn = (...args) => captureLog('warn', ...args);
    console.error = (...args) => captureLog('error', ...args);
    console.info = (...args) => captureLog('info', ...args);
    
    originalConsole.log('[LOGS] Real-time server log capture started');
};

// Stop capturing (restore original)
const stopCapture = () => {
    console.log = originalConsole.log;
    console.warn = originalConsole.warn;
    console.error = originalConsole.error;
    console.info = originalConsole.info;
};

// Start capture when module loads
startCapture();

// Track last sent log ID per client
const clientLastLog = new Map();

/**
 * GET /api/logs/recent
 * Returns the most recent logs
 */
router.get('/recent', (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 100, MAX_LOGS);
    const logs = logBuffer.slice(-limit);
    
    res.json({
        success: true,
        logs,
        total: logBuffer.length,
        lastId: logId
    });
});

/**
 * GET /api/logs/stream
 * Returns only new logs since last request (for polling fallback)
 */
router.get('/stream', (req, res) => {
    const clientId = req.query.clientId || req.ip;
    const lastKnownId = parseInt(req.query.lastId) || clientLastLog.get(clientId) || 0;
    
    // Get only new logs
    const newLogs = logBuffer.filter(log => log.id > lastKnownId);
    
    // Update client's last known log
    if (newLogs.length > 0) {
        clientLastLog.set(clientId, newLogs[newLogs.length - 1].id);
    }
    
    res.json({
        success: true,
        logs: newLogs,
        lastId: logId,
        newCount: newLogs.length
    });
});

/**
 * DELETE /api/logs/clear
 * Clears the log buffer
 */
router.delete('/clear', (req, res) => {
    logBuffer = [];
    clientLastLog.clear();
    
    // Notify all clients
    if (socketService && socketService.io) {
        socketService.io.emit('server:logs-cleared');
    }
    
    res.json({
        success: true,
        message: 'Log buffer cleared'
    });
});

/**
 * GET /api/logs/stats
 * Returns log statistics
 */
router.get('/stats', (req, res) => {
    const stats = {
        total: logBuffer.length,
        maxSize: MAX_LOGS,
        levels: {
            log: logBuffer.filter(l => l.level === 'log').length,
            info: logBuffer.filter(l => l.level === 'info').length,
            warn: logBuffer.filter(l => l.level === 'warn').length,
            error: logBuffer.filter(l => l.level === 'error').length
        },
        oldestTimestamp: logBuffer[0]?.timestamp,
        newestTimestamp: logBuffer[logBuffer.length - 1]?.timestamp,
        socketConnected: socketService?.io ? true : false
    };
    
    res.json({ success: true, stats });
});

// Export router and setSocketService function
module.exports = router;
module.exports.setSocketService = setSocketService;
