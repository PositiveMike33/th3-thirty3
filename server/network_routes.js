/**
 * Network Failover Routes - RISK-006 Mitigation API
 * Provides endpoints for network status monitoring and failover control
 */

const express = require('express');
const router = express.Router();

// Import the network failover service
let networkFailoverService = null;
let NetworkState = null;
let FailoverMode = null;

try {
    const nfs = require('./network_failover_service');
    networkFailoverService = nfs.networkFailoverService;
    NetworkState = nfs.NetworkState;
    FailoverMode = nfs.FailoverMode;
    
    // Start monitoring automatically
    networkFailoverService.start();
    console.log('[NETWORK_ROUTES] Network Failover Service started');
} catch (e) {
    console.error('[NETWORK_ROUTES] Failed to load Network Failover Service:', e.message);
}

/**
 * GET /api/network/status
 * Returns current network status and failover state
 */
router.get('/status', (req, res) => {
    if (!networkFailoverService) {
        return res.status(503).json({
            error: 'Network Failover Service not available',
            state: 'UNKNOWN',
            isOnline: navigator?.onLine ?? true,
            isOllamaAvailable: false
        });
    }
    
    try {
        const status = networkFailoverService.getStatus();
        res.json(status);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/network/mode
 * Set the failover mode (AUTO, LOCAL_ONLY, CLOUD_ONLY, MANUAL)
 */
router.post('/mode', (req, res) => {
    if (!networkFailoverService) {
        return res.status(503).json({ error: 'Service not available' });
    }
    
    const { mode } = req.body;
    
    if (!mode || !FailoverMode[mode]) {
        return res.status(400).json({ 
            error: 'Invalid mode',
            validModes: Object.keys(FailoverMode)
        });
    }
    
    try {
        networkFailoverService.setMode(mode);
        res.json({ 
            success: true, 
            mode,
            status: networkFailoverService.getStatus()
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/network/force-failover
 * Force a failover to local models (for testing)
 */
router.post('/force-failover', (req, res) => {
    if (!networkFailoverService) {
        return res.status(503).json({ error: 'Service not available' });
    }
    
    try {
        networkFailoverService.forceState(NetworkState.OFFLINE);
        res.json({ 
            success: true, 
            message: 'Failover forced to OFFLINE state',
            status: networkFailoverService.getStatus()
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/network/force-recovery
 * Force a recovery to cloud models (for testing)
 */
router.post('/force-recovery', (req, res) => {
    if (!networkFailoverService) {
        return res.status(503).json({ error: 'Service not available' });
    }
    
    try {
        networkFailoverService.forceState(NetworkState.ONLINE);
        res.json({ 
            success: true, 
            message: 'Recovery forced to ONLINE state',
            status: networkFailoverService.getStatus()
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/network/check
 * Trigger an immediate connectivity check
 */
router.post('/check', async (req, res) => {
    if (!networkFailoverService) {
        return res.status(503).json({ error: 'Service not available' });
    }
    
    try {
        await networkFailoverService.performConnectivityCheck();
        res.json({ 
            success: true, 
            status: networkFailoverService.getStatus()
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/network/recommended-model
 * Get the recommended model based on current network state
 */
router.get('/recommended-model', (req, res) => {
    if (!networkFailoverService) {
        return res.status(503).json({ error: 'Service not available' });
    }
    
    const { domain = 'general' } = req.query;
    
    try {
        const recommendation = networkFailoverService.getRecommendedModel(domain);
        res.json(recommendation);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/network/stats
 * Get network monitoring statistics
 */
router.get('/stats', (req, res) => {
    if (!networkFailoverService) {
        return res.status(503).json({ error: 'Service not available' });
    }
    
    try {
        const status = networkFailoverService.getStatus();
        res.json({
            stats: status.stats,
            endpoints: status.endpoints,
            lastCheck: status.lastCheck,
            lastOnline: status.lastOnline,
            lastOffline: status.lastOffline
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/network/start
 * Start network monitoring
 */
router.post('/start', (req, res) => {
    if (!networkFailoverService) {
        return res.status(503).json({ error: 'Service not available' });
    }
    
    try {
        networkFailoverService.start();
        res.json({ success: true, message: 'Network monitoring started' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/network/stop
 * Stop network monitoring
 */
router.post('/stop', (req, res) => {
    if (!networkFailoverService) {
        return res.status(503).json({ error: 'Service not available' });
    }
    
    try {
        networkFailoverService.stop();
        res.json({ success: true, message: 'Network monitoring stopped' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
