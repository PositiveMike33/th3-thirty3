/**
 * Routes API pour l'optimisation cloud-to-local
 * Permet de contrôler l'optimisation automatique des modèles locaux
 */

const express = require('express');
const router = express.Router();

let cloudOptimizer = null;

// Setter for dependency injection
router.setCloudOptimizer = (service) => {
    cloudOptimizer = service;
};

/**
 * GET /optimizer/status
 * Get optimizer status and stats
 */
router.get('/status', (req, res) => {
    if (!cloudOptimizer) {
        return res.status(503).json({ error: 'Cloud optimizer not initialized' });
    }
    
    res.json({
        success: true,
        ...cloudOptimizer.getStatus()
    });
});

/**
 * POST /optimizer/start
 * Start automatic optimization
 * Body: { intervalMinutes? }
 */
router.post('/start', (req, res) => {
    if (!cloudOptimizer) {
        return res.status(503).json({ error: 'Cloud optimizer not initialized' });
    }
    
    const { intervalMinutes = 30 } = req.body;
    cloudOptimizer.startAutoOptimization(intervalMinutes);
    
    res.json({
        success: true,
        message: `Auto-optimization started (every ${intervalMinutes} minutes)`
    });
});

/**
 * POST /optimizer/stop
 * Stop automatic optimization
 */
router.post('/stop', (req, res) => {
    if (!cloudOptimizer) {
        return res.status(503).json({ error: 'Cloud optimizer not initialized' });
    }
    
    cloudOptimizer.stopAutoOptimization();
    
    res.json({
        success: true,
        message: 'Auto-optimization stopped'
    });
});

/**
 * POST /optimizer/run-cycle
 * Run a single optimization cycle manually
 */
router.post('/run-cycle', async (req, res) => {
    if (!cloudOptimizer) {
        return res.status(503).json({ error: 'Cloud optimizer not initialized' });
    }
    
    try {
        const result = await cloudOptimizer.runOptimizationCycle();
        res.json({
            success: true,
            result
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /optimizer/domains
 * Get available training domains
 */
router.get('/domains', (req, res) => {
    if (!cloudOptimizer) {
        return res.status(503).json({ error: 'Cloud optimizer not initialized' });
    }
    
    const status = cloudOptimizer.getStatus();
    res.json({
        success: true,
        domains: status.trainingDomains
    });
});

module.exports = router;
