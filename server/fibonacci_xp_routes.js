/**
 * FIBONACCI XP SYSTEM API ROUTES
 * 
 * Routes for managing model XP progression with Fibonacci growth
 */

const express = require('express');
const router = express.Router();
const { getFibonacciXPSystem } = require('./fibonacci_xp_system');

// Lazy load
let xpSystem = null;
function getXPSystem() {
    if (!xpSystem) {
        xpSystem = getFibonacciXPSystem();
    }
    return xpSystem;
}

/**
 * GET /api/xp/status
 * Get overall XP system status
 */
router.get('/status', (req, res) => {
    try {
        const status = getXPSystem().getSystemStatus();
        res.json({ success: true, ...status });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/xp/leaderboard
 * Get XP leaderboard
 */
router.get('/leaderboard', (req, res) => {
    try {
        const leaderboard = getXPSystem().getLeaderboard();
        res.json({ success: true, ...leaderboard });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/xp/model/:modelName
 * Get XP status for a specific model
 */
router.get('/model/:modelName', (req, res) => {
    try {
        const { modelName } = req.params;
        const status = getXPSystem().getModelStatus(decodeURIComponent(modelName));
        res.json({ success: true, ...status });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/xp/train
 * Add training XP for a model
 * Body: { modelName: string, tokensProcessed: number }
 */
router.post('/train', (req, res) => {
    try {
        const { modelName, tokensProcessed } = req.body;
        
        if (!modelName || !tokensProcessed) {
            return res.status(400).json({
                success: false,
                error: 'modelName and tokensProcessed are required'
            });
        }

        const result = getXPSystem().addTrainingXP(modelName, tokensProcessed);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/xp/decay/:modelName
 * Manually trigger decay check for a model
 */
router.post('/decay/:modelName', (req, res) => {
    try {
        const { modelName } = req.params;
        const result = getXPSystem().applyDecay(decodeURIComponent(modelName));
        
        if (result) {
            res.json({ success: true, decayApplied: true, ...result });
        } else {
            res.json({ success: true, decayApplied: false, message: 'No decay needed' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/xp/fibonacci
 * Get Fibonacci XP multiplier info
 */
router.get('/fibonacci', (req, res) => {
    try {
        const { FIBONACCI_XP, LEVEL_THRESHOLDS, DECAY_RATES } = require('./fibonacci_xp_system');
        res.json({
            success: true,
            fibonacciSequence: FIBONACCI_XP,
            levelThresholds: LEVEL_THRESHOLDS,
            decayRates: DECAY_RATES,
            cognitiveRest: {
                restDurationMinutes: 210,
                maxTrainingPerSession: 5,
                restBonusMultiplier: 1.5,
                fatiguedPenalty: 0.5
            },
            explanation: {
                xpGrowth: 'XP multiplier follows Fibonacci: 1,1,2,3,5,8,13,21...',
                levels: 'Level 2 at 1000 XP, exponential thresholds after',
                decay: 'Inactive models lose 10,9,8,7,6,5,4,3,2,1 XP per day',
                cognitiveRest: 'Models need 3h30 rest after 5 trainings to consolidate learning'
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/xp/rest/:modelName
 * Start cognitive rest for a model
 */
router.post('/rest/:modelName', (req, res) => {
    try {
        const { modelName } = req.params;
        const result = getXPSystem().startCognitiveRest(decodeURIComponent(modelName));
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/xp/rest/:modelName
 * Check cognitive rest status for a model
 */
router.get('/rest/:modelName', (req, res) => {
    try {
        const { modelName } = req.params;
        const model = getXPSystem().getOrCreateModelXP(decodeURIComponent(modelName));
        const restStatus = getXPSystem().checkCognitiveRest(model);
        res.json({ 
            success: true, 
            modelName: decodeURIComponent(modelName),
            ...restStatus,
            cognitiveRest: model.cognitiveRest
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;
