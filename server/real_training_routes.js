/**
 * Routes API pour l'entraînement réel des modèles
 * Permet de lancer des sessions d'entraînement intensif
 */

const express = require('express');
const router = express.Router();

let realTrainingService = null;

// Setter for dependency injection
router.setRealTrainingService = (service) => {
    realTrainingService = service;
};

/**
 * GET /training/status
 * Get overall training status
 */
router.get('/status', (req, res) => {
    if (!realTrainingService) {
        return res.status(503).json({ error: 'Training service not initialized' });
    }
    
    res.json({
        success: true,
        activeTrainings: realTrainingService.getAllTrainingStatus()
    });
});

/**
 * GET /training/status/:modelName
 * Get training status for a specific model
 */
router.get('/status/:modelName', (req, res) => {
    if (!realTrainingService) {
        return res.status(503).json({ error: 'Training service not initialized' });
    }
    
    const status = realTrainingService.getTrainingStatus(req.params.modelName);
    res.json({
        success: true,
        modelName: req.params.modelName,
        status
    });
});

/**
 * POST /training/start
 * Start a training session for a model
 * Body: { modelName, category?, iterations? }
 */
router.post('/start', async (req, res) => {
    if (!realTrainingService) {
        return res.status(503).json({ error: 'Training service not initialized' });
    }
    
    const { modelName, category = 'all', iterations = 5 } = req.body;
    
    if (!modelName) {
        return res.status(400).json({ error: 'modelName is required' });
    }
    
    // Start training in background
    realTrainingService.startTrainingSession(modelName, category, iterations)
        .then(result => {
            console.log(`[TRAINING_ROUTES] Training completed for ${modelName}:`, result.success);
        })
        .catch(err => {
            console.error(`[TRAINING_ROUTES] Training error for ${modelName}:`, err.message);
        });
    
    // Return immediately
    res.json({
        success: true,
        message: `Training started for ${modelName}`,
        modelName,
        category,
        iterations
    });
});

/**
 * POST /training/start-all
 * Start training for all local models
 * Body: { iterations? }
 */
router.post('/start-all', async (req, res) => {
    if (!realTrainingService) {
        return res.status(503).json({ error: 'Training service not initialized' });
    }
    
    const { iterations = 3 } = req.body;
    
    // Start training all in background
    realTrainingService.trainAllLocalModels(iterations)
        .then(result => {
            console.log('[TRAINING_ROUTES] All models training completed:', result.success);
        })
        .catch(err => {
            console.error('[TRAINING_ROUTES] All models training error:', err.message);
        });
    
    res.json({
        success: true,
        message: 'Training started for all local models',
        iterations
    });
});

/**
 * POST /training/stop/:modelName
 * Stop training for a specific model
 */
router.post('/stop/:modelName', (req, res) => {
    if (!realTrainingService) {
        return res.status(503).json({ error: 'Training service not initialized' });
    }
    
    const result = realTrainingService.stopTraining(req.params.modelName);
    res.json(result);
});

/**
 * GET /training/scenarios
 * Get available training scenarios
 */
router.get('/scenarios', (req, res) => {
    if (!realTrainingService) {
        return res.status(503).json({ error: 'Training service not initialized' });
    }
    
    res.json({
        success: true,
        categories: Object.keys(realTrainingService.trainingScenarios),
        counts: Object.fromEntries(
            Object.entries(realTrainingService.trainingScenarios)
                .map(([k, v]) => [k, v.length])
        )
    });
});

let commentaryService = null;

// Setter for commentary service injection
router.setCommentaryService = (service) => {
    commentaryService = service;
};

/**
 * POST /training/commentary
 * Generate self-reflection commentary for a model with data suggestions
 * Body: { model? } - if not specified, generates for all models
 */
router.post('/commentary', async (req, res) => {
    if (!commentaryService) {
        return res.status(503).json({ error: 'Commentary service not initialized' });
    }
    
    try {
        const { model } = req.body;
        let result;
        
        if (model) {
            // Generate for specific model
            const metrics = commentaryService.loadMetrics();
            result = await commentaryService.generateSelfCommentary(model, metrics);
        } else {
            // Generate for all models
            result = await commentaryService.triggerAutoCommentary();
        }
        
        if (result) {
            res.json({ success: true, commentary: result });
        } else {
            res.status(500).json({ success: false, error: 'Failed to generate commentary' });
        }
    } catch (error) {
        console.error('[TRAINING_ROUTES] Commentary error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /training/commentary
 * Get recent commentaries
 * Query: { limit?, model? }
 */
router.get('/commentary', (req, res) => {
    if (!commentaryService) {
        return res.status(503).json({ error: 'Commentary service not initialized' });
    }
    
    const limit = parseInt(req.query.limit) || 10;
    const model = req.query.model;
    
    let commentaries;
    if (model) {
        commentaries = commentaryService.getModelCommentaries(model, limit);
    } else {
        commentaries = commentaryService.getRecentCommentaries(limit);
    }
    
    res.json({
        success: true,
        count: commentaries.length,
        commentaries
    });
});

/**
 * GET /training/commentary/status
 * Get commentary service status
 */
router.get('/commentary/status', (req, res) => {
    if (!commentaryService) {
        return res.status(503).json({ error: 'Commentary service not initialized' });
    }
    
    res.json({
        success: true,
        status: commentaryService.getStatus()
    });
});

module.exports = router;

