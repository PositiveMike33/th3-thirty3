/**
 * HackerGPT Training Routes
 * 
 * API endpoints for the HackerGPT Training System:
 * - /api/hackergpt/status - Get training system status
 * - /api/hackergpt/models - Get model configs and progress
 * - /api/hackergpt/curriculum - Get available courses
 * - /api/hackergpt/lesson - Generate a lesson
 * - /api/hackergpt/exam - Give an exam to a model
 * - /api/hackergpt/train - Run intensive training
 * 
 * @author Th3 Thirty3
 */

const express = require('express');
const router = express.Router();

// Will be injected from index.js
let hackergptService = null;

/**
 * Initialize with service instance
 */
router.init = (service) => {
    hackergptService = service;
};

/**
 * GET /api/hackergpt/status
 * Get training system status
 */
router.get('/status', (req, res) => {
    try {
        if (!hackergptService) {
            return res.status(500).json({ success: false, error: 'Service not initialized' });
        }
        
        const status = hackergptService.getTrainingStatus();
        res.json({
            success: true,
            ...status
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/hackergpt/models
 * Get model configurations and progress
 */
router.get('/models', (req, res) => {
    try {
        if (!hackergptService) {
            return res.status(500).json({ success: false, error: 'Service not initialized' });
        }
        
        const configs = hackergptService.getModelConfigs();
        const status = hackergptService.getTrainingStatus();
        
        res.json({
            success: true,
            configs,
            models: status.models
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/hackergpt/models/:modelName
 * Get specific model progress
 */
router.get('/models/:modelName', (req, res) => {
    try {
        if (!hackergptService) {
            return res.status(500).json({ success: false, error: 'Service not initialized' });
        }
        
        const modelName = decodeURIComponent(req.params.modelName);
        const progress = hackergptService.getModelProgress(modelName);
        const config = hackergptService.applyOptimizedConfig(modelName, 'default');
        
        res.json({
            success: true,
            progress,
            config
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/hackergpt/curriculum
 * Get available courses and tracks
 */
router.get('/curriculum', (req, res) => {
    try {
        if (!hackergptService) {
            return res.status(500).json({ success: false, error: 'Service not initialized' });
        }
        
        const curriculum = hackergptService.getCurriculum();
        res.json({
            success: true,
            curriculum
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hackergpt/lesson
 * Generate a lesson for a model
 */
router.post('/lesson', async (req, res) => {
    try {
        if (!hackergptService) {
            return res.status(500).json({ success: false, error: 'Service not initialized' });
        }
        
        const { modelName, courseId } = req.body;
        
        if (!modelName || !courseId) {
            return res.status(400).json({ 
                success: false, 
                error: 'modelName and courseId are required' 
            });
        }
        
        const lesson = await hackergptService.generateLesson(modelName, courseId);
        res.json({
            success: true,
            lesson
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hackergpt/exam
 * Give an exam to a model
 */
router.post('/exam', async (req, res) => {
    try {
        if (!hackergptService) {
            return res.status(500).json({ success: false, error: 'Service not initialized' });
        }
        
        const { modelName, courseId } = req.body;
        
        if (!modelName || !courseId) {
            return res.status(400).json({ 
                success: false, 
                error: 'modelName and courseId are required' 
            });
        }
        
        const examResult = await hackergptService.giveExam(modelName, courseId);
        res.json({
            success: true,
            result: examResult
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hackergpt/train
 * Run intensive training for a model
 */
router.post('/train', async (req, res) => {
    try {
        if (!hackergptService) {
            return res.status(500).json({ success: false, error: 'Service not initialized' });
        }
        
        const { modelName, track } = req.body;
        
        if (!modelName) {
            return res.status(400).json({ 
                success: false, 
                error: 'modelName is required' 
            });
        }
        
        // Start training in background and return immediately
        res.json({
            success: true,
            message: `Intensive training started for ${modelName} on ${track || 'pentesting'} track`,
            status: 'in_progress'
        });
        
        // Run training asynchronously
        hackergptService.runIntensiveTraining(modelName, track || 'pentesting')
            .then(results => {
                console.log(`[HACKERGPT] Training completed for ${modelName}`);
            })
            .catch(error => {
                console.error(`[HACKERGPT] Training failed:`, error.message);
            });
            
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/hackergpt/config/:modelName
 * Get optimized configuration for a specific model and task
 */
router.get('/config/:modelName', (req, res) => {
    try {
        if (!hackergptService) {
            return res.status(500).json({ success: false, error: 'Service not initialized' });
        }
        
        const modelName = decodeURIComponent(req.params.modelName);
        const taskType = req.query.task || 'default';
        
        const config = hackergptService.applyOptimizedConfig(modelName, taskType);
        res.json({
            success: true,
            config
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/hackergpt/history
 * Get exam history
 */
router.get('/history', (req, res) => {
    try {
        if (!hackergptService) {
            return res.status(500).json({ success: false, error: 'Service not initialized' });
        }
        
        const limit = parseInt(req.query.limit) || 20;
        const history = hackergptService.examHistory.slice(-limit);
        
        res.json({
            success: true,
            history,
            total: hackergptService.examHistory.length
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;
