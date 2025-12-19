/**
 * WiFi Security Training Routes
 * API endpoints for WiFi security model training
 */

const express = require('express');
const router = express.Router();

let wifiTrainingService = null;

// Initialize with dependencies
function initializeRoutes(llmService, modelMetricsService) {
    const WifiSecurityTrainingService = require('./wifi_security_training_service');
    wifiTrainingService = new WifiSecurityTrainingService(llmService, modelMetricsService);
    return router;
}

/**
 * GET /api/wifi-training/stats
 * Get training statistics
 */
router.get('/stats', (req, res) => {
    try {
        if (!wifiTrainingService) {
            return res.status(503).json({ error: 'WiFi Training Service not initialized' });
        }
        
        const stats = wifiTrainingService.getStats();
        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/wifi-training/random-scenario
 * Get a random training scenario
 */
router.get('/random-scenario', (req, res) => {
    try {
        if (!wifiTrainingService) {
            return res.status(503).json({ error: 'WiFi Training Service not initialized' });
        }
        
        const type = req.query.type || 'attack';
        let scenario;
        
        switch (type) {
            case 'attack':
                scenario = wifiTrainingService.getRandomAttackScenario();
                break;
            case 'quiz':
                scenario = wifiTrainingService.getRandomQuiz();
                break;
            case 'challenge':
                scenario = wifiTrainingService.getRandomChallenge();
                break;
            case 'prompt':
                scenario = wifiTrainingService.getRandomPrompt();
                break;
            default:
                scenario = wifiTrainingService.getRandomAttackScenario();
        }
        
        if (!scenario) {
            return res.status(404).json({ error: 'No scenarios available for type: ' + type });
        }
        
        res.json({ type, scenario });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/wifi-training/train
 * Run a single training iteration
 */
router.post('/train', async (req, res) => {
    try {
        if (!wifiTrainingService) {
            return res.status(503).json({ error: 'WiFi Training Service not initialized' });
        }
        
        const { model, type } = req.body;
        
        if (!model) {
            return res.status(400).json({ error: 'Model name required' });
        }
        
        const result = await wifiTrainingService.runTrainingIteration(model, type || 'random');
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/wifi-training/session
 * Run a full training session
 */
router.post('/session', async (req, res) => {
    try {
        if (!wifiTrainingService) {
            return res.status(503).json({ error: 'WiFi Training Service not initialized' });
        }
        
        const { model, iterations } = req.body;
        
        if (!model) {
            return res.status(400).json({ error: 'Model name required' });
        }
        
        const result = await wifiTrainingService.runTrainingSession(
            model, 
            iterations || 5
        );
        
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/wifi-training/quiz
 * Get a random quiz question
 */
router.get('/quiz', (req, res) => {
    try {
        if (!wifiTrainingService) {
            return res.status(503).json({ error: 'WiFi Training Service not initialized' });
        }
        
        const quiz = wifiTrainingService.getRandomQuiz();
        
        if (!quiz) {
            return res.status(404).json({ error: 'No quiz questions available' });
        }
        
        // Don't reveal correct answer initially
        res.json({
            id: quiz.id,
            question: quiz.question,
            options: quiz.options
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/wifi-training/quiz/answer
 * Submit and check quiz answer
 */
router.post('/quiz/answer', (req, res) => {
    try {
        if (!wifiTrainingService) {
            return res.status(503).json({ error: 'WiFi Training Service not initialized' });
        }
        
        const { quizId, answer } = req.body;
        
        // Find the quiz
        const stats = wifiTrainingService.getStats();
        const scenarios = wifiTrainingService.scenarios;
        const quiz = scenarios.quiz_scenarios?.find(q => q.id === quizId);
        
        if (!quiz) {
            return res.status(404).json({ error: 'Quiz not found' });
        }
        
        const isCorrect = answer.toUpperCase() === quiz.correct_answer.toUpperCase();
        
        res.json({
            correct: isCorrect,
            correctAnswer: quiz.correct_answer,
            explanation: quiz.explanation,
            yourAnswer: answer
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/wifi-training/challenge
 * Get a random practical challenge
 */
router.get('/challenge', (req, res) => {
    try {
        if (!wifiTrainingService) {
            return res.status(503).json({ error: 'WiFi Training Service not initialized' });
        }
        
        const challenge = wifiTrainingService.getRandomChallenge();
        
        if (!challenge) {
            return res.status(404).json({ error: 'No challenges available' });
        }
        
        res.json(challenge);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/wifi-training/memory/:model
 * Get Golden Ratio memory status for a specific model
 * Shows: memory type, retention rate, next review time, repetitions
 */
router.get('/memory/:model', (req, res) => {
    try {
        if (!wifiTrainingService) {
            return res.status(503).json({ error: 'WiFi Training Service not initialized' });
        }
        
        const modelName = req.params.model;
        const memoryStatus = wifiTrainingService.getModelMemoryStatus(modelName);
        
        if (!memoryStatus) {
            return res.status(404).json({ 
                error: 'No memory data for this model',
                hint: 'Run at least one training session first'
            });
        }
        
        res.json({
            model: modelName,
            goldenRatio: 1.618,
            memory: memoryStatus
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/wifi-training/memory
 * Get Golden Ratio memory status for all trained models
 */
router.get('/memory', (req, res) => {
    try {
        if (!wifiTrainingService) {
            return res.status(503).json({ error: 'WiFi Training Service not initialized' });
        }
        
        const allMemory = {};
        const modelMemory = wifiTrainingService.modelMemory || {};
        
        for (const [modelName, memory] of Object.entries(modelMemory)) {
            allMemory[modelName] = wifiTrainingService.getModelMemoryStatus(modelName);
        }
        
        res.json({
            goldenRatio: 1.618,
            inverseGoldenRatio: 0.618,
            totalModels: Object.keys(allMemory).length,
            models: allMemory
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/wifi-training/optimization/:model
 * Get resource optimization metrics for a model
 * Shows: VRAM savings, efficiency tier, power output
 */
router.get('/optimization/:model', (req, res) => {
    try {
        if (!wifiTrainingService) {
            return res.status(503).json({ error: 'WiFi Training Service not initialized' });
        }
        
        const modelName = req.params.model;
        const memory = wifiTrainingService.modelMemory[modelName];
        
        if (!memory) {
            return res.status(404).json({ 
                error: 'No data for this model',
                hint: 'Run training sessions first'
            });
        }
        
        const optimization = wifiTrainingService.memorySystem.calculateTotalOptimization(
            memory.repetitions,
            { vram: 4.0, batchSize: 1, tokens: 500 }
        );
        
        res.json({
            model: modelName,
            optimization,
            philosophy: 'φ⁻¹ decay: More experience → Less resources → Ultra power'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/wifi-training/elite/:model
 * Get elite cybernetic status for a model
 */
router.get('/elite/:model', (req, res) => {
    try {
        if (!wifiTrainingService) {
            return res.status(503).json({ error: 'WiFi Training Service not initialized' });
        }
        
        const modelName = req.params.model;
        const memory = wifiTrainingService.modelMemory[modelName];
        
        if (!memory) {
            return res.status(404).json({ error: 'No data for this model' });
        }
        
        // Get exponential growth metrics
        const successCount = memory.history.filter(h => (h.score || h.resultScore || 0) >= 70).length;
        const growth = wifiTrainingService.memorySystem.calculateExponentialGrowth(
            memory.repetitions,
            successCount
        );
        
        // Get cybernetic enhancement
        const cyber = wifiTrainingService.memorySystem.calculateCyberneticEnhancement({
            expertiseScore: memory.score,
            repetitions: memory.repetitions,
            successRate: successCount / Math.max(1, memory.repetitions),
            domains: ['wifi_security']
        });
        
        // Get elite knowledge consolidation
        const elite = wifiTrainingService.memorySystem.consolidateEliteKnowledge(memory.history);
        
        res.json({
            model: modelName,
            eliteStatus: {
                level: growth.eliteLevel,
                cyberneticPower: cyber.cyberneticPower,
                enhancementLevel: cyber.enhancementLevel,
                progressToNext: growth.progressToNextLevel
            },
            growth,
            cybernetic: cyber,
            eliteKnowledge: elite,
            goldenRatio: {
                phi: 1.618,
                inversePhi: 0.618,
                eliteRetention: '61.8% of top experiences'
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = { router, initializeRoutes };
