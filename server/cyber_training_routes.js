/**
 * Routes API pour le Cyber Training
 */

const express = require('express');
const router = express.Router();
const CyberTrainingService = require('./cyber_training_service');

const cyberTraining = new CyberTrainingService();

/**
 * POST /api/cyber-training/train
 * Entraîner l'agent sur un module
 */
router.post('/train', async (req, res) => {
    const { module, commands } = req.body;
    
    if (!module || !commands) {
        return res.status(400).json({ 
            success: false, 
            error: 'module et commands requis' 
        });
    }

    const result = await cyberTraining.trainOnModule(module, commands);
    res.json(result);
});

/**
 * POST /api/cyber-training/explain
 * Expliquer une commande
 */
router.post('/explain', async (req, res) => {
    const { command } = req.body;
    
    if (!command) {
        return res.status(400).json({ 
            success: false, 
            error: 'command requis' 
        });
    }

    const result = await cyberTraining.explainCommand(command);
    res.json(result);
});

/**
 * POST /api/cyber-training/scenario
 * Générer un scénario d'attaque
 */
router.post('/scenario', async (req, res) => {
    const { targetType } = req.body;
    const result = await cyberTraining.generateAttackScenario(targetType || 'web_server');
    res.json(result);
});

/**
 * POST /api/cyber-training/quiz
 * Quiz sur un sujet
 */
router.post('/quiz', async (req, res) => {
    const { topic } = req.body;
    
    if (!topic) {
        return res.status(400).json({ 
            success: false, 
            error: 'topic requis' 
        });
    }

    const result = await cyberTraining.quizAgent(topic);
    res.json(result);
});

module.exports = router;
