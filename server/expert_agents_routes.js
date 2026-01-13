/**
 * Routes API pour les Expert Agents
 */

const express = require('express');
const router = express.Router();
const ExpertAgentsService = require('./expert_agents_service');

const experts = new ExpertAgentsService();

/**
 * GET /api/experts
 * Liste tous les experts et leurs stats
 */
router.get('/', (req, res) => {
    res.json({
        success: true,
        experts: experts.getExpertsStats()
    });
});

/**
 * GET /api/experts/models
 * Modèles recommandés à télécharger
 */
router.get('/models', (req, res) => {
    res.json({
        success: true,
        recommended: experts.getRecommendedModels()
    });
});

/**
 * POST /api/experts/consult
 * Consulter un expert
 */
router.post('/consult', async (req, res) => {
    const { expertId, question, context } = req.body;
    
    if (!expertId || !question) {
        return res.status(400).json({ 
            success: false, 
            error: 'expertId et question requis' 
        });
    }

    try {
        const result = await experts.consultExpert(expertId, question, context);
        res.json({ success: true, ...result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/experts/consult-multiple
 * Consulter plusieurs experts
 */
router.post('/consult-multiple', async (req, res) => {
    const { expertIds, question } = req.body;
    
    if (!expertIds || !question) {
        return res.status(400).json({ 
            success: false, 
            error: 'expertIds (array) et question requis' 
        });
    }

    try {
        const result = await experts.consultMultipleExperts(expertIds, question);
        res.json({ success: true, ...result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/experts/teach
 * Enseigner quelque chose à un expert
 */
router.post('/teach', (req, res) => {
    const { expertId, knowledge } = req.body;
    
    if (!expertId || !knowledge) {
        return res.status(400).json({ 
            success: false, 
            error: 'expertId et knowledge requis' 
        });
    }

    const success = experts.teachExpert(expertId, knowledge);
    res.json({ success, expertId });
});

/**
 * POST /api/experts/collaborate
 * Faire collaborer deux experts
 */
router.post('/collaborate', async (req, res) => {
    const { fromExpert, toExpert, topic } = req.body;
    
    if (!fromExpert || !toExpert || !topic) {
        return res.status(400).json({ 
            success: false, 
            error: 'fromExpert, toExpert et topic requis' 
        });
    }

    try {
        const result = await experts.expertCollaboration(fromExpert, toExpert, topic);
        res.json({ success: true, ...result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;
