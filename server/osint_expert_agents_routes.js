/**
 * Routes API pour les OSINT Expert Agents
 */

const express = require('express');
const router = express.Router();
const OsintExpertAgentsService = require('./osint_expert_agents_service');

const osintExperts = new OsintExpertAgentsService();

/**
 * GET /api/osint-experts
 * Liste tous les experts OSINT et leurs stats
 */
router.get('/', (req, res) => {
    res.json({
        success: true,
        experts: osintExperts.getExpertsStats(),
        totalExperts: Object.keys(osintExperts.agents).length
    });
});

/**
 * GET /api/osint-experts/categories
 * Liste les experts par catégorie
 */
router.get('/categories', (req, res) => {
    res.json({
        success: true,
        categories: osintExperts.getExpertsByCategory()
    });
});

/**
 * POST /api/osint-experts/recommend
 * Recommander l'expert approprié pour une tâche
 */
router.post('/recommend', (req, res) => {
    const { task } = req.body;
    
    if (!task) {
        return res.status(400).json({ success: false, error: 'task requis' });
    }

    const recommendation = osintExperts.recommendExpert(task);
    res.json({ success: true, ...recommendation });
});

/**
 * POST /api/osint-experts/consult
 * Consulter un expert spécifique
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
        const result = await osintExperts.consultExpert(expertId, question, context);
        res.json({ success: true, ...result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/osint-experts/train
 * Entraînement continu sur un sujet
 */
router.post('/train', async (req, res) => {
    const { expertId, topic, iterations } = req.body;
    
    if (!expertId || !topic) {
        return res.status(400).json({ 
            success: false, 
            error: 'expertId et topic requis' 
        });
    }

    try {
        const result = await osintExperts.continuousTraining(expertId, topic, iterations || 3);
        res.json({ success: true, ...result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/osint-experts/investigate
 * Investigation multi-experts
 */
router.post('/investigate', async (req, res) => {
    const { target, targetType } = req.body;
    
    if (!target) {
        return res.status(400).json({ 
            success: false, 
            error: 'target requis. targetType optionnel: domain, person, email, image, username, ip, crypto' 
        });
    }

    try {
        const result = await osintExperts.multiExpertInvestigation(target, targetType || 'domain');
        res.json({ success: true, ...result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/osint-experts/teach
 * Enseigner une technique à un expert
 */
router.post('/teach', (req, res) => {
    const { expertId, technique, successful } = req.body;
    
    if (!expertId || !technique) {
        return res.status(400).json({ 
            success: false, 
            error: 'expertId et technique requis' 
        });
    }

    const success = osintExperts.teachExpert(expertId, technique, successful !== false);
    res.json({ success, expertId });
});

/**
 * POST /api/osint-experts/record-investigation
 * Enregistrer une investigation
 */
router.post('/record-investigation', (req, res) => {
    const { expertId, investigation } = req.body;
    
    if (!expertId || !investigation) {
        return res.status(400).json({ 
            success: false, 
            error: 'expertId et investigation requis' 
        });
    }

    const success = osintExperts.recordInvestigation(expertId, investigation);
    res.json({ success, expertId });
});

/**
 * GET /api/osint-experts/:expertId
 * Obtenir les détails d'un expert
 */
router.get('/:expertId', (req, res) => {
    const { expertId } = req.params;
    const agent = osintExperts.agents[expertId];
    
    if (!agent) {
        return res.status(404).json({ 
            success: false, 
            error: 'Expert not found' 
        });
    }

    res.json({
        success: true,
        expert: {
            id: expertId,
            name: agent.name,
            emoji: agent.emoji,
            tool: agent.tool,
            category: agent.category,
            description: agent.description,
            commands: agent.commands,
            stats: {
                interactions: agent.knowledge.interactions,
                techniquesLearned: agent.knowledge.learned.length,
                successfulTechniques: agent.knowledge.successfulTechniques.length,
                investigations: agent.knowledge.investigations.length,
                topQueries: Object.entries(agent.knowledge.commonQueries)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 5)
            }
        }
    });
});

module.exports = router;
