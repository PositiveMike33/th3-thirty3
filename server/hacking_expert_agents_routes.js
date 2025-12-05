/**
 * Routes API pour les Hacking Expert Agents
 */

const express = require('express');
const router = express.Router();
const HackingExpertAgentsService = require('./hacking_expert_agents_service');

const hackingExperts = new HackingExpertAgentsService();

/**
 * GET /api/hacking-experts
 * Liste tous les experts hacking et leurs stats
 */
router.get('/', (req, res) => {
    res.json({
        success: true,
        experts: hackingExperts.getExpertsStats(),
        totalExperts: Object.keys(hackingExperts.agents).length
    });
});

/**
 * GET /api/hacking-experts/categories
 * Liste les experts par catégorie
 */
router.get('/categories', (req, res) => {
    res.json({
        success: true,
        categories: hackingExperts.getExpertsByCategory()
    });
});

/**
 * POST /api/hacking-experts/consult
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
        const result = await hackingExperts.consultExpert(expertId, question, context);
        res.json({ success: true, ...result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hacking-experts/train
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
        const result = await hackingExperts.continuousTraining(expertId, topic, iterations || 3);
        res.json({ success: true, ...result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hacking-experts/teach
 * Enseigner une technique avec code optionnel
 */
router.post('/teach', (req, res) => {
    const { expertId, technique, code, successful } = req.body;
    
    if (!expertId || !technique) {
        return res.status(400).json({ 
            success: false, 
            error: 'expertId et technique requis' 
        });
    }

    const success = hackingExperts.teachTechnique(expertId, technique, code, successful !== false);
    res.json({ success, expertId });
});

/**
 * POST /api/hacking-experts/teach-defense
 * Enseigner une stratégie de défense
 */
router.post('/teach-defense', (req, res) => {
    const { expertId, defense } = req.body;
    
    if (!expertId || !defense) {
        return res.status(400).json({ 
            success: false, 
            error: 'expertId et defense requis' 
        });
    }

    const success = hackingExperts.teachDefense(expertId, defense);
    res.json({ success, expertId });
});

/**
 * POST /api/hacking-experts/attack-chain
 * Simuler une chaîne d'attaque multi-experts
 */
router.post('/attack-chain', async (req, res) => {
    const { target, phases } = req.body;
    
    if (!target) {
        return res.status(400).json({ 
            success: false, 
            error: 'target requis. phases optionnel: ["recon", "exploit", "persist", "privesc", "lateral"]' 
        });
    }

    try {
        const result = await hackingExperts.attackChain(target, phases);
        res.json({ success: true, ...result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/hacking-experts/:expertId
 * Obtenir les détails d'un expert
 */
router.get('/:expertId', (req, res) => {
    const { expertId } = req.params;
    const agent = hackingExperts.agents[expertId];
    
    if (!agent) {
        return res.status(404).json({ success: false, error: 'Expert not found' });
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
                techniques: agent.knowledge.techniques.length,
                codeSnippets: agent.knowledge.codeSnippets.length,
                exploits: agent.knowledge.successfulExploits.length,
                defenses: agent.knowledge.defenseStrategies.length,
                trainingHistory: agent.knowledge.trainingHistory.slice(-10)
            }
        }
    });
});

module.exports = router;
