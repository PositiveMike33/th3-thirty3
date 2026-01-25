/**
 * HexStrike Expert Agents Routes
 * 
 * API routes pour les agents experts HexStrike
 */

const express = require('express');
const router = express.Router();
const HexStrikeExpertAgentsService = require('./hexstrike_expert_agents_service');

// Instance du service
let expertService = null;

try {
    expertService = new HexStrikeExpertAgentsService();
} catch (error) {
    console.error('[HEXSTRIKE-EXPERTS] Failed to initialize:', error.message);
}

// ============================================================================
// EXPERT LISTING
// ============================================================================

/**
 * GET /api/hexstrike-experts/list
 * Liste tous les experts disponibles
 */
router.get('/list', (req, res) => {
    if (!expertService) {
        return res.status(503).json({ error: 'Expert service not available' });
    }

    const summary = expertService.getExpertsSummary();
    res.json(summary);
});

/**
 * GET /api/hexstrike-experts/categories
 * Liste les experts par catégorie
 */
router.get('/categories', (req, res) => {
    if (!expertService) {
        return res.status(503).json({ error: 'Expert service not available' });
    }

    const { category } = req.query;
    const experts = expertService.getExpertsByCategory(category || null);
    res.json(experts);
});

/**
 * GET /api/hexstrike-experts/:toolId
 * Obtenir les détails d'un expert spécifique
 */
router.get('/:toolId', (req, res) => {
    if (!expertService) {
        return res.status(503).json({ error: 'Expert service not available' });
    }

    const { toolId } = req.params;
    const agent = expertService.agents.get(toolId);

    if (!agent) {
        return res.status(404).json({
            error: `Expert '${toolId}' not found`,
            availableExperts: Array.from(expertService.agents.keys())
        });
    }

    res.json({
        id: toolId,
        ...agent
    });
});

// ============================================================================
// EXPERT CONSULTATION
// ============================================================================

/**
 * POST /api/hexstrike-experts/consult
 * Consulter un expert pour obtenir des conseils
 */
router.post('/consult', async (req, res) => {
    if (!expertService) {
        return res.status(503).json({ error: 'Expert service not available' });
    }

    try {
        const { toolId, question, context } = req.body;

        if (!toolId || !question) {
            return res.status(400).json({ error: 'toolId and question are required' });
        }

        console.log(`[HEXSTRIKE-EXPERTS] Consulting ${toolId}: ${question.substring(0, 50)}...`);

        const result = await expertService.consultExpert(toolId, question, context || {});
        res.json(result);

    } catch (error) {
        console.error('[HEXSTRIKE-EXPERTS] Consult error:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/hexstrike-experts/auto-select
 * Sélection automatique du meilleur expert pour une tâche
 */
router.post('/auto-select', (req, res) => {
    if (!expertService) {
        return res.status(503).json({ error: 'Expert service not available' });
    }

    try {
        const { taskDescription } = req.body;

        if (!taskDescription) {
            return res.status(400).json({ error: 'taskDescription is required' });
        }

        const selectedExperts = expertService.selectExpertForTask(taskDescription);

        const expertsDetails = selectedExperts.map(id => {
            const agent = expertService.agents.get(id);
            return {
                id,
                name: agent?.name,
                emoji: agent?.emoji,
                category: agent?.category,
                tool: agent?.tool
            };
        }).filter(e => e.name);

        res.json({
            success: true,
            taskDescription,
            recommendedExperts: expertsDetails
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/hexstrike-experts/execute
 * Exécuter une commande avec l'expert approprié
 */
router.post('/execute', async (req, res) => {
    if (!expertService) {
        return res.status(503).json({ error: 'Expert service not available' });
    }

    try {
        const { toolId, params } = req.body;

        if (!toolId) {
            return res.status(400).json({ error: 'toolId is required' });
        }

        console.log(`[HEXSTRIKE-EXPERTS] Executing ${toolId} with params:`, params);

        const result = await expertService.executeWithExpert(toolId, params || {});
        res.json(result);

    } catch (error) {
        console.error('[HEXSTRIKE-EXPERTS] Execute error:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/hexstrike-experts/chain
 * Chaîne d'exécution avec plusieurs experts
 */
router.post('/chain', async (req, res) => {
    if (!expertService) {
        return res.status(503).json({ error: 'Expert service not available' });
    }

    try {
        const { experts, target, context } = req.body;

        if (!experts || !Array.isArray(experts) || experts.length === 0) {
            return res.status(400).json({ error: 'experts array is required' });
        }

        console.log(`[HEXSTRIKE-EXPERTS] Chain execution: ${experts.join(' → ')}`);

        const results = [];
        let currentContext = context || {};

        for (const toolId of experts) {
            const result = await expertService.consultExpert(
                toolId,
                `Analyse la cible ${target} et fournis des recommandations`,
                currentContext
            );

            results.push({
                expert: toolId,
                result
            });

            // Context enrichi pour le prochain expert
            if (result.success) {
                currentContext = {
                    ...currentContext,
                    previousExpert: toolId,
                    previousResult: result.response?.substring(0, 500)
                };
            }
        }

        res.json({
            success: true,
            chainLength: experts.length,
            target,
            results
        });

    } catch (error) {
        console.error('[HEXSTRIKE-EXPERTS] Chain error:', error);
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
