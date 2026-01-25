/**
 * Elite Hacker Scenarios Routes
 * 
 * API pour accéder aux 33 scénarios de hackers élite
 */

const express = require('express');
const router = express.Router();
const EliteHackerScenariosService = require('./elite_scenarios_service');

let scenariosService = null;

try {
    scenariosService = new EliteHackerScenariosService();
} catch (error) {
    console.error('[ELITE-SCENARIOS] Failed to initialize:', error.message);
}

/**
 * GET /api/elite-scenarios
 * Liste tous les scénarios
 */
router.get('/', (req, res) => {
    if (!scenariosService) {
        return res.status(503).json({ error: 'Service not available' });
    }

    const scenarios = scenariosService.getAllScenarios();
    res.json({
        success: true,
        count: scenarios.length,
        scenarios: scenarios.map(s => ({
            id: s.id,
            title: s.title,
            category: s.category,
            difficulty: s.difficulty,
            tools: s.tools
        }))
    });
});

/**
 * GET /api/elite-scenarios/stats
 * Statistiques des scénarios
 */
router.get('/stats', (req, res) => {
    if (!scenariosService) {
        return res.status(503).json({ error: 'Service not available' });
    }

    res.json(scenariosService.getStats());
});

/**
 * GET /api/elite-scenarios/categories
 * Liste des catégories
 */
router.get('/categories', (req, res) => {
    if (!scenariosService) {
        return res.status(503).json({ error: 'Service not available' });
    }

    res.json({
        success: true,
        categories: scenariosService.getCategories()
    });
});

/**
 * GET /api/elite-scenarios/random
 * Scénario aléatoire (optionnellement filtré par difficulté)
 */
router.get('/random', (req, res) => {
    if (!scenariosService) {
        return res.status(503).json({ error: 'Service not available' });
    }

    const { difficulty } = req.query;
    let scenario;

    if (difficulty) {
        scenario = scenariosService.getRandomByDifficulty(difficulty);
    } else {
        const all = scenariosService.getAllScenarios();
        scenario = all[Math.floor(Math.random() * all.length)];
    }

    if (!scenario) {
        return res.status(404).json({ error: 'No scenario found' });
    }

    res.json({ success: true, scenario });
});

/**
 * GET /api/elite-scenarios/search
 * Recherche de scénarios
 */
router.get('/search', (req, res) => {
    if (!scenariosService) {
        return res.status(503).json({ error: 'Service not available' });
    }

    const { q } = req.query;
    if (!q) {
        return res.status(400).json({ error: 'Query parameter q is required' });
    }

    const results = scenariosService.searchScenarios(q);
    res.json({
        success: true,
        query: q,
        count: results.length,
        scenarios: results
    });
});

/**
 * GET /api/elite-scenarios/by-tool/:toolId
 * Scénarios utilisant un outil spécifique
 */
router.get('/by-tool/:toolId', (req, res) => {
    if (!scenariosService) {
        return res.status(503).json({ error: 'Service not available' });
    }

    const { toolId } = req.params;
    const scenarios = scenariosService.getByTool(toolId);

    res.json({
        success: true,
        tool: toolId,
        count: scenarios.length,
        scenarios
    });
});

/**
 * GET /api/elite-scenarios/by-category/:category
 * Scénarios par catégorie
 */
router.get('/by-category/:category', (req, res) => {
    if (!scenariosService) {
        return res.status(503).json({ error: 'Service not available' });
    }

    const { category } = req.params;
    const scenarios = scenariosService.getByCategory(category);

    res.json({
        success: true,
        category,
        count: scenarios.length,
        scenarios
    });
});

/**
 * GET /api/elite-scenarios/:id
 * Détails d'un scénario
 */
router.get('/:id', (req, res) => {
    if (!scenariosService) {
        return res.status(503).json({ error: 'Service not available' });
    }

    const scenario = scenariosService.getScenarioById(req.params.id);
    if (!scenario) {
        return res.status(404).json({ error: 'Scenario not found' });
    }

    res.json({ success: true, scenario });
});

/**
 * GET /api/elite-scenarios/:id/training-prompt
 * Générer un prompt d'entraînement complet
 */
router.get('/:id/training-prompt', (req, res) => {
    if (!scenariosService) {
        return res.status(503).json({ error: 'Service not available' });
    }

    const prompt = scenariosService.generateTrainingPrompt(req.params.id);
    if (!prompt) {
        return res.status(404).json({ error: 'Scenario not found' });
    }

    res.json({ success: true, prompt });
});

/**
 * POST /api/elite-scenarios/recommend
 * Recommander des scénarios basés sur un contexte
 */
router.post('/recommend', (req, res) => {
    if (!scenariosService) {
        return res.status(503).json({ error: 'Service not available' });
    }

    const { context } = req.body;
    if (!context) {
        return res.status(400).json({ error: 'Context is required' });
    }

    const recommended = scenariosService.getRecommendedScenarios(context);
    res.json({
        success: true,
        context,
        count: recommended.length,
        scenarios: recommended
    });
});

module.exports = router;
