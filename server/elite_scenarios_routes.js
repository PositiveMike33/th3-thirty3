/**
 * Elite Hacker Scenarios Routes
 * 
 * API pour accéder aux 33 scénarios de hackers élite
 */

const express = require('express');
const router = express.Router();
const EliteHackerScenariosService = require('./elite_scenarios_service');
const orchestrator = require('./orchestrator_instance'); // Singleton
let liveMonitor = null; // Injected monitor instance
let scenariosService = null;

try {
    scenariosService = new EliteHackerScenariosService();
} catch (error) {
    console.error('[ELITE-SCENARIOS] Failed to initialize:', error.message);
}

// Method to inject Live Monitor
router.setLiveMonitor = (monitor) => {
    liveMonitor = monitor;
    console.log('[ELITE-SCENARIOS] Live Monitor connected');
};

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
 * POST /api/elite-scenarios/execute
 * Exécuter un scénario via l'Orchestrateur
 */
router.post('/execute', async (req, res) => {
    if (!scenariosService || !orchestrator) {
        return res.status(503).json({ error: 'Services not available' });
    }

    const { scenarioId, target } = req.body;

    if (!scenarioId) {
        return res.status(400).json({ error: 'scenarioId is required' });
    }

    try {
        const scenario = scenariosService.getScenarioById(scenarioId);
        if (!scenario) {
            return res.status(404).json({ error: 'Scenario not found' });
        }

        console.log(`[ELITE-SCENARIOS] executing scenario ${scenario.id}: ${scenario.title}`);

        // Construire la tâche pour l'orchestrateur
        const prompt = scenariosService.generateTrainingPrompt(scenario.id);
        const missionTask = `MISSION CRITIQUE: Exécution du Scénario #${scenario.id} - ${scenario.title}
        
CIBLE: ${target || 'SIMULATION_ENVIRONMENT'}
        
${prompt}
        
INSTRUCTION: Coordonne les équipes HexStrike, OSINT et Hacking pour exécuter ce scénario étape par étape.
Rapporte chaque succès et échec. Utilise les outils spécifiés.`;

        // Lancer la mission via l'orchestrateur
        const mission = await orchestrator.executeMission(missionTask, {
            priority: 'CRITICAL',
            source: 'elite_scenarios',
            scenarioId: scenario.id
        });

        // BROADCAST TO LIVE MONITOR
        // BROADCAST TO LIVE MONITOR
        if (liveMonitor) {
            console.log(`[ELITE-SCENARIOS] Broadcasting scenario ${scenario.id} to Live Monitor`);

            // Format special lesson for scenario activation (Educational Focus)
            const specialLesson = {
                expert: 'Elite Mission Control',
                emoji: '🎯',
                command: `START_MISSION_${scenario.id}: ${scenario.title}`,
                lesson: `## 🎯 OBJECTIFS & QUESTIONS CRITIQUES
${scenario.question}

## 🏆 RÉSULTATS ATTENDUS
${scenario.expected_result}

## 🛡️ PERSPECTIVE DÉFENSIVE
${scenario.defense_perspective}

## ⚡ ORDRE DE MISSION
L'équipe HexStrike a reçu vos ordres. Exécution des outils ${scenario.tools.slice(0, 3).join(', ')} en cours...`,
                timestamp: new Date().toISOString()
            };

            // Use forceLesson to ensure it stays visible (resets timer)
            if (liveMonitor.forceLesson) {
                liveMonitor.forceLesson(specialLesson);
            } else {
                liveMonitor.emit('monitor:lesson', specialLesson);
            }
        }

        res.json({
            success: true,
            msg: `Scenario ${scenario.id} initiated`,
            missionId: mission.id,
            mission
        });

    } catch (error) {
        console.error('[ELITE-SCENARIOS] Execution failed:', error);
        res.status(500).json({ error: error.message });
    }
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
