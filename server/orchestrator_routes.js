/**
 * Routes API pour l'Orchestrator - Chef d'Équipe des 33 Agents
 */

const express = require('express');
const router = express.Router();
const OrchestratorService = require('./orchestrator_service');

const orchestrator = new OrchestratorService();

/**
 * GET /api/orchestrator/status
 * État de l'orchestrateur et toutes les équipes
 */
router.get('/status', (req, res) => {
    res.json({
        success: true,
        totalAgents: orchestrator.getTotalAgents(),
        teams: orchestrator.getTeamsStatus(),
        activeMissions: orchestrator.getActiveMissions().length,
        model: orchestrator.orchestratorModel
    });
});

/**
 * GET /api/orchestrator/teams
 * Liste des équipes et leurs agents
 */
router.get('/teams', (req, res) => {
    res.json({
        success: true,
        teams: orchestrator.getTeamsStatus()
    });
});

/**
 * POST /api/orchestrator/analyze
 * Analyser une tâche sans l'exécuter
 */
router.post('/analyze', async (req, res) => {
    const { task } = req.body;
    
    if (!task) {
        return res.status(400).json({ success: false, error: 'task requis' });
    }

    try {
        const analysis = await orchestrator.analyzeTask(task);
        res.json({ success: true, analysis });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/orchestrator/mission
 * Lancer une mission complète multi-agents
 */
router.post('/mission', async (req, res) => {
    const { task, options } = req.body;
    
    if (!task) {
        return res.status(400).json({ success: false, error: 'task requis' });
    }

    try {
        const mission = await orchestrator.executeMission(task, options || {});
        res.json({ success: true, mission });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/orchestrator/delegate
 * Déléguer une tâche à une équipe spécifique
 */
router.post('/delegate', async (req, res) => {
    const { team, task } = req.body;
    
    if (!team || !task) {
        return res.status(400).json({ success: false, error: 'team et task requis' });
    }

    try {
        const result = await orchestrator.delegateToTeam(team, task);
        res.json({ success: true, result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/orchestrator/missions/active
 * Missions en cours
 */
router.get('/missions/active', (req, res) => {
    res.json({
        success: true,
        missions: orchestrator.getActiveMissions()
    });
});

/**
 * GET /api/orchestrator/missions/history
 * Historique des missions
 */
router.get('/missions/history', (req, res) => {
    const limit = parseInt(req.query.limit) || 20;
    res.json({
        success: true,
        missions: orchestrator.getMissionHistory(limit)
    });
});

/**
 * POST /api/orchestrator/quick
 * Action rapide - Le chef décide automatiquement
 */
router.post('/quick', async (req, res) => {
    const { query } = req.body;
    
    if (!query) {
        return res.status(400).json({ success: false, error: 'query requis' });
    }

    try {
        // Analyse rapide pour déterminer l'équipe
        const keywords = query.toLowerCase();
        let team = 'general';
        
        if (keywords.includes('scan') || keywords.includes('nmap') || keywords.includes('exploit') || 
            keywords.includes('hack') || keywords.includes('password') || keywords.includes('vuln')) {
            team = 'hacking';
        } else if (keywords.includes('osint') || keywords.includes('recherche') || keywords.includes('email') ||
                   keywords.includes('domain') || keywords.includes('social') || keywords.includes('ip')) {
            team = 'osint';
        }

        const result = await orchestrator.delegateToTeam(team, query);
        res.json({ success: true, autoSelectedTeam: team, result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;
