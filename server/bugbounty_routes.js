/**
 * BUG BOUNTY AGENTS API ROUTES
 * 
 * REST API pour les agents Bug Bounty autonomes
 * Intègre red teaming et HackerAI
 */

const express = require('express');
const router = express.Router();
const { getBugBountyService } = require('./bugbounty_agents_service');

// Lazy load service
let service = null;
function getService() {
    if (!service) {
        service = getBugBountyService();
    }
    return service;
}

/**
 * GET /api/bugbounty/status
 * Get service status
 */
router.get('/status', (req, res) => {
    try {
        const status = getService().getStatus();
        res.json({ success: true, ...status });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/bugbounty/agents
 * List all available agents
 */
router.get('/agents', (req, res) => {
    try {
        const agents = getService().getAgents();
        res.json({ success: true, agents, count: agents.length });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/bugbounty/agents/:id
 * Get specific agent details
 */
router.get('/agents/:id', (req, res) => {
    try {
        const agent = getService().getAgent(req.params.id);
        if (!agent) {
            return res.status(404).json({ success: false, error: 'Agent not found' });
        }
        res.json({ success: true, agent });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/bugbounty/agents/:id/redteam
 * Get red teaming prompts for an agent
 */
router.get('/agents/:id/redteam', (req, res) => {
    try {
        const prompts = getService().getRedTeamingPrompts(req.params.id);
        res.json({ success: true, prompts });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/bugbounty/agents/:id/bestpractices
 * Get best practices for an agent
 */
router.get('/agents/:id/bestpractices', (req, res) => {
    try {
        const practices = getService().getBestPractices(req.params.id);
        res.json({ success: true, practices });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/bugbounty/agents/:id/pitfalls
 * Get pitfalls to avoid for an agent
 */
router.get('/agents/:id/pitfalls', (req, res) => {
    try {
        const pitfalls = getService().getPitfalls(req.params.id);
        res.json({ success: true, pitfalls });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/bugbounty/mission/start
 * Start a new bug bounty mission
 */
router.post('/mission/start', async (req, res) => {
    try {
        const { name, target, scope, agents, autonomyLevel } = req.body;
        
        if (!target) {
            return res.status(400).json({ success: false, error: 'Target is required' });
        }

        const result = await getService().startMission({
            name,
            target,
            scope: scope || [],
            agents: agents || ['recon_agent', 'scan_agent'],
            autonomyLevel
        });

        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/bugbounty/missions
 * Get all active missions
 */
router.get('/missions', (req, res) => {
    try {
        const missions = getService().getActiveMissions();
        res.json({ success: true, missions, count: missions.length });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/bugbounty/mission/:id
 * Get mission details
 */
router.get('/mission/:id', (req, res) => {
    try {
        const mission = getService().getMission(req.params.id);
        if (!mission) {
            return res.status(404).json({ success: false, error: 'Mission not found' });
        }
        res.json({ success: true, mission });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/bugbounty/mission/:id/stop
 * Stop a mission
 */
router.post('/mission/:id/stop', (req, res) => {
    try {
        const result = getService().stopMission(req.params.id);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/bugbounty/mission/:id/finding
 * Add a finding to a mission
 */
router.post('/mission/:id/finding', (req, res) => {
    try {
        const { title, description, severity, cvss, poc, affected } = req.body;
        
        const result = getService().addFinding(req.params.id, {
            title,
            description,
            severity,
            cvss,
            poc,
            affected
        });

        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/bugbounty/mission/:id/report
 * Generate report for a mission
 */
router.get('/mission/:id/report', (req, res) => {
    try {
        const result = getService().generateReport(req.params.id);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/bugbounty/execute
 * Execute an agent tool
 */
router.post('/execute', async (req, res) => {
    try {
        const { agentId, toolName, params } = req.body;

        if (!agentId || !toolName) {
            return res.status(400).json({ 
                success: false, 
                error: 'agentId and toolName are required' 
            });
        }

        const result = await getService().executeAgentTool(agentId, toolName, params || {});
        res.json({ success: true, execution: result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/bugbounty/hackerai/init
 * Initialize HackerAI connection
 */
router.post('/hackerai/init', (req, res) => {
    try {
        const result = getService().initHackerAI();
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/bugbounty/config
 * Get global configuration
 */
router.get('/config', (req, res) => {
    try {
        const config = getService().getGlobalConfig();
        res.json({ success: true, config });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;
