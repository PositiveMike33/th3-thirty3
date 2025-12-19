/**
 * OSINT Team Routes
 * API endpoints for OSINT Expert Team 2025
 */

const express = require('express');
const router = express.Router();
const OsintTeamAnythingLLM = require('./osint_team_anythingllm');

let osintTeam = null;

// Initialize with AnythingLLM wrapper
function initializeTeam(anythingLLMWrapper) {
    osintTeam = new OsintTeamAnythingLLM(anythingLLMWrapper);
    return osintTeam;
}

/**
 * GET /api/osint-team
 * Get team configuration
 */
router.get('/', (req, res) => {
    if (!osintTeam) {
        osintTeam = new OsintTeamAnythingLLM(null);
    }
    
    const config = osintTeam.getTeamConfig();
    if (config) {
        res.json({
            success: true,
            name: config.agent_name,
            description: config.description,
            team: osintTeam.getTeamMembers(),
            toolsCount: config.tools?.length || 0,
            workflowSteps: config.workflow?.steps?.length || 0
        });
    } else {
        res.status(404).json({ success: false, error: 'Team config not found' });
    }
});

/**
 * GET /api/osint-team/members
 * Get team members
 */
router.get('/members', (req, res) => {
    if (!osintTeam) {
        osintTeam = new OsintTeamAnythingLLM(null);
    }
    
    res.json({
        success: true,
        members: osintTeam.getTeamMembers()
    });
});

/**
 * GET /api/osint-team/workflow
 * Get investigation workflow
 */
router.get('/workflow', (req, res) => {
    if (!osintTeam) {
        osintTeam = new OsintTeamAnythingLLM(null);
    }
    
    res.json({
        success: true,
        workflow: osintTeam.getWorkflow()
    });
});

/**
 * GET /api/osint-team/tools
 * Get available OSINT tools
 */
router.get('/tools', (req, res) => {
    if (!osintTeam) {
        osintTeam = new OsintTeamAnythingLLM(null);
    }
    
    const tools = osintTeam.getTools();
    res.json({
        success: true,
        count: tools.length,
        tools: tools.map(t => ({
            name: t.name,
            id: t.id,
            type: t.type,
            category: t.category,
            version: t.version,
            api_required: t.api_required || false,
            doc_url: t.doc_url
        }))
    });
});

/**
 * GET /api/osint-team/tools/:id
 * Get specific tool details
 */
router.get('/tools/:id', (req, res) => {
    if (!osintTeam) {
        osintTeam = new OsintTeamAnythingLLM(null);
    }
    
    const tools = osintTeam.getTools();
    const tool = tools.find(t => t.id === req.params.id || t.name.toLowerCase() === req.params.id.toLowerCase());
    
    if (tool) {
        res.json({ success: true, tool });
    } else {
        res.status(404).json({ success: false, error: 'Tool not found' });
    }
});

/**
 * POST /api/osint-team/execute-step
 * Execute a specific workflow step
 */
router.post('/execute-step', async (req, res) => {
    if (!osintTeam) {
        osintTeam = new OsintTeamAnythingLLM(null);
    }
    
    const { step, target, context } = req.body;
    
    if (!step || !target) {
        return res.status(400).json({ 
            success: false, 
            error: 'step and target are required' 
        });
    }

    try {
        console.log(`[OSINT-TEAM API] Executing step ${step} for target: ${target}`);
        const result = await osintTeam.executeWorkflowStep(parseInt(step), target, context || {});
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/osint-team/investigate
 * Run full investigation pipeline
 */
router.post('/investigate', async (req, res) => {
    if (!osintTeam) {
        osintTeam = new OsintTeamAnythingLLM(null);
    }
    
    const { target, targetType } = req.body;
    
    if (!target) {
        return res.status(400).json({ 
            success: false, 
            error: 'target is required' 
        });
    }

    try {
        console.log(`[OSINT-TEAM API] Starting investigation for: ${target}`);
        const results = await osintTeam.runFullInvestigation(target, targetType || 'domain');
        res.json({ success: true, results });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/osint-team/best-practices
 * Get OSINT best practices
 */
router.get('/best-practices', (req, res) => {
    if (!osintTeam) {
        osintTeam = new OsintTeamAnythingLLM(null);
    }
    
    const config = osintTeam.getTeamConfig();
    if (config?.best_practices) {
        res.json({
            success: true,
            practices: config.best_practices
        });
    } else {
        res.json({ success: true, practices: [] });
    }
});

/**
 * POST /api/osint-team/init-workspace
 * Initialize AnythingLLM workspace
 */
router.post('/init-workspace', async (req, res) => {
    if (!osintTeam) {
        osintTeam = new OsintTeamAnythingLLM(null);
    }
    
    try {
        const result = await osintTeam.initializeWorkspace();
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Export router and initializer
module.exports = router;
module.exports.initializeTeam = initializeTeam;
