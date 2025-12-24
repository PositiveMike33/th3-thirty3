/**
 * LIGHTWEIGHT AGENTS API ROUTES
 * 
 * Exposes the lightweight agent system via REST API
 * Alternative to AnythingLLM for lower resource usage
 */

const express = require('express');
const router = express.Router();
const { getLightweightAgents } = require('./lightweight_agents');

// Lazy load agents only when routes are accessed
let agentSystem = null;

function getAgents() {
    if (!agentSystem) {
        agentSystem = getLightweightAgents();
    }
    return agentSystem;
}

/**
 * GET /api/agents/list
 * List all available agents
 */
router.get('/list', (req, res) => {
    try {
        const agents = getAgents().listAgents();
        res.json({ 
            success: true, 
            agents,
            mode: 'lightweight',
            description: 'Direct Ollama integration without external servers'
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/agents/:agentId
 * Get specific agent details
 */
router.get('/:agentId', (req, res) => {
    try {
        const agent = getAgents().getAgent(req.params.agentId);
        if (agent) {
            res.json({ 
                success: true, 
                agent: {
                    id: agent.id,
                    name: agent.name,
                    description: agent.description,
                    model: agent.model
                }
            });
        } else {
            res.status(404).json({ success: false, error: 'Agent not found' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/agents/chat
 * Chat with a specific agent
 */
router.post('/chat', async (req, res) => {
    try {
        const { agentId, message, sessionId, options } = req.body;
        
        if (!agentId || !message) {
            return res.status(400).json({ 
                success: false, 
                error: 'agentId and message are required' 
            });
        }

        const result = await getAgents().chat(
            agentId, 
            message, 
            sessionId || 'default',
            options || {}
        );

        res.json({ success: true, ...result });
    } catch (error) {
        console.error('[AGENTS] Chat error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/agents/smart-chat
 * Chat with auto-selected agent based on message content
 */
router.post('/smart-chat', async (req, res) => {
    try {
        const { message, sessionId, options } = req.body;
        
        if (!message) {
            return res.status(400).json({ 
                success: false, 
                error: 'message is required' 
            });
        }

        const result = await getAgents().smartChat(
            message, 
            sessionId || 'default',
            options || {}
        );

        res.json({ success: true, ...result });
    } catch (error) {
        console.error('[AGENTS] Smart chat error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * DELETE /api/agents/history/:agentId/:sessionId
 * Clear conversation history
 */
router.delete('/history/:agentId/:sessionId?', (req, res) => {
    try {
        const { agentId, sessionId } = req.params;
        getAgents().clearHistory(agentId, sessionId || 'default');
        res.json({ success: true, message: 'History cleared' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/agents/stats
 * Get agent system statistics
 */
router.get('/system/stats', (req, res) => {
    try {
        const stats = getAgents().getStats();
        res.json({ success: true, ...stats });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;
