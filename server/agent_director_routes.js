/**
 * Routes API pour le Director des Agents
 * Permet d'interagir avec le Directeur Th3 Thirty3
 */

const express = require('express');
const router = express.Router();

let agentDirector = null;

// Setter for dependency injection
router.setAgentDirector = (service) => {
    agentDirector = service;
};

/**
 * POST /director/chat
 * Chat with the Director (main entry point)
 * Body: { message }
 */
router.post('/chat', async (req, res) => {
    if (!agentDirector) {
        return res.status(503).json({ error: 'Agent Director not initialized' });
    }
    
    const { message } = req.body;
    if (!message) {
        return res.status(400).json({ error: 'Message is required' });
    }
    
    try {
        const result = await agentDirector.chat(message);
        res.json({
            success: true,
            ...result
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /director/status
 * Get director and agents status
 */
router.get('/status', (req, res) => {
    if (!agentDirector) {
        return res.status(503).json({ error: 'Agent Director not initialized' });
    }
    
    res.json({
        success: true,
        ...agentDirector.getAgentStatus()
    });
});

/**
 * POST /director/clear
 * Clear conversation history
 */
router.post('/clear', (req, res) => {
    if (!agentDirector) {
        return res.status(503).json({ error: 'Agent Director not initialized' });
    }
    
    agentDirector.clearHistory();
    res.json({
        success: true,
        message: 'Conversation history cleared'
    });
});

/**
 * POST /director/dispatch
 * Directly dispatch to a specific agent
 * Body: { agentId, objective }
 */
router.post('/dispatch', async (req, res) => {
    if (!agentDirector) {
        return res.status(503).json({ error: 'Agent Director not initialized' });
    }
    
    const { agentId, objective } = req.body;
    if (!agentId || !objective) {
        return res.status(400).json({ error: 'agentId and objective are required' });
    }
    
    try {
        const result = await agentDirector.dispatchToAgent(agentId, objective);
        res.json({
            success: true,
            ...result
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

module.exports = router;
