/**
 * Routes API pour Agent Memory Service
 */

const express = require('express');
const router = express.Router();
const AgentMemoryService = require('./agent_memory_service');

const memoryService = new AgentMemoryService();

/**
 * GET /api/agent-memory/stats
 * Statistiques de mémoire pour tous les agents
 */
router.get('/stats', (req, res) => {
    res.json({
        success: true,
        stats: memoryService.getMemoryStats()
    });
});

/**
 * POST /api/agent-memory/store
 * Stocker une connaissance pour un agent
 */
router.post('/store', async (req, res) => {
    const { agentId, knowledge, metadata, syncPieces } = req.body;
    
    if (!agentId || !knowledge) {
        return res.status(400).json({ 
            success: false, 
            error: 'agentId et knowledge requis' 
        });
    }

    try {
        const stored = await memoryService.storeKnowledge(agentId, knowledge, metadata);
        
        // Sync optionnel avec Pieces
        let piecesSynced = false;
        if (syncPieces) {
            piecesSynced = await memoryService.syncWithPieces(agentId, knowledge);
        }

        res.json({ success: stored, piecesSynced, agentId });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/agent-memory/search
 * Rechercher des connaissances pour un agent
 */
router.post('/search', async (req, res) => {
    const { agentId, query, topK } = req.body;
    
    if (!agentId || !query) {
        return res.status(400).json({ 
            success: false, 
            error: 'agentId et query requis' 
        });
    }

    try {
        const results = await memoryService.searchKnowledge(agentId, query, topK || 5);
        res.json({ success: true, results, count: results.length });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/agent-memory/search-all
 * Rechercher dans tous les agents (collaboration)
 */
router.post('/search-all', async (req, res) => {
    const { query, topK } = req.body;
    
    if (!query) {
        return res.status(400).json({ 
            success: false, 
            error: 'query requis' 
        });
    }

    try {
        const results = await memoryService.searchAllAgents(query, topK || 10);
        res.json({ success: true, results, count: results.length });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/agent-memory/context
 * Obtenir le contexte enrichi pour une query
 */
router.post('/context', async (req, res) => {
    const { agentId, query } = req.body;
    
    if (!agentId || !query) {
        return res.status(400).json({ 
            success: false, 
            error: 'agentId et query requis' 
        });
    }

    try {
        const context = await memoryService.getEnrichedContext(agentId, query);
        res.json({ success: true, context });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/agent-memory/embed
 * Générer un embedding pour du texte
 */
router.post('/embed', async (req, res) => {
    const { text } = req.body;
    
    if (!text) {
        return res.status(400).json({ 
            success: false, 
            error: 'text requis' 
        });
    }

    try {
        const embedding = await memoryService.generateEmbedding(text);
        res.json({ 
            success: !!embedding, 
            dimensions: embedding?.length || 0,
            embedding: embedding 
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * DELETE /api/agent-memory/cleanup/:agentId
 * Nettoyer les anciens embeddings
 */
router.delete('/cleanup/:agentId', (req, res) => {
    const { agentId } = req.params;
    const { keepLast } = req.body;
    
    try {
        memoryService.cleanup(agentId, keepLast || 100);
        res.json({ success: true, agentId });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Export le service pour utilisation dans d'autres modules
router.memoryService = memoryService;

module.exports = router;
