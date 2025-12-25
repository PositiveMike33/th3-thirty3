/**
 * Performance Mode Routes
 * API endpoints to control performance optimization
 */

const express = require('express');
const router = express.Router();

module.exports = function(llmService) {
    
    // Get performance mode status
    router.get('/status', (req, res) => {
        res.json(llmService.getPerformanceStatus());
    });
    
    // Enable performance mode (HackerGPT only)
    router.post('/enable', async (req, res) => {
        llmService.setPerformanceMode(true);
        
        // Unload local models to free VRAM
        await llmService.unloadAllModels();
        
        res.json({
            success: true,
            message: 'Performance mode ENABLED - Using HackerGPT only',
            status: llmService.getPerformanceStatus()
        });
    });
    
    // Disable performance mode (full capabilities)
    router.post('/disable', (req, res) => {
        llmService.setPerformanceMode(false);
        
        res.json({
            success: true,
            message: 'Performance mode DISABLED - Full model access restored',
            status: llmService.getPerformanceStatus()
        });
    });
    
    // Force unload all local models
    router.post('/unload-models', async (req, res) => {
        await llmService.unloadAllModels();
        
        res.json({
            success: true,
            message: 'All local models unloaded - VRAM freed'
        });
    });
    
    // Quick HackerGPT chat (performance mode endpoint)
    router.post('/hackergpt', async (req, res) => {
        const { prompt, systemPrompt } = req.body;
        
        if (!prompt) {
            return res.status(400).json({ error: 'prompt required' });
        }
        
        try {
            const response = await llmService.getHackerGPTResponse(
                prompt, 
                systemPrompt || 'You are HackerGPT, an elite cybersecurity AI assistant.'
            );
            
            res.json({
                success: true,
                model: 'HackerGPT (Groq)',
                response
            });
        } catch (error) {
            res.status(500).json({ 
                error: error.message,
                fallback: 'Try /chat with provider=local for offline mode'
            });
        }
    });
    
    // Get current primary model info
    router.get('/primary-model', (req, res) => {
        const status = llmService.getPerformanceStatus();
        res.json({
            primaryModel: status.primaryModel,
            provider: 'groq',
            model: 'llama-3.3-70b-versatile',
            description: 'HackerGPT - Fast cloud inference, no local VRAM needed',
            rateLimit: '30 requests/minute'
        });
    });
    
    return router;
};
