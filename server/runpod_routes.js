/**
 * RunPod API Routes
 * 
 * Endpoints for managing RunPod GPU cloud inference:
 * - /api/runpod/status - Get service status
 * - /api/runpod/generate - Generate response using RunPod
 * - /api/runpod/pods - List/manage GPU pods
 * - /api/runpod/endpoints - List serverless endpoints
 * - /api/runpod/pricing - Get pricing information
 * 
 * @author Th3 Thirty3
 */

const express = require('express');
const router = express.Router();
const runpodService = require('./runpod_service');

/**
 * GET /api/runpod/status
 * Get RunPod service status
 */
router.get('/status', async (req, res) => {
    try {
        const status = runpodService.getStatus();
        
        // Check connection if configured
        if (status.configured && !status.connected) {
            const connectionCheck = await runpodService.checkConnection();
            status.connectionCheck = connectionCheck;
        }
        
        res.json({
            success: true,
            ...status
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /api/runpod/generate
 * Generate response using RunPod serverless or pod
 */
router.post('/generate', async (req, res) => {
    try {
        const { prompt, model, systemPrompt, maxTokens, temperature, mode } = req.body;
        
        if (!prompt) {
            return res.status(400).json({
                success: false,
                error: 'Prompt is required'
            });
        }
        
        const options = {
            systemPrompt: systemPrompt || 'You are a helpful AI assistant.',
            maxTokens: maxTokens || 2048,
            temperature: temperature || 0.7
        };
        
        let response;
        
        if (mode === 'openai') {
            // Use OpenAI-compatible endpoint (for vLLM pods)
            response = await runpodService.generateOpenAICompatibleResponse(prompt, {
                ...options,
                model: model || 'default'
            });
        } else {
            // Use serverless endpoint
            response = await runpodService.generateServerlessResponse(
                prompt,
                model || 'llama70b',
                options
            );
        }
        
        res.json({
            success: true,
            response,
            model: model || 'llama70b',
            provider: 'runpod'
        });
        
    } catch (error) {
        console.error('[RUNPOD_ROUTES] Generate error:', error.message);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /api/runpod/pods
 * List active GPU pods
 */
router.get('/pods', async (req, res) => {
    try {
        const result = await runpodService.listPods();
        res.json(result);
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /api/runpod/pods
 * Create a new GPU pod
 */
router.post('/pods', async (req, res) => {
    try {
        const { gpuType, name, volumeSize, templateId } = req.body;
        
        const result = await runpodService.createPod({
            gpuType,
            name,
            volumeSize,
            templateId
        });
        
        res.json(result);
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /api/runpod/pods/:podId/stop
 * Stop a running pod
 */
router.post('/pods/:podId/stop', async (req, res) => {
    try {
        const { podId } = req.params;
        const result = await runpodService.stopPod(podId);
        res.json(result);
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * DELETE /api/runpod/pods/:podId
 * Terminate and delete a pod
 */
router.delete('/pods/:podId', async (req, res) => {
    try {
        const { podId } = req.params;
        const result = await runpodService.terminatePod(podId);
        res.json(result);
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /api/runpod/endpoints
 * List serverless endpoints
 */
router.get('/endpoints', async (req, res) => {
    try {
        const result = await runpodService.listServerlessEndpoints();
        res.json(result);
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /api/runpod/pricing
 * Get RunPod pricing information
 */
router.get('/pricing', (req, res) => {
    try {
        const pricing = runpodService.getPricing();
        res.json({
            success: true,
            pricing
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /api/runpod/stats
 * Get usage statistics
 */
router.get('/stats', (req, res) => {
    try {
        const status = runpodService.getStatus();
        res.json({
            success: true,
            stats: status.stats
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

module.exports = router;
