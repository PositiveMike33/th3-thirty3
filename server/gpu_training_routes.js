/**
 * GPU Training Routes
 * Express routes for GPU training operations
 */

const express = require('express');
const router = express.Router();

module.exports = function (gpuTrainingService) {

    // Health check
    router.get('/health', async (req, res) => {
        try {
            const health = await gpuTrainingService.checkHealth();
            res.json(health || { status: 'disconnected' });
        } catch (error) {
            res.json({ status: 'error', error: error.message });
        }
    });

    // GPU information
    router.get('/info', async (req, res) => {
        try {
            const info = await gpuTrainingService.getGpuInfo();
            res.json(info);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    // Start training
    router.post('/train/start', async (req, res) => {
        try {
            const { jobId, category, iterations, customData } = req.body;
            const result = await gpuTrainingService.startTraining({
                jobId,
                category: category || 'security',
                iterations: iterations || 5,
                customData
            });
            res.json(result);
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });

    // Get training status
    router.get('/train/status/:jobId', async (req, res) => {
        try {
            const status = await gpuTrainingService.getTrainingStatus(req.params.jobId);
            res.json(status || { error: 'Job not found' });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    // Get all jobs
    router.get('/train/jobs', async (req, res) => {
        try {
            const jobs = await gpuTrainingService.getAllJobs();
            res.json(jobs);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    // Stop training
    router.post('/train/stop/:jobId', async (req, res) => {
        try {
            const result = await gpuTrainingService.stopTraining(req.params.jobId);
            res.json(result);
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });

    // Generate embeddings
    router.post('/embeddings', async (req, res) => {
        try {
            const { texts } = req.body;
            if (!texts) {
                return res.status(400).json({ error: 'texts required' });
            }
            const result = await gpuTrainingService.generateEmbeddings(texts);
            res.json(result);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    // Analyze vulnerability
    router.post('/analyze/vulnerability', async (req, res) => {
        try {
            const { content, type } = req.body;
            if (!content) {
                return res.status(400).json({ error: 'content required' });
            }
            const result = await gpuTrainingService.analyzeVulnerability(content, type);
            res.json(result);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    // Predict exploit
    router.post('/predict/exploit', async (req, res) => {
        try {
            const { vulnerability } = req.body;
            const result = await gpuTrainingService.predictExploit(vulnerability);
            res.json(result);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    // Train hacking expert
    router.post('/train/expert/:expertId', async (req, res) => {
        try {
            const { expertId } = req.params;
            const { topic, iterations } = req.body;
            const result = await gpuTrainingService.trainHackingExpert(
                expertId,
                topic || 'security',
                iterations || 3
            );
            res.json(result);
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });

    // Service status
    router.get('/status', (req, res) => {
        res.json(gpuTrainingService.getStatus());
    });

    return router;
};
