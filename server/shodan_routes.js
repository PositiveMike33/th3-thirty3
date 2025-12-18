/**
 * Shodan API Routes
 * Provides endpoints for Shodan integration and AI training
 */

const express = require('express');
const router = express.Router();

module.exports = (shodanService, modelMetricsService, llmService) => {
    
    // ==========================================
    // STATUS & INFO
    // ==========================================
    
    /**
     * GET /shodan/status
     * Get Shodan service status and API credits
     */
    router.get('/status', async (req, res) => {
        try {
            const status = await shodanService.getStatus();
            res.json(status);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    /**
     * GET /shodan/account
     * Get account information
     */
    router.get('/account', async (req, res) => {
        try {
            const info = await shodanService.getAccountInfo();
            res.json(info);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    /**
     * GET /shodan/myip
     * Get current public IP
     */
    router.get('/myip', async (req, res) => {
        try {
            const ip = await shodanService.getMyIp();
            res.json({ ip });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    // ==========================================
    // SEARCH & LOOKUP
    // ==========================================

    /**
     * GET /shodan/search?query=apache&page=1
     * Search Shodan for hosts
     */
    router.get('/search', async (req, res) => {
        try {
            const { query, page = 1 } = req.query;
            if (!query) {
                return res.status(400).json({ error: 'Query parameter required' });
            }
            const results = await shodanService.search(query, parseInt(page));
            res.json(results);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    /**
     * GET /shodan/host/:ip
     * Get detailed information about a host
     */
    router.get('/host/:ip', async (req, res) => {
        try {
            const { ip } = req.params;
            const host = await shodanService.getHost(ip);
            res.json(host);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    /**
     * GET /shodan/dns/resolve?hostnames=google.com,facebook.com
     * Resolve hostnames to IPs
     */
    router.get('/dns/resolve', async (req, res) => {
        try {
            const { hostnames } = req.query;
            if (!hostnames) {
                return res.status(400).json({ error: 'Hostnames parameter required' });
            }
            const result = await shodanService.getDnsResolve(hostnames);
            res.json(result);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    /**
     * GET /shodan/dns/reverse?ips=8.8.8.8,1.1.1.1
     * Reverse DNS lookup
     */
    router.get('/dns/reverse', async (req, res) => {
        try {
            const { ips } = req.query;
            if (!ips) {
                return res.status(400).json({ error: 'IPs parameter required' });
            }
            const result = await shodanService.getReverseDns(ips);
            res.json(result);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    /**
     * GET /shodan/cve/:cve
     * Get information about a CVE
     */
    router.get('/cve/:cve', async (req, res) => {
        try {
            const { cve } = req.params;
            const result = await shodanService.getCVE(cve);
            res.json(result);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    /**
     * GET /shodan/exploits?query=apache
     * Search for exploits
     */
    router.get('/exploits', async (req, res) => {
        try {
            const { query } = req.query;
            if (!query) {
                return res.status(400).json({ error: 'Query parameter required' });
            }
            const results = await shodanService.searchExploits(query);
            res.json(results);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    // ==========================================
    // AI TRAINING INTEGRATION
    // ==========================================

    /**
     * GET /shodan/training/data?category=all
     * Generate training data from Shodan
     */
    router.get('/training/data', async (req, res) => {
        try {
            const { category = 'all' } = req.query;
            const trainingData = await shodanService.generateTrainingData(category);
            res.json({
                success: true,
                category,
                count: trainingData.length,
                data: trainingData
            });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    /**
     * POST /shodan/training/session
     * Create a training session with real Shodan data
     */
    router.post('/training/session', async (req, res) => {
        try {
            const { modelName } = req.body;
            if (!modelName) {
                return res.status(400).json({ error: 'modelName required' });
            }
            
            // This would integrate with RealTrainingService
            const session = await shodanService.createTrainingSession(modelName, null);
            res.json(session);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    /**
     * POST /shodan/training/iterate
     * Run a single Shodan-powered training iteration
     */
    router.post('/training/iterate', async (req, res) => {
        try {
            const { modelName, category = 'vulnerability_analysis' } = req.body;
            
            if (!modelName) {
                return res.status(400).json({ error: 'modelName required' });
            }

            const result = await shodanService.runShodanTrainingIteration(
                modelName, 
                llmService, 
                category
            );

            // Record in model metrics if successful
            if (result.success && modelMetricsService) {
                modelMetricsService.recordQuery(modelName, {
                    responseTime: result.responseTime,
                    tokensGenerated: Math.floor((result.responseLength || 0) / 4),
                    success: true,
                    category: 'analysis',
                    qualityScore: result.score
                });
            }

            res.json(result);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    /**
     * POST /shodan/training/full
     * Run full Shodan training session for a model
     */
    router.post('/training/full', async (req, res) => {
        try {
            const { modelName, iterations = 5 } = req.body;
            
            if (!modelName) {
                return res.status(400).json({ error: 'modelName required' });
            }

            const categories = [
                'vulnerability_analysis',
                'network_reconnaissance', 
                'threat_intelligence'
            ];

            const results = [];
            
            for (let i = 0; i < iterations; i++) {
                for (const category of categories) {
                    const result = await shodanService.runShodanTrainingIteration(
                        modelName,
                        llmService,
                        category
                    );
                    results.push(result);

                    if (result.success && modelMetricsService) {
                        modelMetricsService.recordQuery(modelName, {
                            responseTime: result.responseTime,
                            tokensGenerated: Math.floor((result.responseLength || 0) / 4),
                            success: true,
                            category: 'analysis',
                            qualityScore: result.score
                        });
                    }

                    // Small delay between iterations
                    await new Promise(r => setTimeout(r, 1000));
                }
            }

            const avgScore = results
                .filter(r => r.success)
                .reduce((acc, r) => acc + r.score, 0) / results.filter(r => r.success).length;

            res.json({
                success: true,
                modelName,
                iterations,
                totalTrainingRuns: results.length,
                successfulRuns: results.filter(r => r.success).length,
                averageScore: Math.round(avgScore * 10) / 10,
                results
            });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    return router;
};
