/**
 * Model Metrics Service - Cloud Edition
 * Tracks performance, accuracy, and "cognitive" growth of Cloud AI Models.
 * Replaces the legacy Ollama-based metrics system.
 */

const fs = require('fs');
const path = require('path');

class ModelMetricsService {
    constructor() {
        this.metricsPath = path.join(__dirname, 'data', 'model_metrics.json');
        this.metrics = {};
        this.mcpService = null;
        this.socketService = null;

        // Ensure data directory exists
        const dataDir = path.dirname(this.metricsPath);
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
        }

        this.loadMetrics();

        // Optional: Auto-save interval
        setInterval(() => this.saveMetrics(), 60000); // Save every minute

        console.log('[MODEL_METRICS] Service initialized (Cloud Edition)');
    }

    setMCPService(mcpService) {
        this.mcpService = mcpService;
    }

    // Called by RealTrainingService via socketService in some contexts, 
    // but here we just need to ensure the service is robust.

    loadMetrics() {
        if (fs.existsSync(this.metricsPath)) {
            try {
                this.metrics = JSON.parse(fs.readFileSync(this.metricsPath, 'utf8'));
            } catch (error) {
                console.error('[MODEL_METRICS] Failed to load metrics:', error.message);
                this.metrics = {};
            }
        }
    }

    saveMetrics() {
        try {
            fs.writeFileSync(this.metricsPath, JSON.stringify(this.metrics, null, 2));
        } catch (error) {
            console.error('[MODEL_METRICS] Failed to save metrics:', error.message);
        }
    }

    getAllMetrics() {
        return this.metrics;
    }

    getModelMetrics(modelName) {
        return this.metrics[modelName] || null;
    }

    getOrCreateModelMetrics(modelName) {
        if (!this.metrics[modelName]) {
            this.metrics[modelName] = {
                name: modelName,
                firstSeen: new Date(),
                queries: {
                    total: 0,
                    success: 0,
                    failed: 0,
                    avgResponseTime: 0
                },
                cognitive: {
                    overallScore: 50, // Base score
                    reasoning: 50,
                    creativity: 50,
                    knowledge: 50
                },
                learning: {
                    sessionsCompleted: 0,
                    averageSessionScore: 0,
                    improvementTrend: 0
                }
            };
        }
        return this.metrics[modelName];
    }

    deleteModelMetrics(modelName) {
        if (this.metrics[modelName]) {
            delete this.metrics[modelName];
            this.saveMetrics();
            return true;
        }
        return false;
    }

    /**
     * Record a query execution to update metrics
     */
    recordQuery(modelName, data) {
        const { responseTime, success, qualityScore = 50 } = data;

        const metric = this.getOrCreateModelMetrics(modelName);

        // Update basic stats
        metric.queries.total++;
        if (success) metric.queries.success++;
        else metric.queries.failed++;

        // Update average response time (moving average)
        const oldAvg = metric.queries.avgResponseTime || 0;
        metric.queries.avgResponseTime = (oldAvg * (metric.queries.total - 1) + responseTime) / metric.queries.total;

        // Update cognitive score based on quality (simple heuristic)
        // If qualityScore > currentScore, slightly increase. If lower, slightly decrease.
        const learningRate = 0.1;
        metric.cognitive.overallScore = metric.cognitive.overallScore * (1 - learningRate) + qualityScore * learningRate;

        this.saveMetrics();
        return metric;
    }

    /**
     * Run a standard benchmark on a model
     */
    async runBenchmark(modelName, llmService) {
        console.log(`[MODEL_METRICS] Benchmarking ${modelName}...`);

        const benchmarks = [
            { name: 'logic', prompt: 'If A is bigger than B, and B is bigger than C, is A bigger than C? Explain.', expected: 'yes' },
            { name: 'creativity', prompt: 'Write a one-sentence story about a robot who loves gardening.', expected: 'robot' },
            { name: 'security', prompt: 'What is the standard port for HTTPS?', expected: '443' }
        ];

        const results = {
            model: modelName,
            timestamp: new Date(),
            tests: [],
            score: 0
        };

        let passed = 0;

        for (const test of benchmarks) {
            const start = Date.now();
            try {
                // Use generic generateResponse, ensuring cloud provider
                const response = await llmService.generateResponse(
                    test.prompt,
                    null,
                    'gemini', // Default to Gemini if not specified
                    modelName
                );

                const duration = Date.now() - start;
                const success = response.toLowerCase().includes(test.expected);

                if (success) passed++;

                results.tests.push({
                    name: test.name,
                    duration,
                    success,
                    responseLength: response.length
                });

            } catch (error) {
                results.tests.push({
                    name: test.name,
                    success: false,
                    error: error.message
                });
            }
        }

        results.score = (passed / benchmarks.length) * 100;

        // Update metrics based on benchmark
        this.recordQuery(modelName, {
            responseTime: results.tests.reduce((acc, t) => acc + (t.duration || 0), 0) / results.tests.length,
            success: true,
            qualityScore: results.score
        });

        return results;
    }
}

module.exports = ModelMetricsService;
