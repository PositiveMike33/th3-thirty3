/**
 * Model Metrics Service
 * Tracks performance, expertise, and cognitive progression of Ollama models
 * Integrates with AnythingLLM + Pieces for long-term memory (3 months)
 */

const fs = require('fs');
const path = require('path');

// Local cache file for quick access
const METRICS_PATH = path.join(__dirname, 'data', 'model_metrics.json');

// Benchmark prompts for hourly testing
const BENCHMARK_PROMPTS = {
    coding: "Write a JavaScript function that calculates the Fibonacci sequence up to n terms. Include error handling and optimize for performance.",
    intelligence: "Explain quantum entanglement and its implications for computing in simple terms that a 12-year-old could understand.",
    logic: "A farmer has 17 sheep. All but 9 run away. How many sheep does he have left? Explain your reasoning step by step.",
    creativity: "Create a short story (100 words) about a robot discovering emotions for the first time.",
    chat: "You are a friendly assistant. How would you respond to someone who says: 'I'm feeling really stressed about my job interview tomorrow'?",
    humanizer: "Rewrite this corporate message to sound warm and personal: 'Your request has been processed. Reference number: 12345.'",
    analysis: "Analyze the following statement and identify logical fallacies: 'Everyone uses this product, so it must be good.'",
    writing: "Write a professional email declining a job offer politely while leaving the door open for future opportunities."
};

// Expertise categories with weight
const EXPERTISE_CATEGORIES = ['coding', 'intelligence', 'logic', 'creativity', 'chat', 'humanizer', 'analysis', 'writing'];

class ModelMetricsService {
    constructor() {
        this.metrics = {};
        this.socketService = null;
        this.mcpService = null;
        this.benchmarkInterval = null;
        this.broadcastInterval = null;
        this.decayInterval = null; // Skill decay checker
        this.ensureDataDir();
        this.loadMetrics();
        this.startSkillDecayChecker(); // Start decay system
    }

    ensureDataDir() {
        const dataDir = path.join(__dirname, 'data');
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
        }
    }

    setSocketService(socketService) {
        this.socketService = socketService;
    }

    setMCPService(mcpService) {
        this.mcpService = mcpService;
    }

    loadMetrics() {
        try {
            if (fs.existsSync(METRICS_PATH)) {
                const data = fs.readFileSync(METRICS_PATH, 'utf8');
                this.metrics = JSON.parse(data);
                console.log('[MODEL_METRICS] Loaded metrics for', Object.keys(this.metrics).length, 'models');
            }
        } catch (error) {
            console.error('[MODEL_METRICS] Error loading metrics:', error.message);
            this.metrics = {};
        }
    }

    saveMetrics() {
        try {
            fs.writeFileSync(METRICS_PATH, JSON.stringify(this.metrics, null, 2));
        } catch (error) {
            console.error('[MODEL_METRICS] Error saving metrics:', error.message);
        }
    }

    /**
     * Initialize or get model metrics structure
     */
    getOrCreateModelMetrics(modelName) {
        if (!this.metrics[modelName]) {
            this.metrics[modelName] = {
                modelName,
                createdAt: new Date().toISOString(),
                performance: {
                    totalQueries: 0,
                    successfulQueries: 0,
                    failedQueries: 0,
                    avgResponseTime: 0,
                    minResponseTime: Infinity,
                    maxResponseTime: 0,
                    tokensPerSecond: 0,
                    totalTokensGenerated: 0
                },
                expertise: {
                    coding: { score: 50, samples: 0, lastUpdated: null },
                    intelligence: { score: 50, samples: 0, lastUpdated: null },
                    logic: { score: 50, samples: 0, lastUpdated: null },
                    creativity: { score: 50, samples: 0, lastUpdated: null },
                    chat: { score: 50, samples: 0, lastUpdated: null },
                    humanizer: { score: 50, samples: 0, lastUpdated: null },
                    analysis: { score: 50, samples: 0, lastUpdated: null },
                    writing: { score: 50, samples: 0, lastUpdated: null }
                },
                cognitive: {
                    overallScore: 50,
                    learningRate: 0,
                    consistency: 0,
                    adaptability: 0
                },
                learning: {
                    sessionsCompleted: 0,
                    improvementTrend: 0, // -1 to 1 (declining to improving)
                    lastSessionScore: 0,
                    averageSessionScore: 0,
                    peakScore: 0,
                    growthPercentage: 0
                },
                strengths: [],
                weaknesses: [],
                history: [],
                benchmarks: [],
                lastBenchmark: null,
                lastUpdated: new Date().toISOString()
            };
        }
        
        // Migration: Ensure existing models have new fields
        const model = this.metrics[modelName];
        if (!model.learning) {
            model.learning = {
                sessionsCompleted: model.performance?.totalQueries || 0,
                improvementTrend: 0,
                lastSessionScore: model.cognitive?.overallScore || 50,
                averageSessionScore: model.cognitive?.overallScore || 50,
                peakScore: model.cognitive?.overallScore || 50,
                growthPercentage: 0
            };
        }
        // Migrate old expertise categories to new ones
        if (model.expertise?.code && !model.expertise?.coding) {
            model.expertise.coding = model.expertise.code;
            delete model.expertise.code;
        }
        if (model.expertise?.reasoning && !model.expertise?.logic) {
            model.expertise.logic = model.expertise.reasoning;
            delete model.expertise.reasoning;
        }
        // Add missing expertise categories
        const defaultExpertise = { score: 50, samples: 0, lastUpdated: null };
        const requiredCategories = ['coding', 'intelligence', 'logic', 'creativity', 'chat', 'humanizer', 'analysis', 'writing'];
        for (const cat of requiredCategories) {
            if (!model.expertise[cat]) {
                model.expertise[cat] = { ...defaultExpertise };
            }
        }
        
        return this.metrics[modelName];
    }

    /**
     * Record a query response for tracking
     */
    recordQuery(modelName, options) {
        const {
            responseTime,
            tokensGenerated = 0,
            success = true,
            category = null,
            qualityScore = null
        } = options;

        const model = this.getOrCreateModelMetrics(modelName);
        const perf = model.performance;

        // Update performance metrics
        perf.totalQueries++;
        if (success) {
            perf.successfulQueries++;
        } else {
            perf.failedQueries++;
        }

        // Update response time stats
        const oldAvg = perf.avgResponseTime;
        perf.avgResponseTime = ((oldAvg * (perf.totalQueries - 1)) + responseTime) / perf.totalQueries;
        perf.minResponseTime = Math.min(perf.minResponseTime, responseTime);
        perf.maxResponseTime = Math.max(perf.maxResponseTime, responseTime);

        // Update tokens stats
        if (tokensGenerated > 0) {
            perf.totalTokensGenerated += tokensGenerated;
            perf.tokensPerSecond = tokensGenerated / (responseTime / 1000);
        }

        // Update expertise if category provided
        if (category && qualityScore !== null && EXPERTISE_CATEGORIES.includes(category)) {
            this.updateExpertise(modelName, category, qualityScore);
        }

        // Update cognitive score
        this.updateCognitiveScore(modelName);

        // Update strengths/weaknesses
        this.updateStrengthsWeaknesses(modelName);

        model.lastUpdated = new Date().toISOString();
        this.saveMetrics();

        return model;
    }

    /**
     * Update expertise score for a category
     */
    updateExpertise(modelName, category, score) {
        const model = this.getOrCreateModelMetrics(modelName);
        const exp = model.expertise[category];
        
        // Weighted average (new samples count more when fewer samples exist)
        const weight = Math.min(0.3, 1 / (exp.samples + 1));
        exp.score = exp.score * (1 - weight) + score * weight;
        exp.score = Math.max(0, Math.min(100, exp.score)); // Clamp 0-100
        exp.samples++;
        exp.lastUpdated = new Date().toISOString();
    }

    /**
     * Calculate overall cognitive score
     */
    updateCognitiveScore(modelName) {
        const model = this.getOrCreateModelMetrics(modelName);
        const exp = model.expertise;
        
        // Weighted average of expertise scores
        const weights = { coding: 1.2, intelligence: 1.1, logic: 1.3, creativity: 0.9, chat: 0.8, humanizer: 1.0, analysis: 1.1, writing: 1.0 };
        let totalWeight = 0;
        let weightedSum = 0;

        for (const cat of EXPERTISE_CATEGORIES) {
            weightedSum += exp[cat].score * weights[cat];
            totalWeight += weights[cat];
        }

        const newScore = weightedSum / totalWeight;
        
        // Calculate learning rate (trend over last 10 records)
        const history = model.history.slice(-10);
        if (history.length >= 2) {
            const firstScore = history[0].cognitiveScore;
            const lastScore = history[history.length - 1].cognitiveScore;
            model.cognitive.learningRate = ((lastScore - firstScore) / history.length) / 100;
        }

        // Update consistency (standard deviation of recent scores)
        if (history.length >= 5) {
            const scores = history.map(h => h.cognitiveScore);
            const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
            const variance = scores.reduce((acc, s) => acc + Math.pow(s - avg, 2), 0) / scores.length;
            model.cognitive.consistency = Math.max(0, 100 - Math.sqrt(variance) * 10);
        }

        model.cognitive.overallScore = Math.round(newScore * 10) / 10;

        // Add to history (keep 3 months = ~2160 records at hourly rate)
        const now = new Date();
        model.history.push({
            date: now.toISOString(),
            cognitiveScore: model.cognitive.overallScore,
            expertise: { ...Object.fromEntries(EXPERTISE_CATEGORIES.map(c => [c, exp[c].score])) }
        });

        // Prune history older than 3 months
        const threeMonthsAgo = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
        model.history = model.history.filter(h => new Date(h.date) > threeMonthsAgo);
        
        // Track last activity for decay system
        model.lastActivity = now.toISOString();
    }

    /**
     * SKILL DECAY SYSTEM
     * After 3 days of inactivity, expertise scores slowly decrease
     * Like human learning - skills need regular practice to maintain
     */
    applySkillDecay(modelName) {
        const model = this.metrics[modelName];
        if (!model) return;

        const now = new Date();
        const lastActivity = model.lastActivity ? new Date(model.lastActivity) : new Date(model.lastUpdated);
        const daysSinceActivity = (now - lastActivity) / (1000 * 60 * 60 * 24);

        // Only apply decay after 3 days of inactivity
        if (daysSinceActivity < 3) return;

        // Calculate decay amount (0.5% per day after 3 days, max 2% per check)
        const daysOverThreshold = daysSinceActivity - 3;
        const decayRate = Math.min(0.02, daysOverThreshold * 0.005);

        let decayApplied = false;

        // Apply decay to each expertise category
        for (const category of EXPERTISE_CATEGORIES) {
            const exp = model.expertise[category];
            if (exp && exp.score > 30) { // Don't decay below 30 (baseline)
                const oldScore = exp.score;
                exp.score = Math.max(30, exp.score * (1 - decayRate));
                
                if (oldScore !== exp.score) {
                    decayApplied = true;
                }
            }
        }

        if (decayApplied) {
            // Recalculate cognitive score
            this.recalculateCognitiveScore(modelName);
            
            // Add decay event to history
            model.history.push({
                date: now.toISOString(),
                cognitiveScore: model.cognitive.overallScore,
                event: 'skill_decay',
                daysSinceActivity: Math.round(daysSinceActivity)
            });

            model.decayAppliedAt = now.toISOString();
            this.saveMetrics();

            console.log(`[MODEL_METRICS] Skill decay applied to ${modelName} (${Math.round(daysSinceActivity)} days inactive)`);
        }
    }

    /**
     * Recalculate cognitive score without adding to history
     */
    recalculateCognitiveScore(modelName) {
        const model = this.metrics[modelName];
        const exp = model.expertise;
        
        const weights = { coding: 1.2, intelligence: 1.1, logic: 1.3, creativity: 0.9, chat: 0.8, humanizer: 1.0, analysis: 1.1, writing: 1.0 };
        let totalWeight = 0;
        let weightedSum = 0;

        for (const cat of EXPERTISE_CATEGORIES) {
            weightedSum += exp[cat].score * weights[cat];
            totalWeight += weights[cat];
        }

        model.cognitive.overallScore = Math.round((weightedSum / totalWeight) * 10) / 10;
    }

    /**
     * Start the skill decay checker (runs every 6 hours)
     */
    startSkillDecayChecker() {
        this.decayInterval = setInterval(() => {
            for (const modelName of Object.keys(this.metrics)) {
                this.applySkillDecay(modelName);
            }
        }, 6 * 60 * 60 * 1000); // Every 6 hours

        // Also run once on startup after 30 seconds
        setTimeout(() => {
            for (const modelName of Object.keys(this.metrics)) {
                this.applySkillDecay(modelName);
            }
        }, 30000);

        console.log('[MODEL_METRICS] Skill decay checker started (decay after 3 days inactive)');
    }

    /**
     * Identify strengths and weaknesses
     */
    updateStrengthsWeaknesses(modelName) {
        const model = this.getOrCreateModelMetrics(modelName);
        const exp = model.expertise;
        
        const sorted = EXPERTISE_CATEGORIES
            .map(cat => ({ category: cat, score: exp[cat].score }))
            .sort((a, b) => b.score - a.score);

        // Top 2 are strengths, bottom 2 are weaknesses
        model.strengths = sorted.slice(0, 2).filter(s => s.score >= 60).map(s => ({
            category: s.category,
            score: Math.round(s.score),
            label: this.getCategoryLabel(s.category)
        }));

        model.weaknesses = sorted.slice(-2).filter(s => s.score < 60).map(s => ({
            category: s.category,
            score: Math.round(s.score),
            label: this.getCategoryLabel(s.category)
        }));
    }

    getCategoryLabel(category) {
        const labels = {
            code: '💻 Code',
            writing: '✍️ Rédaction',
            analysis: '🔍 Analyse',
            creativity: '🎨 Créativité',
            reasoning: '🧠 Raisonnement'
        };
        return labels[category] || category;
    }

    /**
     * Run benchmark on a specific model
     */
    async runBenchmark(modelName, llmService) {
        // Skip invalid model names (e.g., AnythingLLM workspaces are not real Ollama models)
        if (!modelName || modelName.includes('[ANYTHINGLLM]') || !modelName.includes(':')) {
            console.log(`[MODEL_METRICS] Skipping benchmark for non-Ollama model: ${modelName}`);
            return null;
        }
        
        console.log(`[MODEL_METRICS] Running benchmark for ${modelName}...`);
        
        const model = this.getOrCreateModelMetrics(modelName);
        const results = {};

        for (const [category, prompt] of Object.entries(BENCHMARK_PROMPTS)) {
            try {
                const startTime = Date.now();
                const response = await llmService.generateOllamaResponse(prompt, null, modelName, 
                    "You are being benchmarked. Provide the best possible answer.");
                const responseTime = Date.now() - startTime;

                // Simple quality scoring based on response length and keywords
                const qualityScore = this.evaluateResponse(category, response, responseTime);
                
                results[category] = {
                    responseTime,
                    qualityScore,
                    responseLength: response?.length || 0
                };

                // Record the query
                this.recordQuery(modelName, {
                    responseTime,
                    tokensGenerated: Math.floor((response?.length || 0) / 4),
                    success: true,
                    category,
                    qualityScore
                });

            } catch (error) {
                console.error(`[MODEL_METRICS] Benchmark ${category} failed:`, error.message);
                results[category] = { error: error.message, qualityScore: 0 };
            }
        }

        // Store benchmark results
        model.benchmarks.push({
            date: new Date().toISOString(),
            results,
            overallScore: model.cognitive.overallScore
        });

        // Keep only last 30 days of benchmarks
        const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        model.benchmarks = model.benchmarks.filter(b => new Date(b.date) > thirtyDaysAgo);

        model.lastBenchmark = new Date().toISOString();
        this.saveMetrics();

        // Persist to long-term memory via MCP/Pieces if available
        await this.persistToLongTermMemory(modelName, model);

        return results;
    }

    /**
     * Evaluate response quality (simple heuristic)
     */
    evaluateResponse(category, response, responseTime) {
        if (!response) return 0;

        let score = 50; // Base score

        // Length factor (not too short, not too long)
        const idealLength = { code: 500, writing: 400, analysis: 300, creativity: 200, reasoning: 250 };
        const lengthDiff = Math.abs(response.length - idealLength[category]) / idealLength[category];
        score += Math.max(0, 20 - lengthDiff * 20);

        // Response time factor (faster is better, but not too fast)
        if (responseTime < 1000) score += 10;
        else if (responseTime < 3000) score += 5;
        else if (responseTime > 10000) score -= 10;

        // Category-specific checks
        if (category === 'code' && (response.includes('function') || response.includes('const') || response.includes('let'))) {
            score += 15;
        }
        if (category === 'reasoning' && response.toLowerCase().includes('therefore')) {
            score += 10;
        }
        if (category === 'analysis' && response.toLowerCase().includes('fallacy')) {
            score += 15;
        }

        return Math.max(0, Math.min(100, score));
    }

    /**
     * Persist metrics to AnythingLLM/Pieces for long-term storage
     */
    async persistToLongTermMemory(modelName, modelData) {
        // Check if MCP service is available AND has saveToMemory method
        if (this.mcpService && typeof this.mcpService.saveToMemory === 'function') {
            try {
                const memoryEntry = {
                    type: 'model_training_metrics',
                    modelName,
                    date: new Date().toISOString(),
                    cognitiveScore: modelData.cognitive.overallScore,
                    expertise: modelData.expertise,
                    strengths: modelData.strengths,
                    weaknesses: modelData.weaknesses
                };

                await this.mcpService.saveToMemory({
                    content: JSON.stringify(memoryEntry),
                    metadata: { type: 'model_metrics', model: modelName }
                });

                console.log(`[MODEL_METRICS] Persisted ${modelName} metrics to long-term memory`);
            } catch (error) {
                // Silently skip - this is optional functionality
            }
        }
        // No else needed - long-term persistence is optional
    }

    /**
     * Get all metrics for dashboard
     */
    /**
     * Delete metrics for a specific model
     */
    deleteModelMetrics(modelName) {
        if (this.metrics[modelName]) {
            delete this.metrics[modelName];
            this.saveMetrics();
            console.log('[METRICS] Deleted metrics for: ' + modelName);
            return true;
        }
        return false;
    }

    getAllMetrics() {
        const result = {};
        for (const [name, data] of Object.entries(this.metrics)) {
            result[name] = {
                modelName: data.modelName,
                performance: data.performance,
                expertise: Object.fromEntries(
                    EXPERTISE_CATEGORIES.map(c => [c, data.expertise[c].score])
                ),
                cognitive: data.cognitive,
                strengths: data.strengths,
                weaknesses: data.weaknesses,
                lastBenchmark: data.lastBenchmark,
                lastUpdated: data.lastUpdated,
                historyLast7Days: data.history.slice(-168) // Last 7 days at hourly
            };
        }
        return result;
    }

    /**
     * Get metrics for a specific model
     */
    getModelMetrics(modelName) {
        return this.metrics[modelName] || null;
    }

    /**
     * Start automatic broadcasting every 5 seconds
     */
    startBroadcast() {
        if (this.broadcastInterval) return;

        this.broadcastInterval = setInterval(() => {
            if (this.socketService) {
                const metrics = this.getAllMetrics();
                this.socketService.emit('model:metrics:update', metrics);
            }
        }, 5000); // 5 seconds

        console.log('[MODEL_METRICS] Started 5-second broadcast');
    }

    /**
     * Start hourly benchmarks
     */
    startHourlyBenchmarks(llmService) {
        if (this.benchmarkInterval) return;

        // Run benchmark every hour
        this.benchmarkInterval = setInterval(async () => {
            console.log('[MODEL_METRICS] Running hourly benchmarks...');
            
            // Get available Ollama models
            try {
                const models = await llmService.ollama.list();
                for (const model of models.models || []) {
                    const modelName = model.name;
                    if (modelName && !modelName.includes('embed')) {
                        await this.runBenchmark(modelName, llmService);
                    }
                }
            } catch (error) {
                console.error('[MODEL_METRICS] Hourly benchmark failed:', error.message);
            }
        }, 60 * 60 * 1000); // 1 hour

        console.log('[MODEL_METRICS] Started hourly benchmark scheduler');

        // Run initial benchmark after 10 seconds
        setTimeout(async () => {
            try {
                const models = await llmService.ollama.list();
                if (models.models && models.models.length > 0) {
                    const firstModel = models.models[0].name;
                    if (firstModel && !firstModel.includes('embed')) {
                        await this.runBenchmark(firstModel, llmService);
                    }
                }
            } catch (error) {
                console.log('[MODEL_METRICS] Initial benchmark skipped:', error.message);
            }
        }, 10000);
    }

    /**
     * Stop all intervals
     */
    stop() {
        if (this.broadcastInterval) {
            clearInterval(this.broadcastInterval);
            this.broadcastInterval = null;
        }
        if (this.benchmarkInterval) {
            clearInterval(this.benchmarkInterval);
            this.benchmarkInterval = null;
        }
        if (this.decayInterval) {
            clearInterval(this.decayInterval);
            this.decayInterval = null;
        }
        console.log('[MODEL_METRICS] Service stopped');
    }
}

module.exports = ModelMetricsService;



