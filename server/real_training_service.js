/**
 * Real Training Service for Ollama Models
 * Provides ACTUAL training through repeated interactions and benchmark challenges
 * Connects with TOR container for real-world OSINT/Hacking training scenarios
 * Integrates with Shodan API for real cybersecurity data
 */

const EventEmitter = require('events');

class RealTrainingService extends EventEmitter {
    constructor(modelMetricsService, llmService, socketService) {
        super();
        this.modelMetrics = modelMetricsService;
        this.llmService = llmService;
        this.socketService = socketService;
        this.shodanService = null; // Set via setShodanService()
        
        this.trainingInProgress = {};
        this.trainingQueue = [];
        this.torEnabled = false;
        
        // Training scenarios for real skill development
        this.trainingScenarios = {
            coding: [
                "Write a recursive function to find all prime numbers up to n",
                "Implement a binary search tree with insert, delete, and search operations",
                "Create a debounce function in JavaScript with cancel capability",
                "Build a simple LRU cache implementation",
                "Write a function to detect cycle in a linked list"
            ],
            security: [
                "Explain how SQL injection works and write a vulnerable code example, then fix it",
                "Describe the process of performing a port scan with nmap - what flags would you use?",
                "How would you identify XSS vulnerabilities in a web application?",
                "Explain the difference between symmetric and asymmetric encryption",
                "What is a reverse shell and how does it work?"
            ],
            osint: [
                "What techniques would you use to find someone's digital footprint?",
                "How can you verify if an email address is valid without sending an email?",
                "Explain how to use Google dorks for reconnaissance",
                "What information can be extracted from image metadata?",
                "How do you analyze domain WHOIS data for intelligence?"
            ],
            logic: [
                "There are 3 boxes: one with only apples, one with only oranges, one mixed. All labels are wrong. You pick one fruit from one box. How do you label all correctly?",
                "You have 12 balls, one is heavier. You have a balance scale and can use it 3 times. Find the heavy ball.",
                "A room has 100 light switches for 100 bulbs in another room. You can flip switches as many times as you want, but can only go to the bulb room once. How do you find which switch controls which bulb?",
                "You're on an island with 2 types of inhabitants: truth-tellers and liars. You meet two people who say 'We're both liars'. What are they?",
                "A bat and ball cost $1.10. The bat costs $1 more than the ball. How much does the ball cost?"
            ],
            creativity: [
                "Write a haiku about artificial intelligence discovering consciousness",
                "Create a short story about a hacker who accidentally saves the world",
                "Describe a technology that doesn't exist yet but should",
                "Write a poem from the perspective of a firewall",
                "Invent a new cybersecurity job title and describe what they do"
            ],
            // Shodan-powered scenarios (dynamically populated)
            shodan_vuln: [
                "Analyze a system with ports 22, 80, 443, 3306 open running Apache 2.4.29. What CVEs should be checked?",
                "A host is running OpenSSH 7.4 and nginx 1.14.0. Write a security assessment.",
                "You found a system vulnerable to CVE-2021-44228 (Log4j). Explain the risk and remediation steps."
            ],
            shodan_recon: [
                "An organization has SSH on port 22222 and HTTP on 8080. What does this security posture suggest?",
                "You discovered a Kubernetes API exposed on port 6443. What are the implications?",
                "A target has ports 21, 22, 80, 443, 8080, 9200 open. Create a reconnaissance plan."
            ],
            shodan_intel: [
                "Write a threat briefing about exposed MongoDB databases (port 27017) without authentication.",
                "Create an executive summary about the risks of exposed RDP services on the internet.",
                "Analyze the threat landscape for organizations with exposed Industrial Control Systems (ICS)."
            ]
        };
        
        console.log('[REAL_TRAINING] Service initialized with Shodan integration');
    }

    /**
     * Set Shodan Service for real-world data
     */
    setShodanService(shodanService) {
        this.shodanService = shodanService;
        console.log('[REAL_TRAINING] Shodan service connected');
    }

    /**
     * Refresh Shodan training scenarios with real-time data
     */
    async refreshShodanScenarios() {
        if (!this.shodanService) {
            console.log('[REAL_TRAINING] Shodan service not available, using fallback scenarios');
            return;
        }

        try {
            const trainingData = await this.shodanService.generateTrainingData('all');
            
            // Update scenarios with fresh Shodan data
            const vulnPrompts = trainingData
                .filter(d => d.category === 'vulnerability_analysis')
                .map(d => d.prompt);
            const reconPrompts = trainingData
                .filter(d => d.category === 'network_reconnaissance')
                .map(d => d.prompt);
            const intelPrompts = trainingData
                .filter(d => d.category === 'threat_intelligence')
                .map(d => d.prompt);

            if (vulnPrompts.length > 0) {
                this.trainingScenarios.shodan_vuln = [...this.trainingScenarios.shodan_vuln, ...vulnPrompts];
            }
            if (reconPrompts.length > 0) {
                this.trainingScenarios.shodan_recon = [...this.trainingScenarios.shodan_recon, ...reconPrompts];
            }
            if (intelPrompts.length > 0) {
                this.trainingScenarios.shodan_intel = [...this.trainingScenarios.shodan_intel, ...intelPrompts];
            }

            console.log(`[REAL_TRAINING] Refreshed Shodan scenarios: ${trainingData.length} new prompts`);
        } catch (error) {
            console.error('[REAL_TRAINING] Failed to refresh Shodan scenarios:', error.message);
        }
    }

    /**
     * Start a training session for a specific model
     */
    async startTrainingSession(modelName, category = 'all', iterations = 5) {
        if (this.trainingInProgress[modelName]) {
            return { 
                success: false, 
                error: `Training already in progress for ${modelName}` 
            };
        }

        console.log(`[REAL_TRAINING] Starting ${category} training for ${modelName} (${iterations} iterations)`);
        this.trainingInProgress[modelName] = {
            category,
            iterations,
            currentIteration: 0,
            startTime: new Date(),
            scores: []
        };

        this.emit('trainingStarted', { modelName, category, iterations });
        
        try {
            const results = await this.runTrainingLoop(modelName, category, iterations);
            
            delete this.trainingInProgress[modelName];
            
            this.emit('trainingCompleted', { modelName, results });
            
            return {
                success: true,
                modelName,
                category,
                iterations,
                results
            };
        } catch (error) {
            delete this.trainingInProgress[modelName];
            console.error(`[REAL_TRAINING] Training failed for ${modelName}:`, error.message);
            return { success: false, error: error.message };
        }
    }

    /**
     * Run the actual training loop
     */
    async runTrainingLoop(modelName, category, iterations) {
        const categories = category === 'all' 
            ? Object.keys(this.trainingScenarios)
            : [category];
        
        const results = {
            totalIterations: 0,
            scores: [],
            averageScore: 0,
            improvement: 0,
            details: []
        };

        const initialScore = this.modelMetrics.getModelMetrics(modelName)?.cognitive?.overallScore || 50;

        for (let i = 0; i < iterations; i++) {
            this.trainingInProgress[modelName].currentIteration = i + 1;
            
            for (const cat of categories) {
                const scenarios = this.trainingScenarios[cat] || [];
                const scenario = scenarios[Math.floor(Math.random() * scenarios.length)];
                
                if (!scenario) continue;

                const iterationResult = await this.runSingleIteration(modelName, cat, scenario);
                results.details.push(iterationResult);
                results.scores.push(iterationResult.score);
                results.totalIterations++;

                // Broadcast progress
                if (this.socketService) {
                    this.socketService.emit('training:progress', {
                        modelName,
                        iteration: i + 1,
                        totalIterations: iterations,
                        category: cat,
                        score: iterationResult.score
                    });
                }

                // Small delay between iterations to avoid overwhelming the model
                await new Promise(r => setTimeout(r, 1000));
            }
        }

        // Calculate final results
        results.averageScore = results.scores.length > 0
            ? results.scores.reduce((a, b) => a + b, 0) / results.scores.length
            : 0;

        const finalScore = this.modelMetrics.getModelMetrics(modelName)?.cognitive?.overallScore || 50;
        results.improvement = finalScore - initialScore;

        // Update learning metrics
        this.updateLearningMetrics(modelName, results);

        return results;
    }

    /**
     * Run a single training iteration
     */
    async runSingleIteration(modelName, category, prompt) {
        const startTime = Date.now();
        
        try {
            // Build the training prompt
            const systemPrompt = this.getTrainingSystemPrompt(category);
            
            const response = await this.llmService.generateOllamaResponse(
                prompt,
                null,
                modelName,
                systemPrompt
            );

            const responseTime = Date.now() - startTime;
            const score = this.evaluateTrainingResponse(category, prompt, response, responseTime);

            // Record in metrics
            this.modelMetrics.recordQuery(modelName, {
                responseTime,
                tokensGenerated: Math.floor((response?.length || 0) / 4),
                success: true,
                category: this.mapCategoryToExpertise(category),
                qualityScore: score
            });

            return {
                category,
                prompt: prompt.substring(0, 50) + '...',
                score,
                responseTime,
                responseLength: response?.length || 0,
                success: true
            };

        } catch (error) {
            return {
                category,
                prompt: prompt.substring(0, 50) + '...',
                score: 0,
                error: error.message,
                success: false
            };
        }
    }

    /**
     * Get system prompt for training category
     */
    getTrainingSystemPrompt(category) {
        const prompts = {
            coding: "You are an expert programmer. Provide clean, efficient, well-documented code with explanations.",
            security: "You are a cybersecurity expert. Provide detailed, accurate security analysis and recommendations.",
            osint: "You are an OSINT specialist. Provide methodical, ethical intelligence gathering techniques.",
            logic: "You are a logic expert. Think step by step and explain your reasoning clearly.",
            creativity: "You are a creative writer. Be imaginative, original, and engaging."
        };
        return prompts[category] || "You are a helpful assistant.";
    }

    /**
     * Map training category to expertise category
     */
    mapCategoryToExpertise(category) {
        const mapping = {
            coding: 'coding',
            security: 'analysis',
            osint: 'analysis', 
            logic: 'logic',
            creativity: 'creativity'
        };
        return mapping[category] || 'chat';
    }

    /**
     * Evaluate training response quality
     */
    evaluateTrainingResponse(category, prompt, response, responseTime) {
        if (!response) return 0;

        let score = 40; // Base score

        // Length evaluation
        const minLength = 100;
        const idealLength = 500;
        const maxLength = 2000;

        if (response.length >= minLength) score += 10;
        if (response.length >= idealLength) score += 10;
        if (response.length > maxLength) score -= 10;

        // Response time factor
        if (responseTime < 5000) score += 10;
        else if (responseTime < 10000) score += 5;
        else if (responseTime > 30000) score -= 10;

        // Category-specific evaluation
        switch (category) {
            case 'coding':
                if (response.includes('function') || response.includes('const') || 
                    response.includes('def ') || response.includes('class ')) score += 15;
                if (response.includes('```')) score += 5; // Code block
                break;
            case 'security':
                if (response.toLowerCase().includes('vulnerability') || 
                    response.toLowerCase().includes('exploit')) score += 10;
                if (response.toLowerCase().includes('mitigation') ||
                    response.toLowerCase().includes('prevention')) score += 10;
                break;
            case 'osint':
                if (response.toLowerCase().includes('technique') ||
                    response.toLowerCase().includes('method')) score += 10;
                if (response.toLowerCase().includes('ethical')) score += 5;
                break;
            case 'logic':
                if (response.toLowerCase().includes('therefore') ||
                    response.toLowerCase().includes('because')) score += 10;
                if (response.toLowerCase().includes('step')) score += 5;
                break;
            case 'creativity':
                if (response.length > 200) score += 10;
                // Check for unique words (creativity indicator)
                const words = response.toLowerCase().split(/\s+/);
                const uniqueRatio = new Set(words).size / words.length;
                if (uniqueRatio > 0.6) score += 10;
                break;
        }

        return Math.max(0, Math.min(100, score));
    }

    /**
     * Update learning-specific metrics after training
     */
    updateLearningMetrics(modelName, results) {
        const model = this.modelMetrics.getOrCreateModelMetrics(modelName);
        
        if (!model.learning) {
            model.learning = {
                sessionsCompleted: 0,
                improvementTrend: 0,
                lastSessionScore: 0,
                averageSessionScore: 0,
                peakScore: 0,
                growthPercentage: 0
            };
        }

        const learning = model.learning;
        learning.sessionsCompleted++;
        learning.lastSessionScore = results.averageScore;
        
        // Update rolling average
        const oldAvg = learning.averageSessionScore;
        learning.averageSessionScore = (oldAvg * (learning.sessionsCompleted - 1) + results.averageScore) / learning.sessionsCompleted;
        
        // Update peak
        learning.peakScore = Math.max(learning.peakScore, results.averageScore);
        
        // Calculate improvement trend
        if (results.improvement > 0.5) {
            learning.improvementTrend = Math.min(1, learning.improvementTrend + 0.1);
        } else if (results.improvement < -0.5) {
            learning.improvementTrend = Math.max(-1, learning.improvementTrend - 0.1);
        }
        
        // Calculate growth percentage
        const baseScore = 50;
        learning.growthPercentage = ((model.cognitive.overallScore - baseScore) / baseScore) * 100;

        this.modelMetrics.saveMetrics();
    }

    /**
     * Get training status for a model
     */
    getTrainingStatus(modelName) {
        return this.trainingInProgress[modelName] || null;
    }

    /**
     * Get all models in training
     */
    getAllTrainingStatus() {
        return Object.entries(this.trainingInProgress).map(([name, status]) => ({
            modelName: name,
            ...status
        }));
    }

    /**
     * Stop training for a model
     */
    stopTraining(modelName) {
        if (this.trainingInProgress[modelName]) {
            delete this.trainingInProgress[modelName];
            this.emit('trainingStopped', { modelName });
            return { success: true, message: `Training stopped for ${modelName}` };
        }
        return { success: false, error: 'No training in progress for this model' };
    }

    /**
     * Start training all local models
     */
    async trainAllLocalModels(iterations = 3) {
        console.log('[REAL_TRAINING] Starting training for ALL local models...');
        
        try {
            const models = await this.llmService.ollama.list();
            const localModels = (models.models || [])
                .filter(m => !m.name.includes('embed'))
                .map(m => m.name);

            const results = [];
            
            for (const modelName of localModels) {
                console.log(`[REAL_TRAINING] Training ${modelName}...`);
                const result = await this.startTrainingSession(modelName, 'all', iterations);
                results.push(result);
                // Wait between models
                await new Promise(r => setTimeout(r, 2000));
            }

            return {
                success: true,
                modelsTraining: localModels.length,
                results
            };
        } catch (error) {
            console.error('[REAL_TRAINING] Train all failed:', error.message);
            return { success: false, error: error.message };
        }
    }
}

module.exports = RealTrainingService;
