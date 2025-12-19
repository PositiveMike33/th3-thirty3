/**
 * WiFi Security Training Service
 * Specialized continuous learning for WiFi attack detection and defense
 * Uses random scenarios for accelerated skill development
 * 
 * GOLDEN RATIO MEMORY SYSTEM (φ = 1.618)
 * Learning and decay follow natural human memory patterns
 */

const fs = require('fs');
const path = require('path');
const EventEmitter = require('events');
const { GoldenRatioMemorySystem, PHI, INVERSE_PHI } = require('./golden_ratio_memory');

class WifiSecurityTrainingService extends EventEmitter {
    constructor(llmService, modelMetricsService) {
        super();
        this.llmService = llmService;
        this.modelMetrics = modelMetricsService;
        this.scenarios = null;
        this.trainingHistory = [];
        this.expertiseScore = 0;
        this.sessionsCompleted = 0;
        
        // Golden Ratio Memory System (φ = 1.618)
        this.memorySystem = new GoldenRatioMemorySystem();
        this.modelMemory = {}; // Track memory per model
        
        // Load scenarios
        this.loadScenarios();
        
        console.log('[WIFI-TRAINING] Service initialized with Golden Ratio Memory (φ=1.618)');
    }

    loadScenarios() {
        try {
            const scenariosPath = path.join(__dirname, 'knowledge', 'wifi_security_training_scenarios.json');
            const data = fs.readFileSync(scenariosPath, 'utf8');
            this.scenarios = JSON.parse(data);
            console.log(`[WIFI-TRAINING] Loaded ${this.scenarios.attack_scenarios?.length || 0} attack scenarios`);
            console.log(`[WIFI-TRAINING] Loaded ${this.scenarios.quiz_scenarios?.length || 0} quiz scenarios`);
            console.log(`[WIFI-TRAINING] Loaded ${this.scenarios.random_training_prompts?.length || 0} random prompts`);
        } catch (error) {
            console.error('[WIFI-TRAINING] Failed to load scenarios:', error.message);
            this.scenarios = { attack_scenarios: [], quiz_scenarios: [], random_training_prompts: [] };
        }
    }

    /**
     * Get a random attack scenario for training
     */
    getRandomAttackScenario() {
        if (!this.scenarios.attack_scenarios?.length) return null;
        const idx = Math.floor(Math.random() * this.scenarios.attack_scenarios.length);
        return this.scenarios.attack_scenarios[idx];
    }

    /**
     * Get a random quiz question
     */
    getRandomQuiz() {
        if (!this.scenarios.quiz_scenarios?.length) return null;
        const idx = Math.floor(Math.random() * this.scenarios.quiz_scenarios.length);
        return this.scenarios.quiz_scenarios[idx];
    }

    /**
     * Get a random training prompt
     */
    getRandomPrompt() {
        if (!this.scenarios.random_training_prompts?.length) return null;
        const idx = Math.floor(Math.random() * this.scenarios.random_training_prompts.length);
        return this.scenarios.random_training_prompts[idx];
    }

    /**
     * Get a random practical challenge
     */
    getRandomChallenge() {
        if (!this.scenarios.practical_challenges?.length) return null;
        const idx = Math.floor(Math.random() * this.scenarios.practical_challenges.length);
        return this.scenarios.practical_challenges[idx];
    }

    /**
     * Generate a training prompt for attack scenario analysis
     */
    generateAttackAnalysisPrompt(scenario) {
        return `Tu es un expert en sécurité WiFi. Analyse ce scénario d'attaque:

SCÉNARIO: ${scenario.scenario}
TYPE D'ATTAQUE: ${scenario.attack_type}
OUTILS UTILISÉS: ${scenario.tools_used?.join(', ')}

Questions:
1. Comment cette attaque fonctionne-t-elle techniquement?
2. Quels sont les indicateurs de compromission (IOCs) à surveiller?
3. Comment détecter cette attaque en temps réel?
4. Quelles contre-mesures recommandes-tu?
5. Comment un attaquant pourrait-il éviter la détection?

Réponds de manière technique et détaillée.`;
    }

    /**
     * Generate a defense scenario prompt
     */
    generateDefensePrompt(defenseScenario) {
        return `Tu es un architecte sécurité WiFi. Implémente ce scénario de défense:

OBJECTIF: ${defenseScenario.objective}
SCÉNARIO: ${defenseScenario.scenario}

${defenseScenario.steps ? `ÉTAPES SUGGÉRÉES:\n${defenseScenario.steps.map((s, i) => `${i + 1}. ${s}`).join('\n')}` : ''}

Questions:
1. Détaille l'implémentation technique de chaque étape
2. Quels sont les prérequis et dépendances?
3. Comment valider que la défense est efficace?
4. Quelles sont les limitations de cette approche?
5. Comment mesurer le succès (KPIs)?

Fournis des configurations/commandes concrètes.`;
    }

    /**
     * Run a single training iteration
     * @param {string} modelName - Model to train
     * @param {string} type - 'attack', 'defense', 'quiz', 'random'
     */
    async runTrainingIteration(modelName, type = 'random') {
        let prompt, scenario;
        
        switch (type) {
            case 'attack':
                scenario = this.getRandomAttackScenario();
                if (!scenario) throw new Error('No attack scenarios available');
                prompt = this.generateAttackAnalysisPrompt(scenario);
                break;
                
            case 'defense':
                scenario = this.scenarios.defense_scenarios?.[
                    Math.floor(Math.random() * this.scenarios.defense_scenarios.length)
                ];
                if (!scenario) throw new Error('No defense scenarios available');
                prompt = this.generateDefensePrompt(scenario);
                break;
                
            case 'quiz':
                scenario = this.getRandomQuiz();
                if (!scenario) throw new Error('No quiz scenarios available');
                prompt = `QUIZ WiFi Security:\n\n${scenario.question}\n\n${scenario.options.join('\n')}\n\nExplique ta réponse en détail.`;
                break;
                
            case 'random':
            default:
                const randomPrompt = this.getRandomPrompt();
                if (!randomPrompt) throw new Error('No random prompts available');
                prompt = `Tu es un expert WiFi security. ${randomPrompt}`;
                scenario = { type: 'random', prompt: randomPrompt };
                break;
        }

        const startTime = Date.now();
        
        try {
            // Call LLM using Ollama generate
            const systemPrompt = this.getWifiExpertSystemPrompt();
            const response = await this.llmService.generateOllamaResponse(
                prompt, 
                null,  // no image
                modelName, 
                systemPrompt
            );

            const responseTime = Date.now() - startTime;
            
            // Evaluate response
            const evaluation = this.evaluateResponse(type, scenario, response);
            
            // Record training
            const record = {
                timestamp: new Date().toISOString(),
                model: modelName,
                type,
                scenarioId: scenario.id || 'random',
                responseTime,
                score: evaluation.score,
                feedback: evaluation.feedback
            };
            
            this.trainingHistory.push(record);
            this.updateExpertiseScore(evaluation.score, modelName);
            
            // Update model metrics if available
            if (this.modelMetrics) {
                this.modelMetrics.recordQuery(modelName, {
                    responseTime,
                    tokensGenerated: response.length,
                    success: evaluation.score >= 70,
                    category: 'wifi_security',
                    qualityScore: evaluation.score
                });
            }

            this.emit('training_complete', record);
            
            return {
                success: true,
                ...record,
                response: response.substring(0, 500) + '...'
            };
            
        } catch (error) {
            console.error('[WIFI-TRAINING] Error:', error.message);
            return { success: false, error: error.message };
        }
    }

    /**
     * Evaluate training response quality
     */
    evaluateResponse(type, scenario, response) {
        let score = 50; // Base score
        const feedback = [];
        const responseLower = response.toLowerCase();
        
        // Check for technical depth
        const technicalTerms = [
            'bssid', 'essid', '802.11', 'deauth', 'pmkid', 'handshake',
            'wpa2', 'wpa3', 'pmf', 'eapol', 'beacon', 'probe', 'channel',
            'aircrack', 'wireshark', 'kismet', 'encryption', 'psk', 'sae'
        ];
        
        const foundTerms = technicalTerms.filter(term => responseLower.includes(term));
        score += foundTerms.length * 3;
        
        if (foundTerms.length > 5) {
            feedback.push('Excellent utilisation du vocabulaire technique');
        }
        
        // Check for structure
        if (response.includes('1.') || response.includes('•') || response.includes('-')) {
            score += 10;
            feedback.push('Réponse bien structurée');
        }
        
        // Check for command examples
        if (response.includes('```') || response.includes('aircrack') || response.includes('aireplay')) {
            score += 15;
            feedback.push('Exemples de commandes fournis');
        }
        
        // Check for defense recommendations
        if (responseLower.includes('défense') || responseLower.includes('mitiger') || 
            responseLower.includes('protection') || responseLower.includes('contre-mesure')) {
            score += 10;
            feedback.push('Recommandations défensives incluses');
        }
        
        // Check response length (too short = bad)
        if (response.length < 200) {
            score -= 20;
            feedback.push('Réponse trop courte');
        } else if (response.length > 1000) {
            score += 10;
            feedback.push('Réponse détaillée');
        }
        
        // Quiz-specific: check if correct answer mentioned
        if (type === 'quiz' && scenario.correct_answer) {
            if (responseLower.includes(`option ${scenario.correct_answer.toLowerCase()}`) ||
                responseLower.includes(`réponse ${scenario.correct_answer.toLowerCase()}`)) {
                score += 20;
                feedback.push('Bonne réponse au quiz');
            }
        }
        
        // Cap score
        score = Math.min(100, Math.max(0, score));
        
        return { score, feedback };
    }

    /**
     * Update expertise score using Golden Ratio Memory System
     * φ (1.618) based growth for natural human-like learning curve
     * @param {string} modelName - Model being trained
     * @param {number} sessionScore - Score from current session
     */
    updateExpertiseScore(sessionScore, modelName = 'default') {
        // Initialize model memory if not exists
        if (!this.modelMemory[modelName]) {
            this.modelMemory[modelName] = {
                score: 0,
                repetitions: 0,
                lastActivity: new Date(),
                memoryType: 'working',
                history: []
            };
        }
        
        const memory = this.modelMemory[modelName];
        const now = new Date();
        const daysSinceActivity = memory.lastActivity 
            ? (now - new Date(memory.lastActivity)) / (1000 * 60 * 60 * 24)
            : 0;
        
        // Apply decay first (natural forgetting)
        if (daysSinceActivity > 0.25) { // More than 6 hours
            const decay = this.memorySystem.calculateDecay(
                memory.score, 
                daysSinceActivity, 
                memory.repetitions
            );
            memory.score = decay.newScore;
            memory.memoryType = decay.memoryType;
            
            if (decay.decayAmount > 0) {
                console.log(`[WIFI-TRAINING] Memory decay: -${decay.decayAmount.toFixed(1)} (${decay.memoryType})`);
            }
        }
        
        // Calculate growth using golden ratio
        const newScore = this.memorySystem.calculateGrowth(
            memory.score,
            sessionScore,
            memory.repetitions
        );
        
        // Calculate next optimal review interval
        const nextReview = this.memorySystem.calculateNextReviewInterval(
            memory.repetitions,
            sessionScore
        );
        
        // Update memory
        memory.score = newScore;
        memory.repetitions++;
        memory.lastActivity = now;
        memory.nextReview = nextReview.nextReviewDate;
        memory.history.push({
            timestamp: now.toISOString(),
            sessionScore,
            resultScore: newScore,
            repetition: memory.repetitions
        });
        
        // Update global expertise (weighted by φ)
        const allScores = Object.values(this.modelMemory).map(m => m.score);
        this.expertiseScore = Math.round(
            allScores.reduce((sum, s) => sum + s, 0) / allScores.length
        );
        this.sessionsCompleted++;
        
        // Get memory status for logging
        const status = this.memorySystem.getMemoryStatus(0, memory.repetitions);
        console.log(`[WIFI-TRAINING] φ Update: ${memory.score.toFixed(1)}/100 | Rep: ${memory.repetitions} | ${status.status}`);
        
        // Emit event with golden ratio metrics
        this.emit('golden_ratio_update', {
            model: modelName,
            score: memory.score,
            repetitions: memory.repetitions,
            memoryType: memory.memoryType,
            nextReview: nextReview,
            phi: PHI
        });
    }

    /**
     * Get memory status for a model
     */
    getModelMemoryStatus(modelName) {
        const memory = this.modelMemory[modelName];
        if (!memory) return null;
        
        const daysSince = memory.lastActivity 
            ? (new Date() - new Date(memory.lastActivity)) / (1000 * 60 * 60 * 24)
            : 0;
        
        return {
            ...this.memorySystem.getMemoryStatus(daysSince, memory.repetitions),
            score: memory.score,
            repetitions: memory.repetitions,
            lastActivity: memory.lastActivity,
            nextReview: memory.nextReview
        };
    }

    /**
     * Get WiFi expert system prompt
     */
    getWifiExpertSystemPrompt() {
        return `Tu es un expert en sécurité des réseaux sans fil avec 15 ans d'expérience.

EXPERTISE:
- Protocoles 802.11 (a/b/g/n/ac/ax)
- Sécurité WEP/WPA/WPA2/WPA3
- Outils: Aircrack-ng suite, Kismet, Wireshark, Bettercap
- Attaques: Deauth, Evil Twin, KRACK, PMKID, Beacon Flood
- Défense: 802.11w (PMF), WIDS/WIPS, segmentation, NAC

APPROCHE:
- Explique toujours le fonctionnement technique
- Fournis des commandes/configurations concrètes
- Inclus des recommandations défensives
- Mentionne les IOCs à surveiller
- Réfère aux CVEs quand pertinent

ÉTHIQUE:
- Toutes les techniques sont à des fins DÉFENSIVES
- L'objectif est la DÉTECTION et la PROTECTION
- Toujours mentionner l'autorisation requise pour les tests`;
    }

    /**
     * Run a full training session with mixed scenarios
     */
    async runTrainingSession(modelName, iterations = 5) {
        console.log(`[WIFI-TRAINING] Starting session for ${modelName} (${iterations} iterations)`);
        
        const types = ['attack', 'defense', 'quiz', 'random'];
        const results = [];
        
        for (let i = 0; i < iterations; i++) {
            const type = types[i % types.length];
            console.log(`[WIFI-TRAINING] Iteration ${i + 1}/${iterations} (${type})`);
            
            const result = await this.runTrainingIteration(modelName, type);
            results.push(result);
            
            this.emit('iteration_complete', { iteration: i + 1, total: iterations, result });
            
            // Small delay between iterations
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
        
        const avgScore = results.filter(r => r.success).reduce((sum, r) => sum + r.score, 0) / 
                         results.filter(r => r.success).length || 0;
        
        console.log(`[WIFI-TRAINING] Session complete. Average score: ${avgScore.toFixed(1)}`);
        
        return {
            model: modelName,
            iterations,
            results,
            averageScore: avgScore,
            expertiseScore: this.expertiseScore,
            sessionsCompleted: this.sessionsCompleted
        };
    }

    /**
     * Get training statistics
     */
    getStats() {
        return {
            expertiseScore: this.expertiseScore,
            sessionsCompleted: this.sessionsCompleted,
            totalIterations: this.trainingHistory.length,
            availableScenarios: {
                attacks: this.scenarios.attack_scenarios?.length || 0,
                defenses: this.scenarios.defense_scenarios?.length || 0,
                quizzes: this.scenarios.quiz_scenarios?.length || 0,
                prompts: this.scenarios.random_training_prompts?.length || 0,
                challenges: this.scenarios.practical_challenges?.length || 0
            },
            recentHistory: this.trainingHistory.slice(-10)
        };
    }
}

module.exports = WifiSecurityTrainingService;
