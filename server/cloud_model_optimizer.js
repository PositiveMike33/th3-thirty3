/**
 * Cloud Model Optimizer Service
 * Uses cloud models (Groq, Gemini, OpenAI) to automatically optimize local models
 * via AnythingLLM integration for knowledge persistence
 * 
 * Architecture:
 * 1. Cloud models generate high-quality training data/prompts
 * 2. AnythingLLM stores and embeds the training data
 * 3. Local models are trained with this data
 * 4. Performance is tracked and improved iteratively
 */

const fs = require('fs');
const path = require('path');
const EventEmitter = require('events');
const settingsService = require('./settings_service');

// Paths
const OPTIMIZER_DATA_PATH = path.join(__dirname, 'data', 'cloud_optimizer.json');

// Available cloud providers for optimization
const CLOUD_PROVIDERS = {
    groq: {
        name: 'Groq (Ultra-Fast)',
        models: ['llama-3.3-70b-versatile', 'llama-3.1-8b-instant'],
        priority: 1  // Fastest, use first
    },
    openai: {
        name: 'OpenAI',
        models: ['gpt-4o-mini', 'gpt-4o'],
        priority: 2
    },
    claude: {
        name: 'Claude',
        models: ['claude-3-5-sonnet-20241022'],
        priority: 3
    }
};

// Training domains: OSINT, Ethical Hacking, Social Psychology
// AnythingLLM workspace mapping for specialized training
const WORKSPACE_MAPPING = {
    osint: 'osint',                          // AnythingLLM workspace for OSINT
    ethical_hacking: 'cybersecurite',        // AnythingLLM workspace for Ethical Hacking
    social_psychology: 'social-psychology',   // AnythingLLM workspace for Social Psychology
    social_engineering: 'cybersecurite',     // Goes to cybersecurity workspace (related)
    threat_intelligence: 'osint'             // Goes to OSINT workspace (intelligence related)
};

const TRAINING_DOMAINS = {
    osint: {
        name: 'OSINT (Open Source Intelligence)',
        prompts: [
            "Génère un guide complet pour analyser l'empreinte numérique d'une cible à partir de sources publiques",
            "Crée un workflow d'investigation OSINT pour identifier des connexions entre entités",
            "Développe des techniques avancées de Google Dorking pour la reconnaissance",
            "Analyse les méthodes d'extraction d'informations depuis les métadonnées d'images",
            "Génère un protocole de veille OSINT pour la surveillance de menaces",
            "Crée un guide d'analyse de profils sur les réseaux sociaux (SOCMINT)",
            "Développe des techniques de corrélation de données multi-sources",
            "Explique les méthodes de vérification et validation des informations OSINT"
        ]
    },
    ethical_hacking: {
        name: 'Hacking Éthique',
        prompts: [
            "Génère un guide de reconnaissance réseau avec nmap et les techniques d'énumération",
            "Crée un protocole de test de pénétration pour applications web (OWASP Top 10)",
            "Développe des scénarios de tests d'intrusion avec exploitation de vulnérabilités courantes",
            "Analyse les techniques de post-exploitation et de maintien d'accès éthique",
            "Génère un guide de sécurisation après audit de sécurité",
            "Crée des exercices de CTF (Capture The Flag) pour l'entraînement",
            "Développe un protocole de red teaming avec techniques d'évasion",
            "Explique les méthodes d'analyse de malware et reverse engineering basique"
        ]
    },
    social_psychology: {
        name: 'Psychologie Sociale',
        prompts: [
            "Génère une analyse approfondie des dynamiques de groupe et du conformisme social (Asch, Milgram)",
            "Crée des scénarios d'ingénierie sociale éthique pour sensibilisation à la sécurité",
            "Développe un guide des biais cognitifs exploitables en social engineering",
            "Analyse les techniques de manipulation psychologique et comment s'en protéger",
            "Génère un profil psychologique basé sur les patterns de communication digitale",
            "Crée des exercices d'analyse comportementale et de lecture d'intentions",
            "Développe des techniques de persuasion éthique basées sur Cialdini",
            "Explique les mécanismes de confiance et de crédibilité dans les interactions en ligne"
        ]
    },
    social_engineering: {
        name: 'Social Engineering',
        prompts: [
            "Génère des scénarios de phishing pour la formation et sensibilisation",
            "Crée un guide de vishing (voice phishing) et techniques de détection",
            "Développe des red flags pour identifier les tentatives de manipulation",
            "Analyse les vecteurs d'attaque basés sur l'humain et les contre-mesures",
            "Génère un protocole de test d'ingénierie sociale pour audit de sécurité",
            "Crée des scénarios de pretexting avec analyse de vulnérabilités humaines",
            "Développe un guide de sensibilisation aux attaques par influence sociale",
            "Explique les techniques de baiting et tailgating avec prévention"
        ]
    },
    threat_intelligence: {
        name: 'Threat Intelligence',
        prompts: [
            "Génère un rapport de threat intelligence sur les APT actifs",
            "Crée un framework d'analyse de menaces avec le Diamond Model",
            "Développe des indicateurs de compromission (IOC) typiques par type d'attaque",
            "Analyse les tactiques, techniques et procédures (TTP) des groupes de menaces",
            "Génère un guide de hunting de menaces proactif",
            "Crée des scénarios d'attribution d'attaques basés sur des patterns",
            "Développe un protocole de veille sur les vulnérabilités critiques",
            "Explique les méthodes de corrélation threat intel avec MITRE ATT&CK"
        ]
    }
};

class CloudModelOptimizerService extends EventEmitter {
    constructor(llmService, modelMetricsService, anythingLLMWrapper) {
        super();
        this.llmService = llmService;
        this.modelMetrics = modelMetricsService;
        this.anythingLLM = anythingLLMWrapper;
        
        this.isRunning = false;
        this.optimizationInterval = null;
        this.stats = this.loadStats();
        this.verboseLogging = false; // Reduced logging by default
        
        // Don't log on init if verbose is off
        if (this.verboseLogging) {
            console.log('[CLOUD_OPTIMIZER] Service initialized');
        }
    }

    /**
     * Load optimization stats from disk
     */
    loadStats() {
        try {
            if (fs.existsSync(OPTIMIZER_DATA_PATH)) {
                return JSON.parse(fs.readFileSync(OPTIMIZER_DATA_PATH, 'utf8'));
            }
        } catch (error) {
            console.error('[CLOUD_OPTIMIZER] Failed to load stats:', error.message);
        }
        return {
            totalOptimizations: 0,
            trainingDataGenerated: 0,
            localModelsImproved: [],
            lastRun: null,
            history: []
        };
    }

    /**
     * Save stats to disk
     */
    saveStats() {
        try {
            const dir = path.dirname(OPTIMIZER_DATA_PATH);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
            fs.writeFileSync(OPTIMIZER_DATA_PATH, JSON.stringify(this.stats, null, 2));
        } catch (error) {
            console.error('[CLOUD_OPTIMIZER] Failed to save stats:', error.message);
        }
    }

    /**
     * Get available cloud provider (checks API keys)
     */
    getAvailableCloudProvider() {
        const providers = [];
        
        if (process.env.GROQ_API_KEY) {
            providers.push({ ...CLOUD_PROVIDERS.groq, id: 'groq' });
        }
        if (process.env.OPENAI_API_KEY) {
            providers.push({ ...CLOUD_PROVIDERS.openai, id: 'openai' });
        }
        if (process.env.ANTHROPIC_API_KEY) {
            providers.push({ ...CLOUD_PROVIDERS.claude, id: 'claude' });
        }
        
        // Sort by priority and return first available
        providers.sort((a, b) => a.priority - b.priority);
        return providers[0] || null;
    }

    /**
     * Generate training data using cloud model
     */
    async generateTrainingData(domain, cloudProvider) {
        const domainConfig = TRAINING_DOMAINS[domain];
        if (!domainConfig) {
            throw new Error(`Unknown domain: ${domain}`);
        }

        // Pick random prompt from domain
        const prompt = domainConfig.prompts[Math.floor(Math.random() * domainConfig.prompts.length)];
        
        // System prompt for generating high-quality training data
        const systemPrompt = `Tu es un expert en ${domainConfig.name} et en formation d'IA.
Ta mission: Générer des données d'entraînement de HAUTE QUALITÉ pour optimiser un modèle IA local.

Format de réponse REQUIS:
1. CONTEXTE: Explique brièvement le contexte de l'exercice
2. PROMPT D'ENTRAINEMENT: Le prompt exact à utiliser pour entraîner le modèle local
3. RÉPONSE ATTENDUE: La réponse idéale que le modèle devrait produire
4. CRITÈRES D'ÉVALUATION: Comment évaluer la qualité de la réponse

Sois précis, professionnel et orienté vers l'apprentissage machine.`;

        if (this.verboseLogging) {
            console.log(`[CLOUD_OPTIMIZER] Generating training data via ${cloudProvider.id} for ${domain}`);
        }
        
        const response = await this.llmService.generateResponse(
            prompt,
            null,
            cloudProvider.id,
            cloudProvider.models[0],
            systemPrompt
        );

        return {
            domain,
            domainName: domainConfig.name,
            originalPrompt: prompt,
            generatedData: response,
            cloudProvider: cloudProvider.id,
            cloudModel: cloudProvider.models[0],
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Store training data in AnythingLLM for persistence
     */
    async storeInAnythingLLM(trainingData) {
        if (!this.anythingLLM) {
            console.log('[CLOUD_OPTIMIZER] AnythingLLM not available, skipping storage');
            return false;
        }

        try {
            // Get the right workspace for this domain
            const workspaceSlug = WORKSPACE_MAPPING[trainingData.domain] || 'th3-thirty3-workspace';
            
            // Format for AnythingLLM embedding
            const content = `
## Training Data - ${trainingData.domainName}
**Generated by**: ${trainingData.cloudProvider} (${trainingData.cloudModel})
**Date**: ${trainingData.timestamp}
**Workspace**: ${workspaceSlug}

### Original Prompt
${trainingData.originalPrompt}

### Generated Training Content
${trainingData.generatedData}
`;
            // Store in the specialized workspace - use settings first, then fallback to env
            const settings = settingsService.getSettings();
            const anythingLLMUrl = settings?.apiKeys?.anythingllm_url || process.env.ANYTHING_LLM_URL || 'http://localhost:3001';
            const anythingLLMKey = settings?.apiKeys?.anythingllm_key || process.env.ANYTHING_LLM_KEY;
            
            if (!anythingLLMKey) {
                console.log('[CLOUD_OPTIMIZER] AnythingLLM key not configured');
                return false;
            }

            // Try to use the specialized workspace
            const response = await fetch(`${anythingLLMUrl}/workspace/${workspaceSlug}/chat`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${anythingLLMKey}`
                },
                body: JSON.stringify({
                    message: `[TRAINING_DATA] Mémorise ces données d'entraînement: ${content}`,
                    mode: 'chat'
                })
            });

            if (response.ok) {
                console.log(`[CLOUD_OPTIMIZER] Training data stored in AnythingLLM workspace: ${workspaceSlug}`);
                return true;
            } else {
                // Fallback to default wrapper
                await this.anythingLLM.chat(
                    `[TRAINING_DATA] [${workspaceSlug.toUpperCase()}] Mémorise: ${content}`,
                    'chat'
                );
                console.log(`[CLOUD_OPTIMIZER] Training data stored via wrapper (fallback)`);
                return true;
            }
        } catch (error) {
            console.error('[CLOUD_OPTIMIZER] Failed to store in AnythingLLM:', error.message);
            return false;
        }
    }

    /**
     * Train local model with generated data
     */
    async trainLocalModel(localModelName, trainingData) {
        if (this.verboseLogging) {
            console.log(`[CLOUD_OPTIMIZER] Training ${localModelName} with generated data...`);
        }
        
        // Extract the training prompt from generated data
        const trainingPrompt = `Utilise ces données d'entraînement pour améliorer tes compétences en ${trainingData.domainName}:

${trainingData.generatedData}

Maintenant, génère une réponse similaire pour démontrer ta compréhension.`;

        const systemPrompt = `Tu es en mode entraînement intensif. 
Analyse le contenu fourni et génère une réponse de haute qualité qui démontre ta maîtrise du sujet.
Sois précis, professionnel et détaillé.`;

        const startTime = Date.now();
        
        try {
            const response = await this.llmService.generateOllamaResponse(
                trainingPrompt,
                null,
                localModelName,
                systemPrompt
            );
            
            const responseTime = Date.now() - startTime;
            
            // Evaluate response quality
            const qualityScore = this.evaluateResponse(response, trainingData);
            
            // Record metrics
            if (this.modelMetrics) {
                this.modelMetrics.recordQuery(localModelName, {
                    responseTime,
                    tokensGenerated: Math.floor((response?.length || 0) / 4),
                    success: true,
                    category: this.mapDomainToCategory(trainingData.domain),
                    qualityScore
                });
            }
            
            return {
                success: true,
                localModel: localModelName,
                responseTime,
                qualityScore,
                responseLength: response?.length || 0
            };
            
        } catch (error) {
            console.error(`[CLOUD_OPTIMIZER] Training failed for ${localModelName}:`, error.message);
            return {
                success: false,
                localModel: localModelName,
                error: error.message
            };
        }
    }

    /**
     * Evaluate training response quality
     */
    evaluateResponse(response, trainingData) {
        if (!response) return 0;
        
        let score = 40;
        
        // Length check
        if (response.length > 100) score += 10;
        if (response.length > 300) score += 10;
        if (response.length > 600) score += 5;
        
        // Domain-specific keywords
        const keywords = {
            osint: ['reconnaissance', 'empreinte', 'source', 'analyse', 'veille', 'intelligence', 'metadata'],
            ethical_hacking: ['vulnérabilité', 'exploitation', 'pentest', 'sécurité', 'intrusion', 'cve', 'nmap'],
            social_psychology: ['manipulation', 'influence', 'biais', 'comportement', 'confiance', 'persuasion'],
            social_engineering: ['phishing', 'pretexting', 'vishing', 'ingénierie', 'humain', 'vecteur'],
            threat_intelligence: ['menace', 'apt', 'ioc', 'ttp', 'attribution', 'mitre', 'attaque']
        };
        
        const domainKeywords = keywords[trainingData.domain] || [];
        const lowerResponse = response.toLowerCase();
        
        for (const kw of domainKeywords) {
            if (lowerResponse.includes(kw)) score += 5;
        }
        
        return Math.min(100, score);
    }

    /**
     * Map training domain to metrics category
     */
    mapDomainToCategory(domain) {
        const mapping = {
            social_psychology: 'analysis',
            behavioral_analysis: 'analysis',
            influence_methods: 'writing',
            emotional_intelligence: 'humanizer'
        };
        return mapping[domain] || 'chat';
    }

    /**
     * Run a single optimization cycle
     */
    async runOptimizationCycle() {
        if (this.verboseLogging) {
            console.log('[CLOUD_OPTIMIZER] Starting optimization cycle...');
        }
        this.emit('cycleStarted');
        
        const results = {
            timestamp: new Date().toISOString(),
            trainingDataGenerated: [],
            localModelsResults: [],
            success: false
        };
        
        try {
            // 1. Get available cloud provider
            const cloudProvider = this.getAvailableCloudProvider();
            if (!cloudProvider) {
                throw new Error('No cloud provider available (missing API keys)');
            }
            
            if (this.verboseLogging) {
                console.log(`[CLOUD_OPTIMIZER] Using ${cloudProvider.name} for optimization`);
            }
            
            // 2. Get local models
            const localModels = await this.getLocalModels();
            if (localModels.length === 0) {
                throw new Error('No local models available');
            }
            
            // 3. For each domain, generate training data and train local models
            const domains = Object.keys(TRAINING_DOMAINS);
            const selectedDomain = domains[Math.floor(Math.random() * domains.length)];
            
            // Generate training data from cloud
            const trainingData = await this.generateTrainingData(selectedDomain, cloudProvider);
            results.trainingDataGenerated.push(trainingData);
            
            // Store in AnythingLLM
            await this.storeInAnythingLLM(trainingData);
            
            // Train each local model
            for (const localModel of localModels) {
                const trainingResult = await this.trainLocalModel(localModel, trainingData);
                results.localModelsResults.push(trainingResult);
                
                // Small delay between models
                await new Promise(r => setTimeout(r, 2000));
            }
            
            results.success = true;
            
            // Update stats
            this.stats.totalOptimizations++;
            this.stats.trainingDataGenerated += results.trainingDataGenerated.length;
            this.stats.lastRun = new Date().toISOString();
            this.stats.history.push({
                timestamp: results.timestamp,
                domain: selectedDomain,
                cloudProvider: cloudProvider.id,
                localModelsCount: localModels.length,
                success: true
            });
            
            // Keep only last 50 history entries
            if (this.stats.history.length > 50) {
                this.stats.history = this.stats.history.slice(-50);
            }
            
            this.saveStats();
            
        } catch (error) {
            console.error('[CLOUD_OPTIMIZER] Optimization cycle failed:', error.message);
            results.error = error.message;
        }
        
        this.emit('cycleCompleted', results);
        console.log('[CLOUD_OPTIMIZER] Optimization cycle completed');
        
        return results;
    }

    /**
     * Get available local models
     */
    async getLocalModels() {
        try {
            const response = await fetch('http://localhost:11434/api/tags');
            const data = await response.json();
            return (data.models || [])
                .map(m => m.name)
                .filter(n => !n.includes('embed'));
        } catch (error) {
            console.error('[CLOUD_OPTIMIZER] Failed to get local models:', error.message);
            return [];
        }
    }

    // Start automatic optimization (runs every X minutes) - DEFAULT: 120 minutes (2 hours)
    startAutoOptimization(intervalMinutes = 120) {
        if (this.isRunning) {
            console.log('[CLOUD_OPTIMIZER] Already running');
            return;
        }
        
        this.isRunning = true;
        console.log(`[CLOUD_OPTIMIZER] Starting auto-optimization every ${intervalMinutes} minutes`);
        
        // Run immediately first
        this.runOptimizationCycle().catch(err => 
            console.error('[CLOUD_OPTIMIZER] Initial cycle error:', err.message)
        );
        
        // Then schedule
        this.optimizationInterval = setInterval(async () => {
            try {
                await this.runOptimizationCycle();
            } catch (error) {
                console.error('[CLOUD_OPTIMIZER] Scheduled cycle error:', error.message);
            }
        }, intervalMinutes * 60 * 1000);
        
        this.emit('started', { intervalMinutes });
    }

    /**
     * Stop automatic optimization
     */
    stopAutoOptimization() {
        if (this.optimizationInterval) {
            clearInterval(this.optimizationInterval);
            this.optimizationInterval = null;
        }
        this.isRunning = false;
        console.log('[CLOUD_OPTIMIZER] Auto-optimization stopped');
        this.emit('stopped');
    }

    /**
     * Get optimization status
     */
    getStatus() {
        return {
            isRunning: this.isRunning,
            stats: this.stats,
            availableProviders: this.getAvailableCloudProviders(),
            trainingDomains: Object.keys(TRAINING_DOMAINS).map(k => ({
                id: k,
                name: TRAINING_DOMAINS[k].name,
                promptCount: TRAINING_DOMAINS[k].prompts.length
            }))
        };
    }

    /**
     * Get all available cloud providers
     */
    getAvailableCloudProviders() {
        const providers = [];
        
        if (process.env.GROQ_API_KEY) providers.push('groq');
        if (process.env.OPENAI_API_KEY) providers.push('openai');
        if (process.env.ANTHROPIC_API_KEY) providers.push('claude');
        if (process.env.GEMINI_API_KEY) providers.push('gemini');
        
        return providers;
    }
}

module.exports = CloudModelOptimizerService;


