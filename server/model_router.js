/**
 * Model Router Service - OPTIMIZED FOR LOCAL PERFORMANCE
 * Routes agents to optimal local models based on expertise
 * 
 * LOCAL MODELS (légers, rapides):
 * - qwen2.5:3b (1.9GB) - Code & General
 * - granite3.1-moe:1b (1.4GB) - Fast responses
 * - nomic-embed-text (274MB) - Embeddings
 * 
 * CLOUD MODELS (via API):
 * - Groq (Llama, Mixtral)
 * - Gemini
 * - OpenAI
 */

// Local model configuration
const LOCAL_MODELS = {
    code: 'qwen2.5-coder:7b',     // Best for Coding & Reverse Engineering
    general: 'mistral:7b-instruct', // Best for Instruction Following & Strategy
    fast: 'granite3.1-moe:1b',      // Best for Speed & Background Tasks
    embedding: 'nomic-embed-text:latest' // Embeddings
};

// All local trainable models (for rotation)
const ALL_LOCAL_MODELS = [
    'qwen2.5-coder:7b',
    'mistral:7b-instruct',
    'granite3.1-moe:1b'
];

// Cloud providers for heavy tasks
const CLOUD_PROVIDERS = {
    groq: {
        models: ['llama-3.1-70b-versatile', 'mixtral-8x7b-32768', 'llama3-8b-8192'],
        endpoint: 'https://api.groq.com/openai/v1/chat/completions'
    },
    gemini: {
        models: ['gemini-1.5-flash', 'gemini-1.5-pro'],
        endpoint: 'https://generativelanguage.googleapis.com/v1beta'
    }
};

// Network Failover Service Integration (RISK-006 Mitigation)
let networkFailoverService = null;
try {
    const { networkFailoverService: nfs } = require('./network_failover_service');
    networkFailoverService = nfs;
    console.log('[MODEL_ROUTER] Network Failover Service integrated');
} catch (e) {
    console.warn('[MODEL_ROUTER] Network Failover Service not available:', e.message);
}

class ModelRouter {
    constructor() {
        this.initialized = false;
        this.currentlyLoaded = new Set();
        this.lastUsedModel = null;
        this.modelRotationIndex = 0;
        this.preferLocal = true; // Default to local for speed
    }

    /**
     * Initialize the router - preload nomic-embed-text for embeddings
     */
    async initialize() {
        if (this.initialized) return true;
        
        console.log('[MODEL_ROUTER] Initializing (optimized local config)...');
        console.log('[MODEL_ROUTER] Local models: qwen2.5:3b, granite3.1-moe:1b, nomic-embed-text');
        console.log('[MODEL_ROUTER] Cloud fallback: Groq, Gemini');
        
        try {
            // Preload embedding model
            await this.ensureNomicLoaded();
            this.initialized = true;
            return true;
        } catch (error) {
            console.error('[MODEL_ROUTER] Init error:', error.message);
            return false;
        }
    }

    /**
     * Ensure nomic-embed-text is ready for local embeddings
     */
    async ensureNomicLoaded() {
        try {
            const response = await fetch('http://localhost:11434/api/embeddings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: 'nomic-embed-text:latest',
                    prompt: 'init'
                })
            });
            
            if (response.ok) {
                console.log('[MODEL_ROUTER] ✅ nomic-embed-text ready');
                this.currentlyLoaded.add('nomic-embed-text:latest');
                return true;
            }
            return false;
        } catch (error) {
            console.warn('[MODEL_ROUTER] nomic-embed not available:', error.message);
            return false;
        }
    }

    /**
     * Route to optimal model based on task with AUTOMATIC FAILOVER
     * Integrates with NetworkFailoverService for RISK-006 mitigation
     * @param {string} domain - Task type (code, security, general, fast)
     * @param {boolean} forceLocal - Force local model usage
     * @param {boolean} forceCloud - Force cloud model usage (overrides network state)
     * @returns {Object} - { model, isLocal, provider, failoverActive }
     */
    async routeToModel(domain = 'general', forceLocal = false, forceCloud = false) {
        const normalizedDomain = domain.toLowerCase();
        
        // Map domains to appropriate models
        let localModel;
        switch (normalizedDomain) {
            case 'code':
            case 'programming':
            case 'development':
                localModel = LOCAL_MODELS.code;
                break;
            case 'fast':
            case 'quick':
            case 'simple':
                localModel = LOCAL_MODELS.fast;
                break;
            case 'embedding':
                localModel = LOCAL_MODELS.embedding;
                break;
            default:
                localModel = LOCAL_MODELS.general;
        }
        
        // === NETWORK FAILOVER INTEGRATION (RISK-006) ===
        // Check network state before routing
        let failoverActive = false;
        let networkState = 'UNKNOWN';
        
        if (networkFailoverService && !forceCloud) {
            const status = networkFailoverService.getStatus();
            networkState = status.state;
            
            // If network is OFFLINE, force local models
            if (status.state === 'OFFLINE' || !status.isOnline) {
                console.log('[MODEL_ROUTER] 🔴 FAILOVER ACTIVE: Internet offline, using local models');
                forceLocal = true;
                failoverActive = true;
            }
            
            // If network is DEGRADED, prefer local for reliability
            if (status.state === 'DEGRADED') {
                console.log('[MODEL_ROUTER] 🟡 DEGRADED: Preferring local models for reliability');
                this.preferLocal = true;
            }
        }
        // === END FAILOVER INTEGRATION ===
        
        // Try local first if preferred, forced, or failover active
        if (this.preferLocal || forceLocal || failoverActive) {
            try {
                const loaded = await this.loadModel(localModel);
                if (loaded) {
                    this.lastUsedModel = localModel;
                    return { 
                        model: localModel, 
                        isLocal: true, 
                        provider: 'ollama',
                        failoverActive,
                        networkState
                    };
                }
            } catch (error) {
                console.warn(`[MODEL_ROUTER] Local ${localModel} failed:`, error.message);
            }
        }
        
        // If failover is active, don't try cloud
        if (failoverActive) {
            console.log('[MODEL_ROUTER] ⚠️ Failover active, skipping cloud providers');
            return { 
                model: localModel, 
                isLocal: true, 
                provider: 'ollama',
                failoverActive: true,
                networkState,
                warning: 'Cloud unavailable, using local fallback'
            };
        }
        
        // Fallback to cloud (Groq is fastest)
        if (process.env.GROQ_API_KEY) {
            return { 
                model: 'llama3-8b-8192', 
                isLocal: false, 
                provider: 'groq',
                failoverActive: false,
                networkState
            };
        }
        
        // Fallback to Gemini
        if (process.env.GEMINI_API_KEY) {
            return { 
                model: 'gemini-1.5-flash', 
                isLocal: false, 
                provider: 'gemini',
                failoverActive: false,
                networkState
            };
        }
        
        // Last resort: try any local model
        return { 
            model: localModel, 
            isLocal: true, 
            provider: 'ollama',
            failoverActive: false,
            networkState
        };
    }

    /**
     * Load a local model via Ollama
     */
    async loadModel(modelName) {
        try {
            if (this.currentlyLoaded.has(modelName)) {
                return true;
            }
            
            console.log(`[MODEL_ROUTER] Loading: ${modelName}`);
            
            const response = await fetch('http://localhost:11434/api/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: modelName,
                    prompt: 'init',
                    stream: false,
                    options: { num_predict: 1 }
                })
            });
            
            if (response.ok) {
                this.currentlyLoaded.add(modelName);
                console.log(`[MODEL_ROUTER] ✅ ${modelName} loaded`);
                return true;
            }
            
            return false;
        } catch (error) {
            console.error(`[MODEL_ROUTER] ❌ Failed to load ${modelName}:`, error.message);
            return false;
        }
    }

    /**
     * Get next model for training rotation
     */
    getNextTrainingModel() {
        const model = ALL_LOCAL_MODELS[this.modelRotationIndex];
        this.modelRotationIndex = (this.modelRotationIndex + 1) % ALL_LOCAL_MODELS.length;
        return model;
    }

    /**
     * Get all trainable models
     */
    getAllTrainableModels() {
        return [...ALL_LOCAL_MODELS];
    }

    /**
     * Get embedding model
     */
    getEmbeddingModel() {
        return 'nomic-embed-text:latest';
    }

    /**
     * Get cloud provider config
     */
    getCloudProviders() {
        return CLOUD_PROVIDERS;
    }

    /**
     * Set preference for local or cloud
     */
    setPreference(preferLocal = true) {
        this.preferLocal = preferLocal;
        console.log(`[MODEL_ROUTER] Preference: ${preferLocal ? 'LOCAL' : 'CLOUD'}`);
    }

    /**
     * Get current router status
     */
    getStatus() {
        return {
            initialized: this.initialized,
            preferLocal: this.preferLocal,
            localModels: Object.values(LOCAL_MODELS),
            currentlyLoaded: Array.from(this.currentlyLoaded),
            lastUsedModel: this.lastUsedModel,
            cloudAvailable: {
                groq: !!process.env.GROQ_API_KEY,
                gemini: !!process.env.GEMINI_API_KEY
            }
        };
    }
}

// Singleton instance
const modelRouter = new ModelRouter();

// BACKWARD COMPATIBILITY: Add 'models' property for orchestrator_service.js
// Maps old model references to new lightweight models + cloud fallback
modelRouter.models = {
    orchestrator: {
        primary: 'qwen2.5:3b',      // Was gpt-oss:120b-cloud
        fallback: 'granite3.1-moe:1b'  // Was mistral:7b
    },
    technical: {
        primary: 'qwen2.5:3b',      // Best for code/technical
        fallback: 'granite3.1-moe:1b'
    },
    nlp: {
        primary: 'qwen2.5:3b',      // Was mistral:7b
        fallback: 'granite3.1-moe:1b'
    },
    vision: {
        primary: 'qwen2.5:3b',      // Vision model removed, fallback to general
        fallback: 'granite3.1-moe:1b'
    },
    embedding: {
        primary: 'nomic-embed-text:latest',
        fallback: null
    }
};

module.exports = modelRouter;
