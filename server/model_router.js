/**
 * Model Router Service - OPTIMIZED FOR LOCAL PERFORMANCE
 * Routes agents to optimal local models based on expertise
 * 
 * AVAILABLE MODELS (4 only):
 * - qwen2.5-coder:7b (4.7GB) - Code & Technical Analysis
 * - mistral:7b-instruct (4.1GB) - Strategy & Instruction Following
 * - granite3.1-moe:1b (1.4GB) - Fast responses & Fallback
 * - nomic-embed-text:latest (274MB) - Embeddings
 * 
 * CLOUD MODELS (via API):
 * - Groq (Llama, Mixtral)
 * - Gemini
 */

// ==========================================
// LOCAL MODEL CONFIGURATION (4 MODELS ONLY)
// ==========================================

const LOCAL_MODELS = {
    code: 'qwen2.5-coder:7b',         // Best for Coding, Reverse Engineering, Technical
    general: 'mistral:7b-instruct',   // Best for Instruction Following, Strategy, OSINT
    fast: 'granite3.1-moe:1b',        // Best for Speed, Background Tasks, Fallback
    embedding: 'nomic-embed-text:latest' // Embeddings only
};

// All local trainable models (for rotation) - EXCLUDING embedding model
const ALL_LOCAL_MODELS = [
    'qwen2.5-coder:7b',
    'mistral:7b-instruct',
    'granite3.1-moe:1b'
];

// Primary model for each use case
const MODEL_FOR_TASK = {
    // Code/Technical tasks -> qwen2.5-coder
    code: 'qwen2.5-coder:7b',
    programming: 'qwen2.5-coder:7b',
    development: 'qwen2.5-coder:7b',
    technical: 'qwen2.5-coder:7b',
    exploit: 'qwen2.5-coder:7b',
    scripting: 'qwen2.5-coder:7b',
    
    // Strategy/Instruction tasks -> mistral
    strategy: 'mistral:7b-instruct',
    osint: 'mistral:7b-instruct',
    analysis: 'mistral:7b-instruct',
    general: 'mistral:7b-instruct',
    nlp: 'mistral:7b-instruct',
    
    // Fast/Fallback tasks -> granite
    fast: 'granite3.1-moe:1b',
    quick: 'granite3.1-moe:1b',
    simple: 'granite3.1-moe:1b',
    fallback: 'granite3.1-moe:1b',
    
    // Embeddings
    embedding: 'nomic-embed-text:latest',
    embeddings: 'nomic-embed-text:latest'
};

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
} catch (e) {
    // Silently ignore if not available
}

class ModelRouter {
    constructor() {
        this.initialized = false;
        this.currentlyLoaded = new Set();
        this.lastUsedModel = null;
        this.modelRotationIndex = 0;
        this.preferLocal = true;
    }

    async initialize() {
        if (this.initialized) return true;
        
        console.log('[MODEL_ROUTER] Initializing with 4 optimized models...');
        console.log('[MODEL_ROUTER] Models: qwen2.5-coder:7b, mistral:7b-instruct, granite3.1-moe:1b, nomic-embed-text');
        
        try {
            await this.ensureNomicLoaded();
            this.initialized = true;
            return true;
        } catch (error) {
            console.error('[MODEL_ROUTER] Init error:', error.message);
            return false;
        }
    }

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

    getModelForTask(task) {
        const normalizedTask = (task || 'general').toLowerCase();
        return MODEL_FOR_TASK[normalizedTask] || MODEL_FOR_TASK.general;
    }

    async routeToModel(domain = 'general', forceLocal = false, forceCloud = false) {
        const normalizedDomain = domain.toLowerCase();
        let localModel = this.getModelForTask(normalizedDomain);
        
        let failoverActive = false;
        let networkState = 'UNKNOWN';
        
        if (networkFailoverService && !forceCloud) {
            try {
                const status = networkFailoverService.getStatus();
                networkState = status.state;
                
                if (status.state === 'OFFLINE' || !status.isOnline) {
                    forceLocal = true;
                    failoverActive = true;
                }
            } catch (e) {
                // Ignore
            }
        }
        
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
        
        if (failoverActive) {
            return { 
                model: localModel, 
                isLocal: true, 
                provider: 'ollama',
                failoverActive: true,
                networkState,
                warning: 'Cloud unavailable, using local fallback'
            };
        }
        
        if (process.env.GROQ_API_KEY) {
            return { 
                model: 'llama3-8b-8192', 
                isLocal: false, 
                provider: 'groq',
                failoverActive: false,
                networkState
            };
        }
        
        if (process.env.GEMINI_API_KEY) {
            return { 
                model: 'gemini-1.5-flash', 
                isLocal: false, 
                provider: 'gemini',
                failoverActive: false,
                networkState
            };
        }
        
        return { 
            model: localModel, 
            isLocal: true, 
            provider: 'ollama',
            failoverActive: false,
            networkState
        };
    }

    async loadModel(modelName) {
        try {
            if (this.currentlyLoaded.has(modelName)) {
                return true;
            }
            
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

    getNextTrainingModel() {
        const model = ALL_LOCAL_MODELS[this.modelRotationIndex];
        this.modelRotationIndex = (this.modelRotationIndex + 1) % ALL_LOCAL_MODELS.length;
        return model;
    }

    getAllTrainableModels() {
        return [...ALL_LOCAL_MODELS];
    }

    getEmbeddingModel() {
        return 'nomic-embed-text:latest';
    }

    getCloudProviders() {
        return CLOUD_PROVIDERS;
    }

    setPreference(preferLocal = true) {
        this.preferLocal = preferLocal;
    }

    getStatus() {
        return {
            initialized: this.initialized,
            preferLocal: this.preferLocal,
            availableModels: ALL_LOCAL_MODELS,
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

// BACKWARD COMPATIBILITY - Maps old model references to available models
modelRouter.models = {
    orchestrator: {
        primary: 'mistral:7b-instruct',
        fallback: 'granite3.1-moe:1b'
    },
    technical: {
        primary: 'qwen2.5-coder:7b',
        fallback: 'granite3.1-moe:1b'
    },
    nlp: {
        primary: 'mistral:7b-instruct',
        fallback: 'granite3.1-moe:1b'
    },
    vision: {
        primary: 'qwen2.5-coder:7b',
        fallback: 'granite3.1-moe:1b'
    },
    code: {
        primary: 'qwen2.5-coder:7b',
        fallback: 'granite3.1-moe:1b'
    },
    osint: {
        primary: 'mistral:7b-instruct',
        fallback: 'granite3.1-moe:1b'
    },
    embedding: {
        primary: 'nomic-embed-text:latest',
        fallback: null
    }
};

modelRouter.LOCAL_MODELS = LOCAL_MODELS;
modelRouter.ALL_LOCAL_MODELS = ALL_LOCAL_MODELS;

module.exports = modelRouter;
