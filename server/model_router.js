/**
 * Model Router Service - HYBRID (Cloud + Local)
 * Routes agents the optimal model based on availability and task
 */

// Local Ollama Models (User Requested)
// Local Ollama Models (User Requested)
const LOCAL_MODELS = {
    code: 'granite4:latest',      // IBM Granite 4.0 (?) - Code/General
    general: 'granite4:latest',   // IBM Granite 4.0
    fast: 'granite4:latest',      // Fast enough for general use
    embedding: 'mxbai-embed-large:latest', // Primary: State-of-the-art
    fallback_embedding: 'snowflake-arctic-embed:latest' // Fallback: Snowflake
};

// Cloud providers configuration
const CLOUD_PROVIDERS = {
    groq: {
        models: ['llama-3.1-70b-versatile', 'mixtral-8x7b-32768', 'llama3-8b-8192'],
        endpoint: 'https://api.groq.com/openai/v1/chat/completions'
    },
    gemini: {
        models: ['gemini-1.5-flash', 'gemini-1.5-pro'],
        endpoint: 'https://generativelanguage.googleapis.com/v1beta'
    },
    openai: {
        models: ['gpt-4o', 'gpt-4o-mini'],
        endpoint: 'https://api.openai.com/v1'
    }
};

class ModelRouter {
    constructor() {
        this.initialized = false;
        this.preferLocal = true; // Preferred for Privacy/Offline
    }

    /**
     * Initialize the router
     */
    async initialize() {
        if (this.initialized) return true;

        console.log('[MODEL_ROUTER] Initializing (HYBRID mode)...');
        console.log(`[MODEL_ROUTER] Local Models: ${LOCAL_MODELS.general}`);

        // Verify Ollama connection
        try {
            const ollamaUrl = process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
            const response = await fetch(`${ollamaUrl}/api/tags`);
            if (response.ok) {
                console.log('[MODEL_ROUTER] ✅ Ollama connected');
            } else {
                console.warn('[MODEL_ROUTER] ⚠️ Ollama responding but error code', response.status);
            }
        } catch (e) {
            console.warn('[MODEL_ROUTER] ⚠️ Ollama not detected. Falling back to Cloud-only.');
            this.preferLocal = false;
        }

        this.initialized = true;
        return true;
    }

    /**
     * Route to optimal model based on task
     * @param {string} domain - Task type (code, security, general, fast)
     * @param {boolean} forceLocal - Use local model if available
     * @param {boolean} forceCloud - Force cloud usage
     * @returns {Object} - { model, isLocal, provider }
     */
    async routeToModel(domain = 'general', forceLocal = false, forceCloud = false) {
        const normalizedDomain = domain.toLowerCase();

        // 1. Force Local OR Prefer Local (if not forcing cloud)
        if ((forceLocal || this.preferLocal) && !forceCloud) {
            let model = LOCAL_MODELS.general;
            if (normalizedDomain.includes('code') || normalizedDomain.includes('dev')) model = LOCAL_MODELS.code;
            if (normalizedDomain.includes('embed')) return { model: LOCAL_MODELS.embedding, provider: 'ollama', isLocal: true };

            return { model: model, provider: 'ollama', isLocal: true };
        }

        // Check available API keys
        const hasGroq = !!process.env.GROQ_API_KEY;
        const hasGemini = !!process.env.GEMINI_API_KEY;
        const hasOpenAI = !!process.env.OPENAI_API_KEY;
        const hasAnthropic = !!process.env.ANTHROPIC_API_KEY;

        console.log(`[ROUTER] Routing to Cloud for ${domain} (Local=${forceLocal}, Cloud=${forceCloud})`);

        // Default to Gemini Flash if available (Good balance)
        // Then Groq (Fast)
        // Then OpenAI (Quality)

        // 1. CODE / PROGRAMMING
        if (['code', 'programming', 'development'].includes(normalizedDomain)) {
            if (hasAnthropic) return { model: 'claude-3-5-sonnet-20241022', provider: 'claude', isLocal: false };
            if (hasOpenAI) return { model: 'gpt-4o', provider: 'openai', isLocal: false };
            if (hasGemini) return { model: 'gemini-1.5-pro', provider: 'gemini', isLocal: false };
            if (hasGroq) return { model: 'llama-3.1-70b-versatile', provider: 'groq', isLocal: false };
        }

        // 2. FAST / QUICK
        if (['fast', 'quick', 'simple'].includes(normalizedDomain)) {
            if (hasGroq) return { model: 'llama-3.1-8b-instant', provider: 'groq', isLocal: false };
            if (hasGemini) return { model: 'gemini-1.5-flash', provider: 'gemini', isLocal: false };
            if (hasOpenAI) return { model: 'gpt-4o-mini', provider: 'openai', isLocal: false };
        }

        // 3. GENERAL / DEFAULT
        // Prefer Gemini Flash for general use (High rate limits, good speed)
        if (hasGemini) return { model: 'gemini-1.5-flash', provider: 'gemini', isLocal: false };
        if (hasGroq) return { model: 'llama-3.3-70b-versatile', provider: 'groq', isLocal: false };
        if (hasOpenAI) return { model: 'gpt-4o', provider: 'openai', isLocal: false };
        if (hasAnthropic) return { model: 'claude-3-opus-20240229', provider: 'claude', isLocal: false };

        // Fallback / No Keys
        console.warn('[MODEL_ROUTER] ⚠️ No Cloud API Keys found! Fallback to Local.');
        return {
            model: LOCAL_MODELS.general,
            provider: 'ollama',
            isLocal: true
        };
    }

    // Stub methods for backward compatibility
    async loadModel(modelName) { return true; }
    async unloadAllModels() { return true; }
    async ensureNomicLoaded() { return true; }
    getNextTrainingModel() { return 'cloud-model'; }
    getAllTrainableModels() { return []; }
    getEmbeddingModel() { return 'text-embedding-3-small'; } // Recommend OpenAI embedding
    getCloudProviders() { return CLOUD_PROVIDERS; }
    setPreference(preferLocal) { this.preferLocal = false; }

    getStatus() {
        return {
            initialized: this.initialized,
            preferLocal: false,
            modelMode: 'CLOUD_ONLY',
            cloudAvailable: {
                groq: !!process.env.GROQ_API_KEY,
                gemini: !!process.env.GEMINI_API_KEY,
                openai: !!process.env.OPENAI_API_KEY,
                anthropic: !!process.env.ANTHROPIC_API_KEY
            }
        };
    }
}

// Singleton instance
const modelRouter = new ModelRouter();

// BACKWARD COMPATIBILITY: Map to Cloud Models
modelRouter.models = {
    orchestrator: {
        primary: 'gpt-4o',
        fallback: 'gemini-1.5-pro'
    },
    technical: {
        primary: 'claude-3-5-sonnet-20241022',
        fallback: 'gpt-4o'
    },
    nlp: {
        primary: 'gemini-1.5-flash',
        fallback: 'llama-3.1-70b-versatile'
    },
    vision: {
        primary: 'gpt-4o',
        fallback: 'gemini-1.5-pro'
    },
    embedding: {
        primary: 'mxbai-embed-large:latest',
        fallback: 'snowflake-arctic-embed:latest'
    }
};

module.exports = modelRouter;
