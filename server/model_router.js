/**
 * Model Router Service - CLOUD ONLY
 * Routes agents to optimal cloud models based on expertise
 * 
 * CLOUD MODELS (via API):
 * - Groq (Llama, Mixtral) - FAST
 * - Gemini (Flash, Pro) - SMART
 * - OpenAI (GPT-4o) - BEST
 */

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
        this.preferLocal = false; // Forced to false for Cloud Only
    }

    /**
     * Initialize the router - Check specific cloud connectivity if needed
     */
    async initialize() {
        if (this.initialized) return true;

        console.log('[MODEL_ROUTER] Initializing (CLOUD ONLY mode)...');
        console.log('[MODEL_ROUTER] Available Providers: Groq, Gemini, OpenAI, Anthropic');

        this.initialized = true;
        return true;
    }

    /**
     * Route to optimal model based on task
     * @param {string} domain - Task type (code, security, general, fast)
     * @param {boolean} forceLocal - IGNORED in Cloud Only mode
     * @param {boolean} forceCloud - Always true
     * @returns {Object} - { model, isLocal, provider }
     */
    async routeToModel(domain = 'general', forceLocal = false, forceCloud = true) {
        const normalizedDomain = domain.toLowerCase();

        // Check available API keys
        const hasGroq = !!process.env.GROQ_API_KEY;
        const hasGemini = !!process.env.GEMINI_API_KEY;
        const hasOpenAI = !!process.env.OPENAI_API_KEY;
        const hasAnthropic = !!process.env.ANTHROPIC_API_KEY;

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
        console.warn('[MODEL_ROUTER] ⚠️ No Cloud API Keys found! Defaulting to Mock/Error');
        return {
            model: 'error-no-keys',
            isLocal: false,
            provider: 'error',
            error: 'No Cloud API Keys configured'
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
        primary: 'text-embedding-3-small',
        fallback: 'text-embedding-004'
    }
};

module.exports = modelRouter;
