/**
 * Configuration Module
 * Centralized configuration management
 */

require('dotenv').config();

module.exports = {
    // Server Configuration
    server: {
        port: process.env.PORT || 8080,
        host: process.env.HOST || '0.0.0.0',
        env: process.env.NODE_ENV || 'production'
    },

    // AI Provider Configuration
    ai: {
        provider: process.env.AI_PROVIDER || 'anythingllm', // 'anythingllm', 'ollama', 'openrouter'
        
        // AnythingLLM
        anythingllm: {
            url: process.env.ANYTHING_LLM_URL || 'http://localhost:3001/api/v1',
            apiKey: process.env.ANYTHING_LLM_KEY,
            workspace: process.env.VPO_WORKSPACE || 'expert-senior-en-excellence-operationnelle-standard-vpowcm-et-specialiste-technique-des-machines-keelclip'
        },

        // Ollama (Local)
        ollama: {
            url: process.env.OLLAMA_URL || 'http://localhost:11434',
            model: process.env.OLLAMA_MODEL || 'llama3.2-vision:11b',
            embeddingModel: process.env.OLLAMA_EMBEDDING || 'nomic-embed-text'
        },

        // OpenRouter (Cloud)
        openrouter: {
            apiKey: process.env.OPENROUTER_API_KEY,
            model: process.env.OPENROUTER_MODEL || 'qwen/qwen-2.5-vl-72b-instruct',
            baseURL: 'https://openrouter.ai/api/v1'
        }
    },

    // VPO Standards
    vpo: {
        language: process.env.VPO_LANGUAGE || 'fr', // 'en', 'fr', 'es', 'pt'
        strictMode: process.env.VPO_STRICT === 'true', // Enforce strict VPO compliance
        requiredSections: ['QQOQCCP', '5-Why', 'Action Plan'],
        forbiddenTerms: ['erreur humaine', 'faute opérateur', 'inattention', 'négligence'],
        systemicCauses: ['Standard', 'CIL', 'OPL', 'Formation', 'Centerline', 'Maintenance préventive']
    },

    // Validation Thresholds
    validation: {
        minimumScore: 70, // Minimum acceptable score
        warningScore: 85, // Score below this triggers warning
        excellentScore: 95 // Score above this is excellent
    },

    // Logging
    logging: {
        level: process.env.LOG_LEVEL || 'info', // 'error', 'warn', 'info', 'debug'
        file: process.env.LOG_FILE || './logs/keelclip-vpo.log',
        console: process.env.LOG_CONSOLE !== 'false'
    },

    // Storage (for reports)
    storage: {
        type: process.env.STORAGE_TYPE || 'local', // 'local', 's3', 'azure'
        local: {
            path: process.env.STORAGE_PATH || './reports'
        }
    },

    // License Management
    license: {
        key: process.env.LICENSE_KEY,
        type: process.env.LICENSE_TYPE || 'trial', // 'trial', 'perpetual', 'subscription', 'enterprise'
        expiryDate: process.env.LICENSE_EXPIRY,
        maxReportsPerMonth: parseInt(process.env.MAX_REPORTS) || (
            process.env.LICENSE_TYPE === 'trial' ? 10 : -1 // -1 = unlimited
        )
    },

    // Feature Flags
    features: {
        visionAnalysis: process.env.FEATURE_VISION !== 'false',
        multiLanguage: process.env.FEATURE_MULTILANG === 'true',
        fabricIntegration: process.env.FEATURE_FABRIC === 'true',
        apiAccess: process.env.FEATURE_API !== 'false',
        cloudBackup: process.env.FEATURE_CLOUD_BACKUP === 'true'
    }
};
