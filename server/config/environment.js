/**
 * Nexus33 Backend Configuration
 * Centralized configuration for all environment variables
 * 
 * Usage: const config = require('./config/environment');
 */

require('dotenv').config();

// Detect environment
const isProduction = process.env.NODE_ENV === 'production';
const isDevelopment = !isProduction;

// Configuration object
const config = {
    // Environment
    env: {
        NODE_ENV: process.env.NODE_ENV || 'development',
        isProduction,
        isDevelopment
    },

    // Server
    server: {
        PORT: parseInt(process.env.PORT) || 3000,
        API_BASE_URL: process.env.API_BASE_URL || (isProduction ? 'https://api.nexus33.io' : 'http://localhost:3000'),
        FRONTEND_URL: process.env.FRONTEND_URL || (isProduction ? 'https://nexus33.io' : 'http://localhost:5173'),
        CORS_ORIGINS: (process.env.CORS_ORIGINS || 'http://localhost:5173,http://localhost:3000').split(',').map(s => s.trim())
    },

    // Database
    db: {
        MONGODB_URI: process.env.MONGODB_URI || 'mongodb://localhost:27017/nexus33'
    },

    // Authentication
    auth: {
        JWT_SECRET: process.env.JWT_SECRET || 'dev-secret-change-in-production',
        JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '7d'
    },

    // Ollama (Local AI)
    ollama: {
        BASE_URL: process.env.OLLAMA_BASE_URL || 'http://localhost:11434'
    },

    // Ollama Proxy Server (Security layer for Ollama)
    ollamaProxy: {
        ENABLED: process.env.OLLAMA_PROXY_ENABLED === 'true',
        BASE_URL: process.env.OLLAMA_PROXY_URL || 'http://localhost:8080',
        API_KEY: process.env.OLLAMA_PROXY_API_KEY || ''
    },

    // Google OAuth
    google: {
        CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
        CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
        REDIRECT_URI: process.env.GOOGLE_REDIRECT_URI || `${process.env.API_BASE_URL || 'http://localhost:3000'}/auth/google/callback`
    },

    // Stripe Payments
    stripe: {
        SECRET_KEY: process.env.STRIPE_SECRET_KEY,
        WEBHOOK_SECRET: process.env.STRIPE_WEBHOOK_SECRET,
        PRICES: {
            STARTER: process.env.STRIPE_PRICE_ID_STARTER,
            PRO: process.env.STRIPE_PRICE_ID_PRO,
            ENTERPRISE: process.env.STRIPE_PRICE_ID_ENTERPRISE
        }
    },

    // PayPal Payments
    paypal: {
        CLIENT_ID: process.env.PAYPAL_CLIENT_ID,
        CLIENT_SECRET: process.env.PAYPAL_CLIENT_SECRET,
        MODE: process.env.PAYPAL_MODE || 'sandbox'
    },

    // AI Providers
    ai: {
        OPENAI_API_KEY: process.env.OPENAI_API_KEY,
        ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY,
        PERPLEXITY_API_KEY: process.env.PERPLEXITY_API_KEY
    },

    // AnythingLLM
    anythingllm: {
        URL: process.env.ANYTHING_LLM_URL || 'http://localhost:3001',
        API_KEY: process.env.ANYTHING_LLM_KEY
    },

    // Kraken (Crypto)
    kraken: {
        API_KEY: process.env.KRAKEN_API_KEY,
        API_SECRET: process.env.KRAKEN_API_SECRET
    },

    // Security Services
    security: {
        AIKIDO_CLIENT_ID: process.env.AIKIDO_CLIENT_ID,
        AIKIDO_CLIENT_SECRET: process.env.AIKIDO_CLIENT_SECRET,
        SHODAN_API_KEY: process.env.SHODAN_API_KEY
    },

    // Dart AI
    dart: {
        API_KEY: process.env.DART_API_KEY
    },

    // Email (SMTP)
    email: {
        HOST: process.env.SMTP_HOST || 'smtp.gmail.com',
        PORT: parseInt(process.env.SMTP_PORT) || 587,
        USER: process.env.SMTP_USER,
        PASS: process.env.SMTP_PASS
    },

    // Obsidian
    obsidian: {
        VAULT_PATH: process.env.OBSIDIAN_VAULT_PATH
    },

    // MCP Protocol
    mcp: {
        PIECES_URL: process.env.PIECES_MCP_URL || 'http://localhost:39300/model_context_protocol/2024-11-05/sse'
    },

    // VPN/TOR
    anonymization: {
        TOR_SOCKS_PORT: parseInt(process.env.TOR_SOCKS_PORT) || 9050,
        TOR_CONTROL_PORT: parseInt(process.env.TOR_CONTROL_PORT) || 9051,
        PROTONVPN_USER: process.env.PROTONVPN_USER,
        PROTONVPN_PASS: process.env.PROTONVPN_PASS
    }
};

// Validation helper
config.validate = () => {
    const required = [];
    const warnings = [];

    // Critical in production
    if (isProduction) {
        if (!config.auth.JWT_SECRET || config.auth.JWT_SECRET === 'dev-secret-change-in-production') {
            required.push('JWT_SECRET must be set in production');
        }
        if (!config.db.MONGODB_URI.includes('mongodb')) {
            required.push('MONGODB_URI must be configured for production');
        }
    }

    // Warnings for optional features
    if (!config.google.CLIENT_ID) warnings.push('GOOGLE_CLIENT_ID not set - Google auth disabled');
    if (!config.stripe.SECRET_KEY) warnings.push('STRIPE_SECRET_KEY not set - Payments disabled');
    if (!config.ai.OPENAI_API_KEY) warnings.push('OPENAI_API_KEY not set - OpenAI features disabled');

    return { required, warnings, isValid: required.length === 0 };
};

// Log configuration on startup
config.logStatus = () => {
    console.log(`\n╔════════════════════════════════════════════════╗`);
    console.log(`║     NEXUS33 CONFIGURATION STATUS               ║`);
    console.log(`╠════════════════════════════════════════════════╣`);
    console.log(`║ Environment: ${config.env.NODE_ENV.toUpperCase().padEnd(33)}║`);
    console.log(`║ API URL: ${config.server.API_BASE_URL.padEnd(37)}║`);
    console.log(`║ Frontend: ${config.server.FRONTEND_URL.padEnd(36)}║`);
    console.log(`║ Ollama: ${config.ollama.BASE_URL.padEnd(38)}║`);
    console.log(`╚════════════════════════════════════════════════╝\n`);

    const validation = config.validate();
    
    if (validation.warnings.length > 0) {
        console.log('[CONFIG] Warnings:');
        validation.warnings.forEach(w => console.log(`  ⚠️  ${w}`));
    }
    
    if (!validation.isValid) {
        console.error('[CONFIG] CRITICAL ERRORS:');
        validation.required.forEach(e => console.error(`  ❌ ${e}`));
        if (isProduction) {
            throw new Error('Configuration validation failed in production');
        }
    }
};

module.exports = config;
