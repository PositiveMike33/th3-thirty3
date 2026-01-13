/**
 * Configuration centralisée pour Th3 Thirty3 / Nexus33
 * 
 * POUR PASSER EN PRODUCTION:
 * 1. Définir NODE_ENV=production lors du build
 * 2. Ou modifier manuellement FORCE_PRODUCTION = true
 */

// Forcer le mode production (mettre true pour déployer sur nexus33.io)
const FORCE_PRODUCTION = false;

// Détection automatique du mode (Vite uses import.meta.env)
const IS_LOCALHOST = typeof window !== 'undefined' &&
    (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');

const IS_PRODUCTION = !IS_LOCALHOST && (
    FORCE_PRODUCTION ||
    import.meta.env.MODE === 'production' ||
    import.meta.env.PROD === true ||
    (typeof window !== 'undefined' && window.location.hostname === 'nexus33.io')
);

// Configuration par environnement
const ENVIRONMENTS = {
    development: {
        API_URL: 'http://localhost:3000',
        FRONTEND_URL: 'http://localhost:5173',
        OLLAMA_URL: 'http://localhost:11434',
        ANYTHINGLLM_URL: 'http://localhost:3001', // AnythingLLM usually 3001
        WS_URL: 'ws://localhost:3000',
        DOMAIN: 'localhost'
    },
    production: {
        API_URL: 'https://api.nexus33.io',
        FRONTEND_URL: 'https://nexus33.io',
        OLLAMA_URL: 'https://ollama.nexus33.io',
        ANYTHINGLLM_URL: 'https://llm.nexus33.io',
        WS_URL: 'wss://api.nexus33.io',
        DOMAIN: 'nexus33.io'
    }
};

// Sélection de l'environnement
const ENV = IS_PRODUCTION ? ENVIRONMENTS.production : ENVIRONMENTS.development;

// Export de la configuration d'application
export const APP_CONFIG = {
    name: "Th3 Thirty3",
    displayName: IS_PRODUCTION ? "Nexus33" : "Th3 Thirty3",
    version: "1.3.0",
    theme: {
        primary: "#00ff41",     // Matrix Green
        secondary: "#800080",   // Cyberpunk Purple
        background: "#131314",
        sidebar: "#1e1f20",
        accent: "#28292a",
        cyan: "#22d3ee",
        danger: "#ef4444"
    },
    defaultAvatar: "Avatar",

    // URLs dynamiques selon l'environnement
    apiBaseUrl: ENV.API_URL,
    frontendUrl: ENV.FRONTEND_URL,
    ollamaUrl: ENV.OLLAMA_URL,
    anythingLLMUrl: ENV.ANYTHINGLLM_URL,
    wsUrl: ENV.WS_URL,
    domain: ENV.DOMAIN,

    // Flags d'environnement
    isProduction: IS_PRODUCTION,
    isDevelopment: !IS_PRODUCTION
};

// Exports individuels pour import direct
export const API_URL = ENV.API_URL;
export const FRONTEND_URL = ENV.FRONTEND_URL;
export const OLLAMA_URL = ENV.OLLAMA_URL;
export const ANYTHINGLLM_URL = ENV.ANYTHINGLLM_URL;
export const WS_URL = ENV.WS_URL;
export const DOMAIN = ENV.DOMAIN;
export const IS_DEV = !IS_PRODUCTION;
export const IS_PROD = IS_PRODUCTION;

// Helper pour construire les URLs
export const apiUrl = (path) => `${ENV.API_URL}${path.startsWith('/') ? path : '/' + path}`;
export const wsUrl = (path) => `${ENV.WS_URL}${path.startsWith('/') ? path : '/' + path}`;
export const ollamaUrl = (path) => `${ENV.OLLAMA_URL}${path.startsWith('/') ? path : '/' + path}`;

// Log au démarrage (dev only)
if (!IS_PRODUCTION && typeof window !== 'undefined') {
    console.log('🔧 Th3 Thirty3 Config:', {
        mode: IS_PRODUCTION ? 'PRODUCTION' : 'DEVELOPMENT',
        api: ENV.API_URL,
        frontend: ENV.FRONTEND_URL,
        ollama: ENV.OLLAMA_URL
    });
}

export default APP_CONFIG;
