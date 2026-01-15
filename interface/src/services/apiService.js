/**
 * Service API centralisé pour Th3 Thirty3 / Nexus33
 * Utilise la configuration centralisée pour toutes les URLs
 */

import { API_URL, OLLAMA_URL, WS_URL, IS_PROD } from '../config';

// Headers par défaut
const getHeaders = () => ({
    'Content-Type': 'application/json',
    'x-api-key': localStorage.getItem('th3_api_key') || ''
});

// Helper pour les requêtes fetch avec gestion d'erreur
const fetchWithError = async (url, options = {}) => {
    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                ...getHeaders(),
                ...options.headers
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        return response.json();
    } catch (error) {
        console.error(`API Error [${url}]:`, error);
        throw error;
    }
};

// ================================
// API Backend (Express)
// ================================

export const api = {
    // Base URL
    baseUrl: API_URL,

    // Generic HTTP Methods (Support for api.get, api.post patterns)
    get: (endpoint) => fetchWithError(`${API_URL}${endpoint.startsWith('/') ? endpoint : '/' + endpoint}`),

    post: (endpoint, data) => fetchWithError(`${API_URL}${endpoint.startsWith('/') ? endpoint : '/' + endpoint}`, {
        method: 'POST',
        body: JSON.stringify(data)
    }),

    put: (endpoint, data) => fetchWithError(`${API_URL}${endpoint.startsWith('/') ? endpoint : '/' + endpoint}`, {
        method: 'PUT',
        body: JSON.stringify(data)
    }),

    delete: (endpoint) => fetchWithError(`${API_URL}${endpoint.startsWith('/') ? endpoint : '/' + endpoint}`, {
        method: 'DELETE'
    }),

    // Chat

    chat: (message, provider, model) => fetchWithError(`${API_URL}/chat`, {
        method: 'POST',
        body: JSON.stringify({ message, provider, model })
    }),

    // Sessions
    getSessions: () => fetchWithError(`${API_URL}/sessions`),
    getSession: (id) => fetchWithError(`${API_URL}/sessions/${id}`),
    deleteSession: (id) => fetch(`${API_URL}/sessions/${id}`, { method: 'DELETE', headers: getHeaders() }),
    updateMessage: (sessionId, msgId, data) => fetchWithError(`${API_URL}/sessions/${sessionId}/messages/${msgId}`, {
        method: 'PUT',
        body: JSON.stringify(data)
    }),

    // Settings
    getSettings: () => fetchWithError(`${API_URL}/settings`),
    saveSettings: (settings) => fetchWithError(`${API_URL}/settings`, {
        method: 'POST',
        body: JSON.stringify(settings)
    }),

    // Models
    getModels: () => fetchWithError(`${API_URL}/models`),
    getModelMetrics: () => fetchWithError(`${API_URL}/models/metrics`),
    trackModelQuery: (modelName, data) => fetch(`${API_URL}/models/${encodeURIComponent(modelName)}/track-query`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify(data)
    }),
    benchmarkModel: (modelName) => fetchWithError(`${API_URL}/models/${encodeURIComponent(modelName)}/benchmark`, {
        method: 'POST'
    }),

    // Dashboard
    getDashboardSummary: () => fetchWithError(`${API_URL}/api/dashboard/summary`),

    // Patterns (Fabric)
    getPatterns: () => fetchWithError(`${API_URL}/patterns`),
    getPattern: (name) => fetchWithError(`${API_URL}/patterns/${name}`),

    // Feedback
    sendFeedback: (feedback) => fetchWithError(`${API_URL}/feedback`, {
        method: 'POST',
        body: JSON.stringify(feedback)
    }),

    // Training
    getTrainingCommentary: () => fetch(`${API_URL}/training/commentary`, { headers: getHeaders() }).then(r => r.json()).catch(() => ({})),
    triggerTraining: () => fetchWithError(`${API_URL}/training/commentary/trigger`, { method: 'POST' }),

    // Cyber Training
    getCyberSummary: () => fetchWithError(`${API_URL}/api/cyber-training/aikido/summary`),
    trainCyber: (data) => fetchWithError(`${API_URL}/api/cyber-training/train`, {
        method: 'POST',
        body: JSON.stringify(data)
    }),
    explainCyber: (data) => fetchWithError(`${API_URL}/api/cyber-training/explain`, {
        method: 'POST',
        body: JSON.stringify(data)
    }),

    // Finance
    getPortfolio: () => fetchWithError(`${API_URL}/finance/portfolio`),
    getTicker: (symbol) => fetchWithError(`${API_URL}/finance/ticker?symbol=${symbol}`),
    getNews: () => fetchWithError(`${API_URL}/finance/news`),

    // Projects
    getProjects: () => fetchWithError(`${API_URL}/projects`),
    createProject: (data) => fetchWithError(`${API_URL}/projects`, {
        method: 'POST',
        body: JSON.stringify(data)
    }),
    deleteProject: (id) => fetch(`${API_URL}/projects/${id}`, { method: 'DELETE', headers: getHeaders() }),
    addTask: (projectId, data) => fetchWithError(`${API_URL}/projects/${projectId}/tasks`, {
        method: 'POST',
        body: JSON.stringify(data)
    }),
    updateTask: (projectId, taskId, data) => fetchWithError(`${API_URL}/projects/${projectId}/tasks/${taskId}`, {
        method: 'PUT',
        body: JSON.stringify(data)
    }),
    deleteTask: (projectId, taskId) => fetch(`${API_URL}/projects/${projectId}/tasks/${taskId}`, { method: 'DELETE', headers: getHeaders() }),

    // Google
    getGoogleStatus: () => fetch(`${API_URL}/google/status`, { headers: getHeaders() }).then(r => r.json()).catch(() => ({ authenticated: false })),
    getGoogleAuthUrl: (email) => `${API_URL}/auth/google?email=${email}`,
    getCalendar: () => fetchWithError(`${API_URL}/google/calendar`),
    getEmails: () => fetchWithError(`${API_URL}/google/emails`),
    getTasks: () => fetchWithError(`${API_URL}/google/tasks`),
    getDrive: () => fetchWithError(`${API_URL}/google/drive`),

    // OSINT
    osintSearch: (query, type) => fetchWithError(`${API_URL}/osint/search`, {
        method: 'POST',
        body: JSON.stringify({ query, type })
    }),

    // Dart Tasks
    getDartTasks: () => fetchWithError(`${API_URL}/api/dart/tasks`),
    createDartTask: (data) => fetchWithError(`${API_URL}/api/dart/tasks`, {
        method: 'POST',
        body: JSON.stringify(data)
    }),

    // Auth
    login: (credentials) => fetchWithError(`${API_URL}/auth/login`, {
        method: 'POST',
        body: JSON.stringify(credentials)
    }),
    getAuthStatus: () => fetch(`${API_URL}/auth/status`, { headers: getHeaders() }).then(r => r.json()).catch(() => ({ authenticated: false })),

    // Payments
    getSubscription: () => fetchWithError(`${API_URL}/payments/subscription`),
    createCheckout: (plan) => fetchWithError(`${API_URL}/payments/create-checkout`, {
        method: 'POST',
        body: JSON.stringify({ plan })
    })
};

// ================================
// Ollama API
// ================================

export const ollama = {
    baseUrl: OLLAMA_URL,

    // Get models list
    getTags: () => fetch(`${OLLAMA_URL}/api/tags`).then(r => r.json()).catch(() => ({ models: [] })),

    // Get running models
    getRunning: () => fetch(`${OLLAMA_URL}/api/ps`).then(r => r.json()).catch(() => ({ models: [] })),

    // Generate
    generate: (model, prompt, options = {}) => fetch(`${OLLAMA_URL}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model, prompt, ...options })
    }),

    // Chat
    chat: (model, messages, options = {}) => fetch(`${OLLAMA_URL}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model, messages, ...options })
    }),

    // Pull model
    pull: (name) => fetch(`${OLLAMA_URL}/api/pull`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name })
    }),

    // Delete model
    delete: (name) => fetch(`${OLLAMA_URL}/api/delete`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name })
    })
};

// ================================
// WebSocket
// ================================

export const getWebSocketUrl = () => WS_URL;

// ================================
// Export config helpers
// ================================

export const isProduction = () => IS_PROD;
export const getApiUrl = () => API_URL;
export const getOllamaUrl = () => OLLAMA_URL;

export default api;
