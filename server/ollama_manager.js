/**
 * Ollama Model Manager
 * Gère le chargement/déchargement automatique des modèles pour libérer RAM/VRAM
 * 
 * Features:
 * - Auto-unload after inactivity
 * - Single model loading to conserve memory
 * - Preload capability for embeddings
 * - Supports Ollama Proxy Server with API Key authentication
 */

const fetch = require('node-fetch');
const config = require('./config/environment');

// Determine which URL to use based on proxy configuration
const PROXY_ENABLED = config.ollamaProxy?.ENABLED;
const OLLAMA_URL = PROXY_ENABLED ? config.ollamaProxy.BASE_URL : config.ollama.BASE_URL;
const API_KEY = config.ollamaProxy?.API_KEY || '';

// Helper to build headers with optional auth
const getHeaders = () => {
    const headers = { 'Content-Type': 'application/json' };
    if (PROXY_ENABLED && API_KEY) {
        headers['Authorization'] = `Bearer ${API_KEY}`;
    }
    return headers;
};

class OllamaModelManager {
    constructor() {
        this.currentModel = null;
        this.unloadTimeout = null;
        this.UNLOAD_DELAY = 5 * 60 * 1000;  // 5 minutes d'inactivité
        this.loadedModels = new Set();
        
        console.log(`[OLLAMA] Model Manager initialized (${OLLAMA_URL})${PROXY_ENABLED ? ' [PROXY MODE]' : ''}`);
    }

    /**
     * Load a model via Ollama API
     * @param {string} modelName - Model to load
     * @returns {Promise<boolean>}
     */
    async loadModel(modelName) {
        try {
            // Check if already loaded
            if (this.currentModel === modelName) {
                console.log(`[OLLAMA] Model ${modelName} already loaded`);
                this.resetUnloadTimer(modelName);
                return true;
            }
            
            console.log(`[OLLAMA] Loading model via API: ${modelName}`);
            
            // Use generate endpoint with minimal prompt to trigger load
            const response = await fetch(`${OLLAMA_URL}/api/generate`, {
                method: 'POST',
                headers: getHeaders(),
                body: JSON.stringify({
                    model: modelName,
                    prompt: 'ping',
                    stream: false,
                    options: { num_predict: 1 },
                    keep_alive: '5m'  // Keep alive for 5 minutes
                })
            });
            
            if (!response.ok) {
                const errText = await response.text();
                throw new Error(`HTTP Error: ${response.status} - ${errText}`);
            }
            
            this.currentModel = modelName;
            this.loadedModels.add(modelName);
            this.resetUnloadTimer(modelName);
            
            console.log(`[OLLAMA] ✅ Model ${modelName} loaded`);
            return true;
            
        } catch (error) {
            console.error(`[OLLAMA] ❌ Failed to load ${modelName}:`, error.message);
            return false;
        }
    }

    /**
     * Unload a model to free RAM/VRAM
     * @param {string} modelName - Model to unload
     */
    async unloadModel(modelName) {
        try {
            console.log(`[OLLAMA] Unloading model: ${modelName}`);
            
            // Use keep_alive: 0 to immediately unload
            await fetch(`${OLLAMA_URL}/api/generate`, {
                method: 'POST',
                headers: getHeaders(),
                body: JSON.stringify({
                    model: modelName,
                    prompt: '',
                    keep_alive: 0
                })
            });
            
            if (this.currentModel === modelName) {
                this.currentModel = null;
            }
            this.loadedModels.delete(modelName);
            
            console.log(`[OLLAMA] Model ${modelName} unloaded`);
            return true;
            
        } catch (error) {
            console.error(`[OLLAMA] Failed to unload ${modelName}:`, error.message);
            return false;
        }
    }

    /**
     * Reset the auto-unload timer
     * @param {string} modelName
     */
    resetUnloadTimer(modelName) {
        // Clear existing timer
        if (this.unloadTimeout) {
            clearTimeout(this.unloadTimeout);
            this.unloadTimeout = null;
        }
        
        // Start new timer to unload after inactivity
        this.unloadTimeout = setTimeout(() => {
            console.log(`[OLLAMA] Auto-unloading ${modelName} after ${this.UNLOAD_DELAY / 1000}s inactivity`);
            this.unloadModel(modelName);
        }, this.UNLOAD_DELAY);
    }

    /**
     * Force unload current model immediately
     */
    async forceUnload() {
        if (this.currentModel) {
            await this.unloadModel(this.currentModel);
        }
        if (this.unloadTimeout) {
            clearTimeout(this.unloadTimeout);
            this.unloadTimeout = null;
        }
    }

    /**
     * Get list of currently loaded models
     */
    async getLoadedModels() {
        try {
            const response = await fetch(`${OLLAMA_URL}/api/ps`, { headers: getHeaders() });
            const data = await response.json();
            return data.models || [];
        } catch (error) {
            console.error('[OLLAMA] Failed to get loaded models:', error.message);
            return [];
        }
    }

    /**
     * Get list of all available models
     */
    async getAvailableModels() {
        try {
            const response = await fetch(`${OLLAMA_URL}/api/tags`, { headers: getHeaders() });
            const data = await response.json();
            return data.models || [];
        } catch (error) {
            console.error('[OLLAMA] Failed to get available models:', error.message);
            return [];
        }
    }

    /**
     * Preload embedding model (nomic-embed-text)
     */
    async preloadEmbedding() {
        try {
            console.log('[OLLAMA] Preloading nomic-embed-text for embeddings...');
            
            const response = await fetch(`${OLLAMA_URL}/api/embeddings`, {
                method: 'POST',
                headers: getHeaders(),
                body: JSON.stringify({
                    model: 'nomic-embed-text:latest',
                    prompt: 'preload test'
                })
            });
            
            if (response.ok) {
                console.log('[OLLAMA] ✅ nomic-embed-text preloaded');
                this.loadedModels.add('nomic-embed-text:latest');
                return true;
            }
            return false;
            
        } catch (error) {
            console.error('[OLLAMA] Failed to preload embedding model:', error.message);
            return false;
        }
    }

    /**
     * Get current model status
     */
    getStatus() {
        return {
            currentModel: this.currentModel,
            loadedModels: Array.from(this.loadedModels),
            autoUnloadEnabled: !!this.unloadTimeout,
            unloadDelay: this.UNLOAD_DELAY / 1000
        };
    }

    /**
     * Set unload delay
     */
    setUnloadDelay(seconds) {
        this.UNLOAD_DELAY = seconds * 1000;
        console.log(`[OLLAMA] Unload delay set to ${seconds}s`);
    }
}

// Singleton instance
const modelManager = new OllamaModelManager();

module.exports = modelManager;
