/**
 * Ollama Model Manager
 * Gère le chargement/déchargement automatique des modèles pour libérer RAM/VRAM
 */

const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

class OllamaModelManager {
    constructor() {
        this.currentModel = null;
        this.unloadTimeout = null;
        this.UNLOAD_DELAY = 5 * 60 * 1000; // 5 minutes d'inactivité
        console.log('[OLLAMA] Model Manager initialized');
    }

    /**
     * Load a model (if not already loaded)
     * @param {string} modelName - Model to load
     */
    async loadModel(modelName) {
        if (this.currentModel === modelName) {
            console.log(`[OLLAMA] Model ${modelName} already loaded`);
            this.resetUnloadTimer(modelName);
            return;
        }

        console.log(`[OLLAMA] Loading model: ${modelName}`);
        
        try {
            // Unload previous model if exists
            if (this.currentModel) {
                await this.unloadModel(this.currentModel);
            }

            // Load new model by making a dummy request
            await execPromise(`ollama run ${modelName} "test" --verbose`);
            
            this.currentModel = modelName;
            console.log(`[OLLAMA] ✓ Model ${modelName} loaded`);
            
            // Start auto-unload timer
            this.resetUnloadTimer(modelName);
            
        } catch (error) {
            console.error(`[OLLAMA] Failed to load ${modelName}:`, error.message);
            throw error;
        }
    }

    /**
     * Unload a model to free RAM/VRAM
     * @param {string} modelName - Model to unload
     */
    async unloadModel(modelName) {
        console.log(`[OLLAMA] Unloading model: ${modelName}`);
        
        try {
            // Send keep_alive=0 to unload
            const response = await fetch('http://localhost:11434/api/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: modelName,
                    keep_alive: 0
                })
            });

            if (response.ok) {
                console.log(`[OLLAMA] ✓ Model ${modelName} unloaded (RAM/VRAM freed)`);
                if (this.currentModel === modelName) {
                    this.currentModel = null;
                }
            }
        } catch (error) {
            console.error(`[OLLAMA] Failed to unload ${modelName}:`, error.message);
        }
    }

    /**
     * Reset the auto-unload timer
     * @param {string} modelName - Model name
     */
    resetUnloadTimer(modelName) {
        // Clear existing timer
        if (this.unloadTimeout) {
            clearTimeout(this.unloadTimeout);
        }

        // Set new timer to unload after inactivity
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
     * Get current model status
     */
    getStatus() {
        return {
            currentModel: this.currentModel,
            autoUnloadEnabled: !!this.unloadTimeout,
            unloadDelay: this.UNLOAD_DELAY / 1000
        };
    }
}

// Singleton instance
const modelManager = new OllamaModelManager();

module.exports = modelManager;
