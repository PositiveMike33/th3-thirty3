/**
 * PERFORMANCE MODE CONFIGURATION
 * Optimized for laptop performance - minimal model usage
 * 
 * Features:
 * - HackerGPT as primary chat model (via Groq - no local VRAM)
 * - Auto-unload local models after 30 seconds of inactivity
 * - Disable cloud providers when not in use
 * - Aggressive memory management
 */

const PERFORMANCE_CONFIG = {
    // Mode settings
    enabled: true,
    mode: 'laptop', // 'laptop' | 'desktop' | 'server'
    
    // Primary model configuration
    primaryModel: {
        provider: 'groq',
        model: 'llama-3.3-70b-versatile', // HackerGPT via Groq (no local VRAM needed)
        name: 'HackerGPT',
        fallback: 'llama-3.1-8b-instant'
    },
    
    // Local model management
    localModels: {
        enabled: false, // Disable Ollama by default in performance mode
        autoUnloadSeconds: 30, // Unload after 30 seconds of inactivity
        maxLoadedModels: 1, // Maximum 1 model loaded at a time
        preferredModel: null // No preferred local model
    },
    
    // Cloud providers
    cloudProviders: {
        groq: { 
            enabled: true, // Primary - HackerGPT
            rateLimit: 30, // requests per minute
            priority: 1
        },
        gemini: { 
            enabled: false, // Disabled for performance
            priority: 2
        },
        openai: { 
            enabled: false, // Disabled for performance
            priority: 3
        },
        claude: { 
            enabled: false, // Disabled for performance
            priority: 4
        },
        deepseek: { 
            enabled: false, // Disabled for performance
            priority: 5
        },
        runpod: { 
            enabled: false, // Disabled - uses GPU
            priority: 6
        },
        perplexity: { 
            enabled: false, // Disabled for performance
            priority: 7
        },
        anythingllm: { 
            enabled: false, // Disabled for performance
            priority: 8
        }
    },
    
    // Memory management
    memory: {
        aggressiveGC: true, // Force garbage collection
        maxHeapMB: 512, // Limit heap size
        unloadUnusedModels: true,
        cacheTimeout: 10000 // 10 second cache timeout (vs 30s normal)
    },
    
    // Feature toggles for performance
    features: {
        ragEnabled: true, // Keep RAG for knowledge
        fibonacciOptimizer: false, // Disable for performance
        socketBroadcast: false, // Reduce socket overhead
        modelMetrics: false, // Disable metrics tracking
        learningLoop: false // Disable autonomous learning
    },
    
    // Auto-shutdown timers (seconds)
    autoShutdown: {
        ollamaInactivity: 30, // Unload Ollama models after 30s
        cloudSessionTimeout: 300, // 5 min cloud session
        backgroundTasksPause: true // Pause background tasks when idle
    }
};

// Performance mode helpers
class PerformanceManager {
    constructor() {
        this.config = PERFORMANCE_CONFIG;
        this.lastActivity = Date.now();
        this.loadedModels = new Set();
        this.unloadTimer = null;
    }
    
    // Record activity to prevent auto-unload
    recordActivity() {
        this.lastActivity = Date.now();
        this.resetUnloadTimer();
    }
    
    // Start unload timer
    resetUnloadTimer() {
        if (this.unloadTimer) {
            clearTimeout(this.unloadTimer);
        }
        
        if (this.config.enabled && this.config.localModels.autoUnloadSeconds > 0) {
            this.unloadTimer = setTimeout(() => {
                this.unloadAllLocalModels();
            }, this.config.localModels.autoUnloadSeconds * 1000);
        }
    }
    
    // Unload all local models to free VRAM
    async unloadAllLocalModels() {
        if (this.loadedModels.size === 0) return;
        
        console.log('[PERFORMANCE] Auto-unloading local models to free VRAM...');
        
        const { Ollama } = require('ollama');
        const ollama = new Ollama({ host: process.env.OLLAMA_URL || 'http://localhost:11434' });
        
        for (const model of this.loadedModels) {
            try {
                await ollama.generate({ model, prompt: '', keep_alive: 0 });
                console.log(`[PERFORMANCE] Unloaded: ${model}`);
            } catch (e) {
                console.log(`[PERFORMANCE] Failed to unload ${model}: ${e.message}`);
            }
        }
        
        this.loadedModels.clear();
        
        // Force garbage collection if available
        if (this.config.memory.aggressiveGC && global.gc) {
            global.gc();
            console.log('[PERFORMANCE] Garbage collection triggered');
        }
    }
    
    // Track loaded model
    modelLoaded(modelName) {
        this.loadedModels.add(modelName);
        this.recordActivity();
    }
    
    // Check if provider is enabled
    isProviderEnabled(providerId) {
        if (!this.config.enabled) return true; // Performance mode disabled, allow all
        
        if (providerId === 'local' || providerId === 'ollama') {
            return this.config.localModels.enabled;
        }
        
        return this.config.cloudProviders[providerId]?.enabled ?? false;
    }
    
    // Get primary model for chat
    getPrimaryModel() {
        return this.config.primaryModel;
    }
    
    // Check if feature is enabled
    isFeatureEnabled(feature) {
        return this.config.features[feature] ?? true;
    }
    
    // Get status
    getStatus() {
        return {
            performanceMode: this.config.enabled,
            mode: this.config.mode,
            primaryModel: this.config.primaryModel.name,
            loadedModels: Array.from(this.loadedModels),
            lastActivity: new Date(this.lastActivity).toISOString(),
            idleSeconds: Math.floor((Date.now() - this.lastActivity) / 1000),
            features: this.config.features,
            enabledProviders: Object.entries(this.config.cloudProviders)
                .filter(([_, v]) => v.enabled)
                .map(([k, _]) => k)
        };
    }
    
    // Toggle performance mode
    setEnabled(enabled) {
        this.config.enabled = enabled;
        console.log(`[PERFORMANCE] Mode ${enabled ? 'ENABLED' : 'DISABLED'}`);
        
        if (enabled) {
            this.resetUnloadTimer();
        } else if (this.unloadTimer) {
            clearTimeout(this.unloadTimer);
            this.unloadTimer = null;
        }
    }
    
    // Enable/disable specific provider
    setProviderEnabled(providerId, enabled) {
        if (this.config.cloudProviders[providerId]) {
            this.config.cloudProviders[providerId].enabled = enabled;
            console.log(`[PERFORMANCE] Provider ${providerId} ${enabled ? 'enabled' : 'disabled'}`);
        }
    }
}

// Singleton instance
const performanceManager = new PerformanceManager();

module.exports = {
    PERFORMANCE_CONFIG,
    performanceManager
};
