/**
 * HYBRID EMBEDDING SERVICE
 * Supports multiple embedding providers with automatic fallback
 * 
 * PRIORITY ORDER FOR LOCAL WORK:
 * 1. nomic-embed-text via Ollama (LOCAL FIRST for offline capability)
 * 2. Gemini (cloud fallback when online)
 * 
 * When working locally, nomic-embed-text is ALWAYS the first choice
 */

const { Ollama } = require('ollama');
const { GoogleGenerativeAI } = require('@google/generative-ai');

class EmbeddingService {
    constructor() {
        this.ollama = new Ollama({ host: process.env.OLLAMA_URL || 'http://localhost:11434' });
        this.gemini = process.env.GEMINI_API_KEY 
            ? new GoogleGenerativeAI(process.env.GEMINI_API_KEY) 
            : null;
        
        // Embedding model priority (MoE v2 primary, v1 fallback)
        this.localModels = [
            'nomic-embed-text-v2-moe:latest',
            'nomic-embed-text:latest'  // v1 fallback
        ];
        this.activeLocalModel = this.localModels[0];
        
        // Cache for embeddings (reduces API calls)
        this.cache = new Map();
        this.maxCacheSize = 1000;
        
        // Statistics
        this.stats = {
            ollama_success: 0,
            ollama_failures: 0,
            gemini_success: 0,
            gemini_failures: 0,
            cache_hits: 0,
            offline_mode_activations: 0
        };
        
        // Default to local mode (OFFLINE FIRST)
        this.preferLocal = true;
        this.isOfflineMode = false;
        
        console.log('[EMBEDDING] Service initialized - OFFLINE-FIRST MODE');
        console.log('[EMBEDDING] Local model: nomic-embed-text-v2-moe');
        console.log('[EMBEDDING] Gemini available:', !!this.gemini);
    }

    /**
     * Set preference for local or cloud embeddings
     */
    setPreference(preferLocal = true) {
        this.preferLocal = preferLocal;
        console.log(`[EMBEDDING] Preference set to: ${preferLocal ? 'LOCAL (nomic)' : 'CLOUD (gemini)'}`);
    }

    /**
     * Main embed function with automatic provider selection
     * @param {string|string[]} texts - Text(s) to embed
     * @param {string} preferredProvider - 'ollama', 'gemini', or 'auto' (default)
     * @returns {Promise<number[]|number[][]>} Embedding vector(s)
     */
    async embed(texts, preferredProvider = 'auto') {
        const isArray = Array.isArray(texts);
        const textArray = isArray ? texts : [texts];
        
        // Check cache first
        const cacheKey = JSON.stringify({ texts: textArray, provider: preferredProvider });
        if (this.cache.has(cacheKey)) {
            this.stats.cache_hits++;
            console.log('[EMBEDDING] Cache hit');
            const result = this.cache.get(cacheKey);
            return isArray ? result : result[0];
        }
        
        let result = null;
        
        // Determine provider order based on preference
        if (preferredProvider === 'ollama') {
            result = await this._embedWithOllama(textArray);
        } else if (preferredProvider === 'gemini') {
            result = await this._embedWithGemini(textArray);
        } else {
            // Auto mode: LOCAL FIRST (nomic), then Gemini
            if (this.preferLocal) {
                // Try Ollama (nomic) first
                try {
                    result = await this._embedWithOllama(textArray);
                    this.stats.ollama_success++;
                } catch (ollamaError) {
                    console.warn(`[EMBEDDING] Ollama failed: ${ollamaError.message}, trying Gemini...`);
                    this.stats.ollama_failures++;
                    
                    // Fallback to Gemini
                    if (this.gemini) {
                        try {
                            result = await this._embedWithGemini(textArray);
                            this.stats.gemini_success++;
                        } catch (geminiError) {
                            console.error(`[EMBEDDING] Both providers failed. Ollama: ${ollamaError.message}, Gemini: ${geminiError.message}`);
                            this.stats.gemini_failures++;
                            throw new Error('All embedding providers failed');
                        }
                    } else {
                        throw ollamaError;
                    }
                }
            } else {
                // Cloud first (Gemini), then Ollama
                if (this.gemini) {
                    try {
                        result = await this._embedWithGemini(textArray);
                        this.stats.gemini_success++;
                    } catch (geminiError) {
                        console.warn(`[EMBEDDING] Gemini failed: ${geminiError.message}, falling back to Ollama...`);
                        this.stats.gemini_failures++;
                        
                        try {
                            result = await this._embedWithOllama(textArray);
                            this.stats.ollama_success++;
                        } catch (ollamaError) {
                            this.stats.ollama_failures++;
                            throw new Error('All embedding providers failed');
                        }
                    }
                } else {
                    // No Gemini, use Ollama
                    result = await this._embedWithOllama(textArray);
                    this.stats.ollama_success++;
                }
            }
        }
        
        // Cache the result
        this.cache.set(cacheKey, result);
        
        // Manage cache size
        if (this.cache.size > this.maxCacheSize) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }
        
        return isArray ? result : result[0];
    }

    /**
     * Embed using Ollama with nomic-embed-text (LOCAL)
     * Tries MoE v2 first, falls back to v1, works completely offline
     * @private
     */
    async _embedWithOllama(texts) {
        console.log(`[EMBEDDING] Using ${this.activeLocalModel} (local) for ${texts.length} text(s)`);
        
        const embeddings = [];
        
        for (const text of texts) {
            let success = false;
            let lastError = null;
            
            // Try each local model in order
            for (const model of this.localModels) {
                try {
                    const response = await this.ollama.embeddings({
                        model: model,
                        prompt: text
                    });
                    embeddings.push(response.embedding);
                    
                    // Update active model if different
                    if (this.activeLocalModel !== model) {
                        this.activeLocalModel = model;
                        console.log(`[EMBEDDING] Switched to fallback model: ${model}`);
                    }
                    
                    success = true;
                    break;
                } catch (err) {
                    lastError = err;
                    console.warn(`[EMBEDDING] Model ${model} failed: ${err.message}`);
                }
            }
            
            if (!success) {
                throw lastError || new Error('All local embedding models failed');
            }
        }
        
        // Mark as offline mode since local worked
        if (!this.isOfflineMode) {
            this.isOfflineMode = true;
            console.log('[EMBEDDING] ✅ OFFLINE MODE ACTIVE - Using local embeddings only');
        }
        
        console.log(`[EMBEDDING] ✅ ${this.activeLocalModel} completed (${embeddings.length} embeddings)`);
        return embeddings;
    }

    /**
     * Embed using Gemini (CLOUD)
     * @private
     */
    async _embedWithGemini(texts) {
        if (!this.gemini) {
            throw new Error('Gemini not configured (missing GEMINI_API_KEY)');
        }
        
        console.log(`[EMBEDDING] Using Gemini (cloud) for ${texts.length} text(s)`);
        
        const model = this.gemini.getGenerativeModel({ model: 'text-embedding-004' });
        const embeddings = [];
        
        for (const text of texts) {
            const result = await model.embedContent(text);
            embeddings.push(result.embedding.values);
        }
        
        console.log(`[EMBEDDING] ✅ Gemini completed (${embeddings.length} embeddings)`);
        return embeddings;
    }

    /**
     * Semantic search across documents
     * @param {string} query - Search query
     * @param {Array<{text: string, ...}>} documents - Documents to search
     * @param {number} topK - Number of results to return
     * @param {string} provider - Embedding provider
     */
    async semanticSearch(query, documents, topK = 5, provider = 'auto') {
        // Embed query
        const queryEmbedding = await this.embed(query, provider);
        
        // Embed all documents
        const docTexts = documents.map(d => d.text || d.content || String(d));
        const docEmbeddings = await this.embed(docTexts, provider);
        
        // Calculate similarities
        const similarities = docEmbeddings.map((docEmbed, idx) => ({
            ...documents[idx],
            similarity: this.cosineSimilarity(queryEmbedding, docEmbed)
        }));
        
        // Sort and return top K
        return similarities
            .sort((a, b) => b.similarity - a.similarity)
            .slice(0, topK);
    }

    /**
     * Calculate cosine similarity between two vectors
     */
    cosineSimilarity(a, b) {
        if (!a || !b || a.length !== b.length) return 0;
        
        let dotProduct = 0;
        let normA = 0;
        let normB = 0;
        
        for (let i = 0; i < a.length; i++) {
            dotProduct += a[i] * b[i];
            normA += a[i] * a[i];
            normB += b[i] * b[i];
        }
        
        const denominator = Math.sqrt(normA) * Math.sqrt(normB);
        return denominator === 0 ? 0 : dotProduct / denominator;
    }

    /**
     * Get service statistics
     */
    getStats() {
        const totalRequests = this.stats.ollama_success + this.stats.ollama_failures +
                             this.stats.gemini_success + this.stats.gemini_failures;
        
        return {
            ...this.stats,
            cache_size: this.cache.size,
            total_requests: totalRequests,
            prefer_local: this.preferLocal,
            is_offline_mode: this.isOfflineMode,
            active_local_model: this.activeLocalModel,
            available_local_models: this.localModels,
            ollama_available: true,  // Always assume Ollama is available locally
            gemini_available: !!this.gemini && !this.isOfflineMode,
            primary_provider: `${this.activeLocalModel} (local)`
        };
    }

    /**
     * Force offline mode (disable cloud providers)
     */
    setOfflineMode(offline = true) {
        this.isOfflineMode = offline;
        if (offline) {
            this.preferLocal = true;
            this.stats.offline_mode_activations++;
            console.log('[EMBEDDING] ⚡ OFFLINE MODE ENABLED - Cloud providers disabled');
        } else {
            console.log('[EMBEDDING] 🌐 ONLINE MODE - Cloud providers available');
        }
    }

    /**
     * Check if a local model is available
     */
    async checkLocalModels() {
        const available = [];
        for (const model of this.localModels) {
            try {
                await this.ollama.embeddings({ model, prompt: 'test' });
                available.push(model);
            } catch {
                // Model not available
            }
        }
        return available;
    }

    /**
     * Clear cache
     */
    clearCache() {
        this.cache.clear();
        console.log('[EMBEDDING] Cache cleared');
    }

    /**
     * Test embedding functionality
     */
    async test() {
        try {
            console.log('[EMBEDDING] Running self-test...');
            
            // Test with nomic (local)
            const localResult = await this.embed('Test embedding with nomic', 'ollama');
            console.log(`[EMBEDDING] ✅ nomic-embed-text: ${localResult.length} dimensions`);
            
            // Test with Gemini if available
            if (this.gemini) {
                const cloudResult = await this.embed('Test embedding with Gemini', 'gemini');
                console.log(`[EMBEDDING] ✅ Gemini: ${cloudResult.length} dimensions`);
            }
            
            return { success: true, stats: this.getStats() };
        } catch (error) {
            console.error('[EMBEDDING] Test failed:', error.message);
            return { success: false, error: error.message };
        }
    }
}

module.exports = EmbeddingService;
