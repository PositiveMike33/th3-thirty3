/**
 * CLOUD EMBEDDING SERVICE
 * Uses Gemini text-embedding-004 exclusively.
 */

const { GoogleGenerativeAI } = require('@google/generative-ai');

class EmbeddingService {
    constructor() {
        // Initialize Gemini from ENV or Settings
        const settings = require('./settings_service').getSettings();
        const geminiKey = process.env.GEMINI_API_KEY || settings.apiKeys.gemini;

        this.gemini = geminiKey
            ? new GoogleGenerativeAI(geminiKey)
            : null;

        // Cache for embeddings (reduces API calls)
        this.cache = new Map();
        this.maxCacheSize = 1000;

        // Statistics
        this.stats = {
            gemini_success: 0,
            gemini_failures: 0,
            cache_hits: 0
        };

        console.log('[EMBEDDING] Service initialized (Cloud Only)');
        console.log('[EMBEDDING] Priority: text-embedding-004 (Gemini)');
        console.log('[EMBEDDING] Gemini available:', !!this.gemini);
    }

    /**
     * Set preference (Legacy - ignored in Cloud Only)
     */
    setPreference(preferLocal = false) {
        console.log(`[EMBEDDING] Preference update ignored (Cloud Only Mode)`);
    }

    /**
     * Main embed function
     * @param {string|string[]} texts - Text(s) to embed
     * @param {string} preferredProvider - Ignored
     * @returns {Promise<number[]|number[][]>} Embedding vector(s)
     */
    async embed(texts, preferredProvider = 'gemini') {
        const isArray = Array.isArray(texts);
        const textArray = isArray ? texts : [texts];

        // Check cache first
        const cacheKey = JSON.stringify({ texts: textArray });
        if (this.cache.has(cacheKey)) {
            this.stats.cache_hits++;
            const result = this.cache.get(cacheKey);
            return isArray ? result : result[0];
        }

        let result = null;

        try {
            result = await this._embedWithGemini(textArray);
            this.stats.gemini_success++;
        } catch (geminiError) {
            console.error(`[EMBEDDING] Gemini failed: ${geminiError.message}`);
            this.stats.gemini_failures++;
            throw geminiError;
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
     * Embed using Gemini (CLOUD)
     * @private
     */
    async _embedWithGemini(texts) {
        if (!this.gemini) {
            throw new Error('Gemini not configured (missing GEMINI_API_KEY)');
        }

        const model = this.gemini.getGenerativeModel({ model: 'text-embedding-004' });
        const embeddings = [];

        for (const text of texts) {
            const result = await model.embedContent(text);
            embeddings.push(result.embedding.values);
        }

        return embeddings;
    }

    /**
     * Semantic search across documents
     */
    async semanticSearch(query, documents, topK = 5) {
        // Embed query
        const queryEmbedding = await this.embed(query);

        // Embed all documents
        const docTexts = documents.map(d => d.text || d.content || String(d));
        const docEmbeddings = await this.embed(docTexts);

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
        return {
            ...this.stats,
            cache_size: this.cache.size,
            gemini_available: !!this.gemini,
            primary_provider: 'Gemini (cloud)'
        };
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
            if (this.gemini) {
                const cloudResult = await this.embed('Test embedding with Gemini');
                console.log(`[EMBEDDING] ✅ Gemini: ${cloudResult.length} dimensions`);
                return { success: true, stats: this.getStats() };
            }
            return { success: false, error: 'Gemini not configured' };
        } catch (error) {
            console.error('[EMBEDDING] Test failed:', error.message);
            return { success: false, error: error.message };
        }
    }
}

module.exports = EmbeddingService;
