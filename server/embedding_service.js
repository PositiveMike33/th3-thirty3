/**
 * HYBRID EMBEDDING SERVICE
 * Supports multiple embedding providers with automatic fallback
 * - Primary: Gemini (fast, cloud-based)
 * - Fallback: nomic-embed-text via Ollama (local, offline)
 */

const { Ollama } = require('ollama');
const { GoogleGenerativeAI } = require('@google/generative-ai');

class EmbeddingService {
    constructor() {
        this.ollama = new Ollama();
        this.gemini = process.env.GEMINI_API_KEY ? new GoogleGenerativeAI(process.env.GEMINI_API_KEY) : null;
        this.cache = new Map(); // Simple in-memory cache
        this.stats = {
            gemini_success: 0,
            gemini_failures: 0,
            ollama_success: 0,
            ollama_failures: 0
        };
    }

    /**
     * Generate embeddings with automatic provider selection
     * @param {string|string[]} text - Text or array of texts to embed
     * @param {string} preferredProvider - 'gemini', 'ollama', or 'auto' (default)
     * @returns {Promise<number[]|number[][]>} Embedding vector(s)
     */
    async embed(text, preferredProvider = 'auto') {
        const isArray = Array.isArray(text);
        const texts = isArray ? text : [text];

        // Check cache first
        const cacheKey = JSON.stringify({ texts, provider: preferredProvider });
        if (this.cache.has(cacheKey)) {
            console.log('[EMBEDDING] Cache hit');
            return this.cache.get(cacheKey);
        }

        let result;

        if (preferredProvider === 'auto') {
            // Try Gemini first (faster), fallback to Ollama
            try {
                result = await this._embedWithGemini(texts);
                this.stats.gemini_success++;
            } catch (geminiError) {
                console.log(`[EMBEDDING] Gemini failed: ${geminiError.message}, falling back to Ollama...`);
                this.stats.gemini_failures++;
                try {
                    result = await this._embedWithOllama(texts);
                    this.stats.ollama_success++;
                } catch (ollamaError) {
                    this.stats.ollama_failures++;
                    throw new Error(`All embedding providers failed. Gemini: ${geminiError.message}, Ollama: ${ollamaError.message}`);
                }
            }
        } else if (preferredProvider === 'gemini') {
            result = await this._embedWithGemini(texts);
            this.stats.gemini_success++;
        } else if (preferredProvider === 'ollama') {
            result = await this._embedWithOllama(texts);
            this.stats.ollama_success++;
        } else {
            throw new Error(`Unknown embedding provider: ${preferredProvider}`);
        }

        // Cache the result
        this.cache.set(cacheKey, result);
        if (this.cache.size > 100) {
            // Simple LRU: delete oldest entry
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }

        return isArray ? result : result[0];
    }

    /**
     * Generate embeddings using Gemini
     */
    async _embedWithGemini(texts) {
        if (!this.gemini) {
            throw new Error('Gemini API key not configured');
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
     * Generate embeddings using Ollama (nomic-embed-text)
     */
    async _embedWithOllama(texts) {
        const embeddings = [];

        for (const text of texts) {
            const response = await this.ollama.embeddings({
                model: 'nomic-embed-text',
                prompt: text
            });
            embeddings.push(response.embedding);
        }

        return embeddings;
    }

    /**
     * Calculate cosine similarity between two embeddings
     */
    cosineSimilarity(embeddingA, embeddingB) {
        if (embeddingA.length !== embeddingB.length) {
            throw new Error('Embeddings must have the same dimension');
        }

        let dotProduct = 0;
        let normA = 0;
        let normB = 0;

        for (let i = 0; i < embeddingA.length; i++) {
            dotProduct += embeddingA[i] * embeddingB[i];
            normA += embeddingA[i] * embeddingA[i];
            normB += embeddingB[i] * embeddingB[i];
        }

        return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
    }

    /**
     * Find most similar texts from a collection
     * @param {string} query - Query text
     * @param {Array<{text: string, metadata?: any}>} documents - Document collection
     * @param {number} topK - Number of results to return
     * @param {string} provider - Embedding provider to use
     */
    async findSimilar(query, documents, topK = 5, provider = 'auto') {
        console.log(`[EMBEDDING] Finding similar documents for query (${documents.length} total)`);

        // Embed query
        const queryEmbedding = await this.embed(query, provider);

        // Embed all documents
        const docTexts = documents.map(d => d.text);
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
     * Get service statistics
     */
    getStats() {
        return {
            ...this.stats,
            cache_size: this.cache.size,
            total_requests: this.stats.gemini_success + this.stats.gemini_failures + 
                           this.stats.ollama_success + this.stats.ollama_failures,
            gemini_available: !!this.gemini,
            fallback_rate: this.stats.ollama_success / (this.stats.gemini_failures || 1)
        };
    }

    /**
     * Clear cache
     */
    clearCache() {
        this.cache.clear();
        console.log('[EMBEDDING] Cache cleared');
    }
}

module.exports = EmbeddingService;
