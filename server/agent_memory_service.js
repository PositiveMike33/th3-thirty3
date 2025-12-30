/**
 * Agent Memory Service - Embeddings + Pieces Integration
 * Mémoire persistante pour les agents experts via embeddings et Pieces
 */

const fs = require('fs');
const path = require('path');
const settingsService = require('./settings_service');

class AgentMemoryService {
    constructor() {
        // Load settings
        const settings = settingsService.getSettings();
        const apiKeys = settings.apiKeys || {};

        // Ollama URL from settings (proxy or direct)
        this.ollamaUrl = apiKeys.ollama_use_proxy
            ? (apiKeys.ollama_proxy_url || 'http://localhost:8080')
            : (apiKeys.ollama_direct_url || 'http://localhost:11434');

        this.embeddingModel = 'mxbai-embed-large:latest';
        this.dataPath = path.join(__dirname, 'data', 'embeddings');
        this.piecesUrl = apiKeys.pieces_host || 'http://localhost:39300';

        this.ensureDataFolder();
        this.loadEmbeddings();

        console.log(`[AGENT-MEMORY] Embedding service initialized (Ollama: ${this.ollamaUrl})`);
    }

    ensureDataFolder() {
        if (!fs.existsSync(this.dataPath)) {
            fs.mkdirSync(this.dataPath, { recursive: true });
        }
    }

    loadEmbeddings() {
        this.embeddings = {};
        const embeddingsFile = path.join(this.dataPath, 'agent_embeddings.json');

        if (fs.existsSync(embeddingsFile)) {
            this.embeddings = JSON.parse(fs.readFileSync(embeddingsFile, 'utf8'));
            console.log(`[AGENT-MEMORY] Loaded ${Object.keys(this.embeddings).length} embedding collections`);
        }
    }

    saveEmbeddings() {
        const embeddingsFile = path.join(this.dataPath, 'agent_embeddings.json');
        fs.writeFileSync(embeddingsFile, JSON.stringify(this.embeddings, null, 2));
    }

    /**
     * Générer un embedding avec mxbai-embed-large
     */
    async generateEmbedding(text) {
        try {
            const response = await fetch(`${this.ollamaUrl}/api/embeddings`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: this.embeddingModel,
                    prompt: text
                })
            });

            if (!response.ok) {
                throw new Error(`Embedding error: ${response.status}`);
            }

            const data = await response.json();
            return data.embedding;
        } catch (error) {
            console.error('[AGENT-MEMORY] Embedding error:', error.message);
            return null;
        }
    }

    /**
     * Calculer la similarité cosinus entre deux vecteurs
     */
    cosineSimilarity(vecA, vecB) {
        if (!vecA || !vecB || vecA.length !== vecB.length) return 0;

        let dotProduct = 0;
        let normA = 0;
        let normB = 0;

        for (let i = 0; i < vecA.length; i++) {
            dotProduct += vecA[i] * vecB[i];
            normA += vecA[i] * vecA[i];
            normB += vecB[i] * vecB[i];
        }

        return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
    }

    /**
     * Stocker une connaissance avec son embedding pour un agent
     */
    async storeKnowledge(agentId, knowledge, metadata = {}) {
        const embedding = await this.generateEmbedding(knowledge);
        if (!embedding) return false;

        if (!this.embeddings[agentId]) {
            this.embeddings[agentId] = [];
        }

        this.embeddings[agentId].push({
            id: Date.now().toString(),
            content: knowledge,
            embedding: embedding,
            metadata: { ...metadata, timestamp: new Date().toISOString() }
        });

        // Limiter à 500 embeddings par agent
        if (this.embeddings[agentId].length > 500) {
            this.embeddings[agentId] = this.embeddings[agentId].slice(-500);
        }

        this.saveEmbeddings();
        console.log(`[AGENT-MEMORY] Stored knowledge for ${agentId}: ${knowledge.substring(0, 50)}...`);
        return true;
    }

    /**
     * Rechercher des connaissances similaires pour un agent
     */
    async searchKnowledge(agentId, query, topK = 5) {
        const queryEmbedding = await this.generateEmbedding(query);
        if (!queryEmbedding) return [];

        const agentEmbeddings = this.embeddings[agentId] || [];
        if (agentEmbeddings.length === 0) return [];

        // Calculer les similarités
        const results = agentEmbeddings.map(item => ({
            ...item,
            similarity: this.cosineSimilarity(queryEmbedding, item.embedding)
        }));

        // Trier par similarité et retourner top K
        return results
            .sort((a, b) => b.similarity - a.similarity)
            .slice(0, topK)
            .map(({ embedding, ...rest }) => rest); // Exclure l'embedding du résultat
    }

    /**
     * Rechercher dans TOUS les agents (collaboration)
     */
    async searchAllAgents(query, topK = 10) {
        const queryEmbedding = await this.generateEmbedding(query);
        if (!queryEmbedding) return [];

        const allResults = [];

        for (const [agentId, embeddings] of Object.entries(this.embeddings)) {
            for (const item of embeddings) {
                allResults.push({
                    agentId,
                    content: item.content,
                    metadata: item.metadata,
                    similarity: this.cosineSimilarity(queryEmbedding, item.embedding)
                });
            }
        }

        return allResults
            .sort((a, b) => b.similarity - a.similarity)
            .slice(0, topK);
    }

    /**
     * Synchroniser avec Pieces (si disponible)
     */
    async syncWithPieces(agentId, knowledge) {
        try {
            // Vérifier si Pieces est disponible
            const healthCheck = await fetch(`${this.piecesUrl}/health`, {
                method: 'GET',
                signal: AbortSignal.timeout(2000)
            }).catch(() => null);

            if (!healthCheck || !healthCheck.ok) {
                console.log('[AGENT-MEMORY] Pieces not available, skipping sync');
                return false;
            }

            // Créer un snippet dans Pieces
            const response = await fetch(`${this.piecesUrl}/assets/create`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    application: 'th3thirty3-agents',
                    format: { classification: { specific: 'md' } },
                    metadata: {
                        name: `Agent ${agentId} - Knowledge`,
                        description: knowledge.substring(0, 100),
                        tags: ['agent', agentId, 'knowledge']
                    },
                    original: {
                        reference: { fragment: { string: { raw: knowledge } } }
                    }
                })
            });

            if (response.ok) {
                console.log(`[AGENT-MEMORY] Synced to Pieces: ${agentId}`);
                return true;
            }
        } catch (error) {
            console.log('[AGENT-MEMORY] Pieces sync failed:', error.message);
        }
        return false;
    }

    /**
     * Obtenir le contexte enrichi pour un agent basé sur une query
     */
    async getEnrichedContext(agentId, query) {
        const relevantKnowledge = await this.searchKnowledge(agentId, query, 3);
        const crossAgentKnowledge = await this.searchAllAgents(query, 2);

        let context = '';

        if (relevantKnowledge.length > 0) {
            context += '\n\n📚 CONNAISSANCES MÉMORISÉES:\n';
            context += relevantKnowledge.map(k => `- ${k.content}`).join('\n');
        }

        // Ajouter connaissances d'autres agents si pertinentes
        const otherAgentsKnowledge = crossAgentKnowledge.filter(k => k.agentId !== agentId);
        if (otherAgentsKnowledge.length > 0) {
            context += '\n\n🔗 CONNAISSANCES D\'AUTRES AGENTS:\n';
            context += otherAgentsKnowledge.map(k => `- [${k.agentId}] ${k.content}`).join('\n');
        }

        return context;
    }

    /**
     * Statistiques de mémoire
     */
    getMemoryStats() {
        const stats = {};
        for (const [agentId, embeddings] of Object.entries(this.embeddings)) {
            stats[agentId] = {
                totalKnowledge: embeddings.length,
                lastUpdated: embeddings.length > 0
                    ? embeddings[embeddings.length - 1].metadata?.timestamp
                    : null
            };
        }
        return stats;
    }

    /**
     * Nettoyer les anciens embeddings
     */
    cleanup(agentId, keepLast = 100) {
        if (this.embeddings[agentId]) {
            this.embeddings[agentId] = this.embeddings[agentId].slice(-keepLast);
            this.saveEmbeddings();
        }
    }
}

module.exports = AgentMemoryService;
