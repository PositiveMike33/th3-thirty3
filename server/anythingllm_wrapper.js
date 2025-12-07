/**
 * ANYTHINGLLM WRAPPER WITH EMBEDDING FALLBACK
 * 
 * Intercepts AnythingLLM requests and handles embedding errors gracefully
 * by falling back to local embeddings when Gemini is unavailable
 */

const EmbeddingService = require('./embedding_service');
const settingsService = require('./settings_service');

class AnythingLLMWrapper {
    constructor() {
        this.embeddingService = new EmbeddingService();
        this.baseUrl = null;
        this.apiKey = null;
        this.workspaceSlug = null;
    }

    /**
     * Initialize connection to AnythingLLM
     */
    async initialize() {
        const settings = settingsService.getSettings();
        this.baseUrl = settings.apiKeys.anythingllm_url || process.env.ANYTHING_LLM_URL;
        this.apiKey = settings.apiKeys.anythingllm_key || process.env.ANYTHING_LLM_KEY;

        if (!this.baseUrl || !this.apiKey) {
            throw new Error('AnythingLLM configuration missing');
        }

        // Get workspace slug
        const res = await fetch(`${this.baseUrl}/workspaces`, {
            headers: { 'Authorization': `Bearer ${this.apiKey}` }
        });

        if (!res.ok) {
            throw new Error(`Failed to fetch workspaces: ${res.status}`);
        }

        const data = await res.json();
        const preferred = data.workspaces.find(w => w.slug.includes('thirty3'));
        this.workspaceSlug = preferred ? preferred.slug : data.workspaces[0].slug;

        console.log(`[ANYTHINGLLM] Connected to workspace: ${this.workspaceSlug}`);
    }

    /**
     * Send chat message with automatic embedding fallback
     */
    async chat(message, mode = 'chat', userId = null) {
        if (!this.workspaceSlug) {
            await this.initialize();
        }

        console.log(`[ANYTHINGLLM] Sending message to ${this.workspaceSlug}...`);

        try {
            // Attempt normal chat
            const chatRes = await fetch(`${this.baseUrl}/workspace/${this.workspaceSlug}/chat`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    message,
                    mode,
                    userId
                })
            });

            if (!chatRes.ok) {
                const errorBody = await chatRes.text();
                
                // Check if it's an embedding error
                if (errorBody.includes('Failed to embed') || errorBody.includes('Gemini Failed to embed')) {
                    console.log('[ANYTHINGLLM] Embedding error detected, using fallback strategy...');
                    return await this._chatWithLocalEmbeddings(message, mode);
                }
                
                throw new Error(`AnythingLLM chat failed: ${chatRes.status} - ${errorBody}`);
            }

            const chatData = await chatRes.json();
            return chatData.textResponse;

        } catch (error) {
            if (error.message.includes('Failed to embed') || error.message.includes('Connection error')) {
                console.log('[ANYTHINGLLM] Network/Embedding error, using local fallback...');
                return await this._chatWithLocalEmbeddings(message, mode);
            }
            throw error;
        }
    }

    /**
     * Fallback: Use local embeddings + local LLM when AnythingLLM embeddings fail
     */
    async _chatWithLocalEmbeddings(message, mode) {
        console.log('[FALLBACK] Using local embeddings + RAG');

        // 1. Get relevant documents using local embeddings
        const documents = await this._getWorkspaceDocuments();
        
        if (documents.length > 0) {
            // 2. Find similar documents
            const relevant = await this.embeddingService.findSimilar(message, documents, 3, 'ollama');
            
            // 3. Build context-enhanced prompt
            const context = relevant.map(doc => doc.text).join('\n\n');
            const enhancedPrompt = `Context from knowledge base:\n${context}\n\nUser question: ${message}`;
            
            console.log(`[FALLBACK] Found ${relevant.length} relevant documents`);
            
            // 4. Use local Ollama for response (you could also call LLM service here)
            const { Ollama } = require('ollama');
            const ollama = new Ollama();
            
            const response = await ollama.chat({
                model: 'granite3.1-moe:1b',
                messages: [
                    { 
                        role: 'system', 
                        content: 'You are Th3 Thirty3, a cybersecurity expert. Answer based on the provided context.' 
                    },
                    { role: 'user', content: enhancedPrompt }
                ]
            });
            
            return `[OFFLINE MODE - Local RAG] ${response.message.content}`;
        } else {
            // No documents available, use plain local LLM
            console.log('[FALLBACK] No documents available, using plain local LLM');
            const { Ollama } = require('ollama');
            const ollama = new Ollama();
            
            const response = await ollama.chat({
                model: 'granite3.1-moe:1b',
                messages: [
                    { role: 'system', content: 'You are Th3 Thirty3, a cybersecurity expert.' },
                    { role: 'user', content: message }
                ]
            });
            
            return `[OFFLINE MODE] ${response.message.content}`;
        }
    }

    /**
     * Fetch workspace documents (simplified - you may need to adapt based on your setup)
     */
    async _getWorkspaceDocuments() {
        try {
            const docsRes = await fetch(`${this.baseUrl}/workspace/${this.workspaceSlug}/documents`, {
                headers: { 'Authorization': `Bearer ${this.apiKey}` }
            });

            if (docsRes.ok) {
                const data = await docsRes.json();
                return data.documents || [];
            }
        } catch (e) {
            console.log('[FALLBACK] Could not fetch workspace documents:', e.message);
        }
        
        return [];
    }

    /**
     * Get embedding service stats
     */
    getStats() {
        return this.embeddingService.getStats();
    }
}

module.exports = AnythingLLMWrapper;
