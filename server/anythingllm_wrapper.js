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
        let baseURL = settings.apiKeys.anythingllm_url || process.env.ANYTHING_LLM_URL;
        this.apiKey = settings.apiKeys.anythingllm_key || process.env.ANYTHING_LLM_KEY;

        if (!baseURL || !this.apiKey) {
            throw new Error('AnythingLLM configuration missing');
        }

        // Ensure correct API endpoint structure
        if (!baseURL.endsWith('/api/v1')) {
            baseURL = baseURL.replace(/\/+$/, '') + '/api/v1';
        }
        this.baseUrl = baseURL;

        // Get workspace slug
        const res = await fetch(`${this.baseUrl}/workspaces`, {
            headers: { 'Authorization': `Bearer ${this.apiKey}` }
        });

        if (!res.ok) {
            throw new Error(`Failed to fetch workspaces: ${res.status}`);
        }

        const data = await res.json();
        const preferred = data.workspaces.find(w => w.slug.includes('thirty3') || w.slug.includes('geo') || w.slug.includes('agent'));
        this.workspaceSlug = preferred ? preferred.slug : (data.workspaces[0] ? data.workspaces[0].slug : null);

        if (!this.workspaceSlug) {
            throw new Error('No workspaces found in AnythingLLM');
        }

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

        // INJECT MAP CONTROL PROTOCOL
        // This instructs the model (regardless of its system prompt) on how to control the UI.
        const mapProtocol = `
[SYSTEM INSTRUCTION: INTERFACE CONTROLLER]
You are a Voice-to-UI Controller for a tactical map dashboard.
Your job is NOT to physically move or drive. Your job is to generate JSON commands that the dashboard interface interprets to show routes and locations.

Valid JSON Commands:
1. ROUTE: {"action": "route", "waypoints": ["Origin", "Waypoint 1", "Destination"]}
2. HIGHLIGHT: {"action": "highlight", "location": "Exact Place Name", "description": "Short info"}

RULES:
- If the user asks for a route, DO NOT say "I cannot navigate". Instead, GENERATE the JSON for the route.
- If the user asks to see a place, GENERATE the highlight JSON.
- Always include the JSON block at the very end of your response.
`;
        const enrichedMessage = `${mapProtocol}\n\nUSER REQUEST: ${message}`;

        try {
            // Attempt normal chat
            const chatRes = await fetch(`${this.baseUrl}/workspace/${this.workspaceSlug}/chat`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    message: enrichedMessage,
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
            // Updated error handling to catch all connection-related issues
            const isConnectionError = error.message.includes('Failed to embed') ||
                error.message.includes('Connection error') ||
                error.message.includes('fetch failed') ||
                error.message.includes('ECONNREFUSED');

            if (isConnectionError) {
                console.log(`[ANYTHINGLLM] Connection issue detected (${error.message}), using local fallback...`);
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

        // Get Ollama URL from settings
        const settings = settingsService.getSettings();
        const apiKeys = settings.apiKeys || {};
        const ollamaUrl = apiKeys.ollama_use_proxy
            ? (apiKeys.ollama_proxy_url || 'http://localhost:8080')
            : (apiKeys.ollama_direct_url || 'http://localhost:11434');

        // 1. Get relevant documents using local embeddings
        const documents = await this._getWorkspaceDocuments();

        const mapSystemPrompt = `You are Th3 Thirty3, a tactical AI assistant.
[MAP PROTOCOL]
To control the map, output JSON:
- Route: {"action": "route", "waypoints": ["A", "B"]}
- Highlight: {"action": "highlight", "location": "X"}
`;

        if (documents.length > 0) {
            // 2. Find similar documents
            const relevant = await this.embeddingService.findSimilar(message, documents, 3, 'ollama');

            // 3. Build context-enhanced prompt
            const context = relevant.map(doc => doc.text).join('\n\n');
            const enhancedPrompt = `Context from knowledge base:\n${context}\n\nUser question: ${message}`;

            console.log(`[FALLBACK] Found ${relevant.length} relevant documents`);

            // 4. Use Ollama for response (via proxy or direct)
            const { Ollama } = require('ollama');
            const ollama = new Ollama({ host: ollamaUrl });

            const response = await ollama.chat({
                model: 'granite4:latest',
                messages: [
                    {
                        role: 'system',
                        content: mapSystemPrompt
                    },
                    { role: 'user', content: enhancedPrompt }
                ]
            });

            return `[OFFLINE MODE - Local RAG] ${response.message.content}`;
        } else {
            // No documents available, use plain local LLM
            console.log('[FALLBACK] No documents available, using plain local LLM');
            const { Ollama } = require('ollama');
            const ollama = new Ollama({ host: ollamaUrl });

            const response = await ollama.chat({
                model: 'granite4:latest',
                messages: [
                    { role: 'system', content: mapSystemPrompt },
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
