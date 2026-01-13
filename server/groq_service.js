/**
 * Groq API Service
 * Modèles ultra-rapides pour Th3 Thirty3
 * Llama 3.1, Mixtral, Gemma à vitesse éclair
 */

class GroqService {
    constructor() {
        this.apiKey = process.env.GROQ_API_KEY || '';
        this.baseUrl = 'https://api.groq.com/openai/v1';
        
        // Modèles disponibles sur Groq (ultra-rapides)
        this.models = {
            // Llama 3.1 - Meilleurs modèles
            'llama-3.1-70b-versatile': {
                name: 'Llama 3.1 70B',
                description: 'Modèle polyvalent ultra-performant',
                contextWindow: 131072,
                speed: 'ultra-fast'
            },
            'llama-3.1-8b-instant': {
                name: 'Llama 3.1 8B Instant',
                description: 'Réponses instantanées, parfait pour chat',
                contextWindow: 131072,
                speed: 'instant'
            },
            // Mixtral
            'mixtral-8x7b-32768': {
                name: 'Mixtral 8x7B',
                description: 'MoE puissant, excellent raisonnement',
                contextWindow: 32768,
                speed: 'very-fast'
            },
            // Gemma
            'gemma2-9b-it': {
                name: 'Gemma 2 9B',
                description: 'Modèle Google compact et efficace',
                contextWindow: 8192,
                speed: 'fast'
            },
            // Llama 3 Guard
            'llama-guard-3-8b': {
                name: 'Llama Guard 3',
                description: 'Modération de contenu et sécurité',
                contextWindow: 8192,
                speed: 'instant'
            }
        };

        this.defaultModel = 'llama-3.1-8b-instant';
        
        if (this.apiKey) {
            console.log('[GROQ] Service initialized with API key');
        } else {
            console.log('[GROQ] Service initialized - No API key configured');
        }
    }

    /**
     * Vérifier si le service est configuré
     */
    isConfigured() {
        return !!this.apiKey;
    }

    /**
     * Définir la clé API
     */
    setApiKey(key) {
        this.apiKey = key;
        console.log('[GROQ] API key configured');
    }

    /**
     * Obtenir la liste des modèles disponibles
     */
    getAvailableModels() {
        return Object.entries(this.models).map(([id, info]) => ({
            id,
            ...info,
            provider: 'groq'
        }));
    }

    /**
     * Envoyer un message au modèle Groq
     */
    async chat(messages, options = {}) {
        if (!this.apiKey) {
            throw new Error('Groq API key not configured');
        }

        const model = options.model || this.defaultModel;
        
        try {
            const response = await fetch(`${this.baseUrl}/chat/completions`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model,
                    messages,
                    temperature: options.temperature || 0.7,
                    max_tokens: options.maxTokens || 4096,
                    top_p: options.topP || 1,
                    stream: options.stream || false
                })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error?.message || `Groq API error: ${response.status}`);
            }

            const data = await response.json();
            
            return {
                success: true,
                content: data.choices[0]?.message?.content || '',
                model,
                usage: data.usage,
                provider: 'groq'
            };
        } catch (error) {
            console.error('[GROQ] Error:', error.message);
            return {
                success: false,
                error: error.message,
                provider: 'groq'
            };
        }
    }

    /**
     * Chat simple avec un seul message
     */
    async simpleChat(prompt, model = null) {
        return this.chat([
            { role: 'user', content: prompt }
        ], { model: model || this.defaultModel });
    }

    /**
     * Streaming de réponse
     */
    async streamChat(messages, options = {}) {
        if (!this.apiKey) {
            throw new Error('Groq API key not configured');
        }

        const model = options.model || this.defaultModel;

        const response = await fetch(`${this.baseUrl}/chat/completions`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${this.apiKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model,
                messages,
                temperature: options.temperature || 0.7,
                max_tokens: options.maxTokens || 4096,
                stream: true
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error?.message || `Groq API error: ${response.status}`);
        }

        return response.body;
    }

    /**
     * Tester la connexion à Groq
     */
    async testConnection() {
        try {
            const result = await this.simpleChat('Say "Groq connected!" in one line.');
            return {
                success: result.success,
                message: result.content || result.error,
                model: this.defaultModel
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
}

module.exports = GroqService;
