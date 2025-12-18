
const { Ollama } = require('ollama');
const OpenAI = require('openai');
const Anthropic = require('@anthropic-ai/sdk');
const AnythingLLMWrapper = require('./anythingllm_wrapper');
const knowledgeBase = require('./knowledge_base_service');

class LLMService {
    constructor() {
        this.ollama = new Ollama();
        this.socketService = null;
        this.modelMetricsService = null;
        this.anythingLLMWrapper = new AnythingLLMWrapper();
        this.knowledgeBase = knowledgeBase; // RAG Knowledge Base
        this.providers = {
            local: { name: 'Local (Ollama)', type: 'local' },
            openai: { name: 'OpenAI (ChatGPT)', type: 'cloud' },
            claude: { name: 'Anthropic Claude', type: 'cloud' },
            groq: { name: 'Groq (Ultra-Fast)', type: 'cloud' },
            lmstudio: { name: 'LM Studio (Private)', type: 'local' },
            anythingllm: { name: 'AnythingLLM (Agents)', type: 'cloud' }
        };
    }

    setSocketService(socketService) {
        this.socketService = socketService;
    }

    setModelMetricsService(modelMetricsService) {
        this.modelMetricsService = modelMetricsService;
    }

    /**
     * Lists all available models (Local + Cloud + Agents).
     */
    async listModels(computeMode = 'local') {
        // Note: Called frequently by frontend polling, avoid verbose logging
        const models = { local: [], cloud: [] };

        // --- LOCAL MODE (Always Available) ---
        // 1. Ollama
        try {
            // Wrap Ollama call in a timeout promise
            const list = await Promise.race([
                this.ollama.list(),
                new Promise((_, reject) => setTimeout(() => reject(new Error("Ollama Timeout")), 2000))
            ]);
            models.local = list.models.map(m => m.name);
        } catch (e) {
            console.error("Failed to list local models:", e.message);
            models.local = ["Ollama Offline"];
        }

        // 2. LM Studio
        if (process.env.LM_STUDIO_URL) {
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 2000); // 2s timeout

                const response = await fetch(`${process.env.LM_STUDIO_URL}/models`, { signal: controller.signal });
                clearTimeout(timeoutId);

                if (response.ok) {
                    const data = await response.json();
                    const lmModels = data.data.map(m => `[LMS] ${m.id}`);
                    models.local.push(...lmModels);
                }
            } catch (e) {
                // console.log("LM Studio offline");
                models.local.push("[LMS] Offline");
            }
        }

        // --- CLOUD MODE ---
        if (computeMode === 'cloud') {
            // Gemini
            // if (process.env.GEMINI_API_KEY) {
            //     models.cloud.push({ id: 'gemini-1.5-flash', name: 'Gemini 1.5 Flash', provider: 'gemini' });
            //     models.cloud.push({ id: 'gemini-1.5-pro', name: 'Gemini 1.5 Pro', provider: 'gemini' });
            // }

            // OpenAI - All Available Models
            if (process.env.OPENAI_API_KEY) {
                // GPT-4o Series
                models.cloud.push({ id: 'gpt-4o', name: '🟢 GPT-4o (Flagship)', provider: 'openai' });
                models.cloud.push({ id: 'gpt-4o-mini', name: '🟢 GPT-4o Mini', provider: 'openai' });
                models.cloud.push({ id: 'chatgpt-4o-latest', name: '🟢 ChatGPT-4o Latest', provider: 'openai' });
                
                // O1 Reasoning Series
                models.cloud.push({ id: 'o1', name: '🧠 O1 (Reasoning)', provider: 'openai' });
                models.cloud.push({ id: 'o1-mini', name: '🧠 O1 Mini', provider: 'openai' });
                models.cloud.push({ id: 'o1-preview', name: '🧠 O1 Preview', provider: 'openai' });
                
                // O3 Series (Latest)
                models.cloud.push({ id: 'o3-mini', name: '⚡ O3 Mini (Fast)', provider: 'openai' });
                
                // GPT-4 Turbo
                models.cloud.push({ id: 'gpt-4-turbo', name: '🔵 GPT-4 Turbo', provider: 'openai' });
                models.cloud.push({ id: 'gpt-4-turbo-preview', name: '🔵 GPT-4 Turbo Preview', provider: 'openai' });
                
                // GPT-4 Classic
                models.cloud.push({ id: 'gpt-4', name: '🔵 GPT-4', provider: 'openai' });
                
                // GPT-3.5
                models.cloud.push({ id: 'gpt-3.5-turbo', name: '⚪ GPT-3.5 Turbo', provider: 'openai' });
            }

            // Claude (Anthropic)
            if (process.env.ANTHROPIC_API_KEY) {
                models.cloud.push({ id: 'claude-3-5-sonnet-20241022', name: 'Claude 3.5 Sonnet', provider: 'claude' });
                models.cloud.push({ id: 'claude-3-opus-20240229', name: 'Claude 3 Opus', provider: 'claude' });
            }

            // Groq (Ultra-fast) - Modèles actuels vérifiés
            if (process.env.GROQ_API_KEY) {
                models.cloud.push({ id: 'llama-3.3-70b-versatile', name: '⚡ Llama 3.3 70B Versatile', provider: 'groq' });
                models.cloud.push({ id: 'llama-3.1-8b-instant', name: '⚡ Llama 3.1 8B Instant', provider: 'groq' });
                models.cloud.push({ id: 'qwen/qwen3-32b', name: '⚡ Qwen 3 32B', provider: 'groq' });
                models.cloud.push({ id: 'groq/compound', name: '⚡ Groq Compound', provider: 'groq' });
            }

            // Perplexity
            if (process.env.PERPLEXITY_API_KEY) {
                models.cloud.push({ id: 'sonar', name: '🔍 Perplexity Sonar', provider: 'perplexity' });
                models.cloud.push({ id: 'sonar-pro', name: '🔍 Perplexity Sonar Pro', provider: 'perplexity' });
                models.cloud.push({ id: 'sonar-reasoning', name: '🧠 Perplexity Sonar Reasoning', provider: 'perplexity' });
            }

            // AnythingLLM (Agents)
            if (process.env.ANYTHING_LLM_URL && process.env.ANYTHING_LLM_KEY) {
                try {
                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => controller.abort(), 5000); // 5s timeout

                    const response = await fetch(`${process.env.ANYTHING_LLM_URL}/openai/models`, {
                        headers: { 'Authorization': `Bearer ${process.env.ANYTHING_LLM_KEY}` },
                        signal: controller.signal
                    });
                    clearTimeout(timeoutId);

                    if (response.ok) {
                        const data = await response.json();
                        if (data && data.data) {
                            const agents = data.data.map(m => ({
                                id: m.id,
                                name: `[AGENT] ${m.id}`,
                                provider: 'anythingllm'
                            }));
                            models.cloud.push(...agents);
                        }
                    }
                } catch (e) {
                    console.error("Failed to list AnythingLLM agents (Timeout/Error):", e.message);
                }
            }
        }

        return models;
    }

    /**
     * Analyzes OSINT tool output using a specific Expert Persona.
     */
    async analyzeOsintResult(toolId, output, provider = 'local', model = 'granite3.1-moe:1b') {
        const personas = {
            sherlock: `You are 'Ghost', an Elite Social Engineer and Profiler with 20+ years of experience in tracking targets across the digital footprint. 
            Analyze the provided Sherlock username search results. 
            Identify patterns in platform usage, potential high-value accounts (GitHub, Twitter, etc.), and suggest specific social engineering vectors or further investigation steps. 
            Be direct, cynical, and extremely professional. Format your response as a tactical intelligence brief.`,

            spiderfoot: `You are 'Watcher', a Senior Cyber Intelligence Analyst with 20+ years of experience in automated reconnaissance and threat modeling.
            Analyze the provided SpiderFoot scan summary or status.
            Identify critical vulnerabilities, potential data leaks, and infrastructure weaknesses.
            Highlight any "smoking guns" or anomalies in the data.
            Format your response as a high-priority threat assessment.`,

            whois: `You are 'Architect', a Veteran Infrastructure Investigator with 20+ years of experience in domain attribution and network mapping.
            Analyze the provided WHOIS/DNS data.
            Look for registrar patterns, hosting history, potential obfuscation techniques (Cloudflare, privacy guards), and connections to known threat actors.
            Format your response as a network infrastructure analysis.`,

            default: `You are a Senior OSINT Investigator with 20+ years of experience.
            Analyze the provided tool output.
            Extract key intelligence, identify anomalies, and recommend the next phase of the investigation.
            Be concise and professional.`
        };

        const systemPrompt = personas[toolId] || personas.default;
        const prompt = `[TOOL OUTPUT START]\n${output}\n[TOOL OUTPUT END]\n\nAnalyze this data based on your persona.`;

        // Use the requested provider/model, or fallback to a smart default if not specified
        // For analysis, we prefer a smarter model if available (e.g., Gemini Flash/Pro)
        let targetProvider = provider;
        let targetModel = model;

        if (process.env.ANYTHING_LLM_KEY && provider === 'local') {
            targetProvider = 'anythingllm';
            targetModel = 'gpt-4o'; // Default to a strong model via AnythingLLM
        }

        return await this.generateResponse(prompt, null, targetProvider, targetModel, systemPrompt);
    }

    async generateResponse(prompt, imageBase64, providerId, modelId, systemPrompt) {
        console.log(`[LLM] Request: Provider=${providerId}, Model=${modelId}`);
        
        // RAG AUGMENTATION: Inject relevant knowledge context
        let augmentedPrompt = prompt;
        const ragContext = this.knowledgeBase.buildRAGContext(prompt);
        if (ragContext) {
            augmentedPrompt = ragContext + '\n\nUSER QUERY: ' + prompt;
            console.log('[LLM] RAG context injected (knowledge base hit)');
        }
        
        if (this.socketService) {
            this.socketService.emitAgentStart({ provider: providerId, model: modelId, prompt: augmentedPrompt });
            this.socketService.emitAgentStatus("Thinking...");
        }

        try {
            // RESOURCE MANAGEMENT:
            // If we are NOT using local/ollama, ensure we unload any loaded local models to free VRAM
            // This is critical when running AnythingLLM or other heavy local apps alongside.
            if (providerId !== 'local') {
                // We don't await this to avoid slowing down the request
                this.unloadModel('granite3.1-moe:1b').catch(e => console.log("[LLM] Background unload failed:", e.message));
            }

            let response;
            switch (providerId) {

                case 'openai':
                    response = await this.generateOpenAIResponse(augmentedPrompt, imageBase64, modelId, systemPrompt);
                    break;
                case 'claude':
                    response = await this.generateClaudeResponse(augmentedPrompt, imageBase64, modelId, systemPrompt);
                    break;
                case 'groq':
                    response = await this.generateGroqResponse(augmentedPrompt, modelId, systemPrompt);
                    break;
                case 'perplexity':
                    response = await this.generatePerplexityResponse(augmentedPrompt, modelId, systemPrompt);
                    break;
                case 'openrouter':
                    response = await this.generateOpenRouterResponse(augmentedPrompt, imageBase64, modelId, systemPrompt);
                    break;
                case 'anythingllm':
                case 'cloud': // Force Cloud mode to AnythingLLM
                    response = await this.generateAnythingLLMResponse(augmentedPrompt, modelId, systemPrompt);
                    break;
                case 'lmstudio':
                    response = await this.generateLMStudioResponse(augmentedPrompt, modelId, systemPrompt);
                    break;
                case 'local':
                default:
                    response = await this.generateOllamaResponse(augmentedPrompt, imageBase64, modelId, systemPrompt);
                    break;
            }

            if (this.socketService) {
                this.socketService.emitAgentEnd(response);
                this.socketService.emitAgentStatus("Idle");
            }
            return response;
        } catch (error) {
            console.error(`[LLM] Error with ${providerId}:`, error);
            if (this.socketService) this.socketService.emitAgentStatus("Error");
            return `⚠️ Erreur (${providerId}): ${error.message}`;
        }
    }

    // --- PROVIDER IMPLEMENTATIONS ---

    // --- GENERIC OPENAI-COMPATIBLE HANDLER ---
    async generateOpenAICompatibleResponse(prompt, imageBase64, modelId, systemPrompt, config) {
        const { apiKey, baseURL, extraHeaders, providerName } = config;

        if (!apiKey && providerName !== 'lmstudio') { // LM Studio doesn't strictly need a key but SDK might
            throw new Error(`${providerName.toUpperCase()}_API_KEY missing`);
        }

        const client = new OpenAI({
            apiKey: apiKey || 'dummy-key',
            baseURL: baseURL
        });

        const messages = [
            { role: "system", content: systemPrompt },
            {
                role: "user",
                content: imageBase64 && providerName === 'openai' // Only OpenAI supports standard image_url in this specific way for now
                    ? [
                        { type: "text", text: prompt },
                        { type: "image_url", image_url: { url: imageBase64 } }
                    ]
                    : prompt
            }
        ];

        const params = {
            model: modelId,
            messages: messages,
        };

        if (extraHeaders) {
            params.extraHeaders = extraHeaders;
        }

        const completion = await client.chat.completions.create(params);
        return completion.choices[0].message.content;
    }

    // --- SPECIFIC WRAPPERS ---

    async generateOpenAIResponse(prompt, imageBase64, modelId, systemPrompt) {
        return this.generateOpenAICompatibleResponse(prompt, imageBase64, modelId || "gpt-4o-mini", systemPrompt, {
            apiKey: process.env.OPENAI_API_KEY,
            providerName: 'openai'
        });
    }

    async generatePerplexityResponse(prompt, modelId, systemPrompt) {
        return this.generateOpenAICompatibleResponse(prompt, null, modelId || "sonar", systemPrompt, {
            apiKey: process.env.PERPLEXITY_API_KEY,
            baseURL: 'https://api.perplexity.ai',
            providerName: 'perplexity'
        });
    }

    async generateGroqResponse(prompt, modelId, systemPrompt) {
        return this.generateOpenAICompatibleResponse(prompt, null, modelId || "llama-3.1-8b-instant", systemPrompt, {
            apiKey: process.env.GROQ_API_KEY,
            baseURL: 'https://api.groq.com/openai/v1',
            providerName: 'groq'
        });
    }

    async generateOpenRouterResponse(prompt, imageBase64, modelId, systemPrompt) {
        return this.generateOpenAICompatibleResponse(prompt, null, modelId || "auto", systemPrompt, {
            apiKey: process.env.OPENROUTER_API_KEY,
            baseURL: 'https://openrouter.ai/api/v1',
            providerName: 'openrouter',
            extraHeaders: {
                "HTTP-Referer": "http://localhost:3000",
                "X-Title": "Thirty3 Agent"
            }
        });
    }

    async generateAnythingLLMResponse(prompt, modelId, systemPrompt) {
        if (this.socketService) {
            this.socketService.emitAgentStatus("Accessing Private Web (AnythingLLM with Hybrid Embeddings)...");
        }

        const startTime = Date.now();
        const workspaceName = this.anythingLLMWrapper.workspaceSlug || 'th3-thirty3-workspace';
        const metricsModelName = `[ANYTHINGLLM] ${workspaceName}`;

        try {
            // Use the wrapper which handles Gemini → nomic-embed-text fallback automatically
            const response = await this.anythingLLMWrapper.chat(prompt, 'chat');
            const responseTime = Date.now() - startTime;
            
            // Record metrics for Training Dashboard
            if (this.modelMetricsService) {
                const tokensEstimate = Math.floor((response?.length || 0) / 4);
                this.modelMetricsService.recordQuery(metricsModelName, {
                    responseTime,
                    tokensGenerated: tokensEstimate,
                    success: true,
                    category: 'chat',
                    qualityScore: Math.min(85, 50 + Math.floor(tokensEstimate / 10)) // Base score + length bonus
                });
                console.log(`[ANYTHINGLLM] Metrics recorded: ${metricsModelName} | ${responseTime}ms | ${tokensEstimate} tokens`);
            }
            
            // Log stats periodically
            const stats = this.anythingLLMWrapper.getStats();
            if (stats.total_requests % 10 === 0) {
                console.log('[ANYTHINGLLM] Stats:', stats);
            }
            
            return response;
        } catch (error) {
            const responseTime = Date.now() - startTime;
            
            // Record failed query
            if (this.modelMetricsService) {
                this.modelMetricsService.recordQuery(metricsModelName, {
                    responseTime,
                    tokensGenerated: 0,
                    success: false,
                    category: 'chat',
                    qualityScore: 0
                });
            }
            
            console.error("[ANYTHINGLLM] Error:", error);
            return `⚠️ Erreur AnythingLLM: ${error.message}`;
        }
    }

    async generateLMStudioResponse(prompt, modelId, systemPrompt) {
        return this.generateOpenAICompatibleResponse(prompt, null, modelId || "local-model", systemPrompt, {
            apiKey: "lm-studio",
            baseURL: process.env.LM_STUDIO_URL,
            providerName: 'lmstudio'
        });
    }

    async generateOllamaResponse(prompt, imageBase64, modelId, systemPrompt) {
        // Fallback to default if no model specified
        const model = modelId || 'granite3.1-moe:1b';

        const messages = [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: prompt }
        ];

        // Note: Most local models are text-only unless specified (llava)
        if (imageBase64 && !model.includes('llava') && !model.includes('vision')) {
            console.warn("[LLM] Image ignored for non-vision local model.");
        }

        const response = await this.ollama.chat({
            model: model,
            messages: messages,
            images: (imageBase64 && (model.includes('llava') || model.includes('vision'))) ? [imageBase64] : undefined
        });
        return response.message.content;
    }

    setMCPService(mcpService) {
        this.mcpService = mcpService;
    }



    async generateClaudeResponse(prompt, imageBase64, modelId, systemPrompt) {
        if (!process.env.ANTHROPIC_API_KEY) throw new Error("ANTHROPIC_API_KEY missing");

        const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

        const messageContent = [];
        if (imageBase64) {
            messageContent.push({
                type: "image",
                source: {
                    type: "base64",
                    media_type: "image/jpeg",
                    data: imageBase64.replace(/^data:image\/\w+;base64,/, ""),
                }
            });
        }
        messageContent.push({ type: "text", text: prompt });

        const msg = await anthropic.messages.create({
            model: modelId || "claude-3-5-sonnet-20241022",
            max_tokens: 1024,
            system: systemPrompt,
            messages: [{ role: "user", content: messageContent }],
        });

        return msg.content[0].text;
    }

    async unloadModel(modelName) {
        // Only relevant for local Ollama
        await this.ollama.chat({ model: modelName, messages: [], keep_alive: 0 });
    }
}

module.exports = LLMService;
