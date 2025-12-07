
const { Ollama } = require('ollama');
const OpenAI = require('openai');
const Anthropic = require('@anthropic-ai/sdk');
const AnythingLLMWrapper = require('./anythingllm_wrapper');

class LLMService {
    constructor() {
        this.ollama = new Ollama();
        this.socketService = null;
        this.anythingLLMWrapper = new AnythingLLMWrapper();
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

    /**
     * Lists all available models (Local + Cloud + Agents).
     */
    async listModels(computeMode = 'local') {
        console.log("[LLM] listModels called");
        const models = { local: [], cloud: [] };

        // --- LOCAL MODE (Always Available) ---
        // 1. Ollama
        console.log("[LLM] Checking Ollama...");
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

            // OpenAI
            if (process.env.OPENAI_API_KEY) {
                models.cloud.push({ id: 'gpt-4o', name: 'GPT-4o', provider: 'openai' });
                models.cloud.push({ id: 'gpt-4o-mini', name: 'GPT-4o Mini', provider: 'openai' });
            }

            // Claude (Anthropic)
            if (process.env.ANTHROPIC_API_KEY) {
                models.cloud.push({ id: 'claude-3-5-sonnet-20241022', name: 'Claude 3.5 Sonnet', provider: 'claude' });
                models.cloud.push({ id: 'claude-3-opus-20240229', name: 'Claude 3 Opus', provider: 'claude' });
            }

            // Groq (Ultra-fast)
            if (process.env.GROQ_API_KEY) {
                models.cloud.push({ id: 'llama-3.1-70b-versatile', name: '⚡ Llama 3.1 70B', provider: 'groq' });
                models.cloud.push({ id: 'llama-3.1-8b-instant', name: '⚡ Llama 3.1 8B Instant', provider: 'groq' });
                models.cloud.push({ id: 'mixtral-8x7b-32768', name: '⚡ Mixtral 8x7B', provider: 'groq' });
                models.cloud.push({ id: 'gemma2-9b-it', name: '⚡ Gemma 2 9B', provider: 'groq' });
            }

            // Perplexity
            // if (process.env.PERPLEXITY_API_KEY) {
            //     models.cloud.push({ id: 'llama-3.1-sonar-large-128k-online', name: 'Perplexity Sonar Large', provider: 'perplexity' });
            // }

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
        if (this.socketService) {
            this.socketService.emitAgentStart({ provider: providerId, model: modelId, prompt });
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
                    response = await this.generateOpenAIResponse(prompt, imageBase64, modelId, systemPrompt);
                    break;
                case 'claude':
                    response = await this.generateClaudeResponse(prompt, imageBase64, modelId, systemPrompt);
                    break;
                case 'groq':
                    response = await this.generateGroqResponse(prompt, modelId, systemPrompt);
                    break;
                case 'perplexity':
                    response = await this.generatePerplexityResponse(prompt, modelId, systemPrompt);
                    break;
                case 'openrouter':
                    response = await this.generateOpenRouterResponse(prompt, imageBase64, modelId, systemPrompt);
                    break;
                case 'anythingllm':
                case 'cloud': // Force Cloud mode to AnythingLLM
                    response = await this.generateAnythingLLMResponse(prompt, modelId, systemPrompt);
                    break;
                case 'lmstudio':
                    response = await this.generateLMStudioResponse(prompt, modelId, systemPrompt);
                    break;
                case 'local':
                default:
                    response = await this.generateOllamaResponse(prompt, imageBase64, modelId, systemPrompt);
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
        return this.generateOpenAICompatibleResponse(prompt, null, modelId || "llama-3.1-sonar-large-128k-online", systemPrompt, {
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

        try {
            // Use the wrapper which handles Gemini → nomic-embed-text fallback automatically
            const response = await this.anythingLLMWrapper.chat(prompt, 'chat');
            
            // Log stats periodically
            const stats = this.anythingLLMWrapper.getStats();
            if (stats.total_requests % 10 === 0) {
                console.log('[ANYTHINGLLM] Stats:', stats);
            }
            
            return response;
        } catch (error) {
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
