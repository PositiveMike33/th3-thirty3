
const OpenAI = require('openai');
const Anthropic = require('@anthropic-ai/sdk');
const AnythingLLMWrapper = require('./anythingllm_wrapper');
const knowledgeBase = require('./knowledge_base_service');
const { hackerGPTService } = require('./hackergpt_persona');
const settingsService = require('./settings_service');

class LLMService {
    constructor() {
        console.log(`[LLM_SERVICE] Running in CLOUD-ONLY mode.`);
        this.socketService = null;
        this.modelMetricsService = null;
        this.anythingLLMWrapper = AnythingLLMWrapper;
        this.knowledgeBase = knowledgeBase; // RAG Knowledge Base
        this.providers = {
            openai: { name: 'OpenAI (ChatGPT)', type: 'cloud' },
            claude: { name: 'Anthropic Claude', type: 'cloud' },
            groq: { name: 'Groq (Ultra-Fast)', type: 'cloud' },
            gemini: { name: 'Google Gemini', type: 'cloud' },
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
     * Lists all available models (Cloud + Agents).
     */
    async listModels(computeMode = 'cloud') {
        // Force cloud mode
        const models = { local: [], cloud: [] };
        const settings = settingsService.getSettings();

        // --- CLOUD MODE MODELS ---

        // Claude (Anthropic)
        if (process.env.ANTHROPIC_API_KEY) {
            models.cloud.push({ id: 'claude-3-5-sonnet-20241022', name: 'Claude 3.5 Sonnet', provider: 'claude' });
            models.cloud.push({ id: 'claude-3-opus-20240229', name: 'Claude 3 Opus', provider: 'claude' });
        }

        // Groq (Ultra-fast)
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
                const timeoutId = setTimeout(() => controller.abort(), 2000); // 2s timeout

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
                console.error("Failed to list AnythingLLM agents:", e.message);
                // Fail silently for listing
            }
        }

        // Google Gemini - Gemini 1.5 Series (User Request)
        const geminiKey = process.env.GEMINI_API_KEY || settings.apiKeys?.gemini;
        if (geminiKey) {
            models.cloud.push({ id: 'gemini-3-pro-preview', name: '🔥 Gemini 3 Pro (1M Context)', provider: 'gemini' });
            models.cloud.push({ id: 'gemini-3-flash-preview', name: '⚡ Gemini 3 Flash', provider: 'gemini' });
            models.cloud.push({ id: 'gemini-3-pro-image-preview', name: '🎨 Gemini 3 Pro Image', provider: 'gemini' });
        }

        // OpenAI - All Available Models
        const openaiKey = process.env.OPENAI_API_KEY || settings.apiKeys?.openai;
        if (openaiKey) {
            models.cloud.push({ id: 'gpt-4o', name: '🟢 GPT-4o (Flagship)', provider: 'openai' });
            models.cloud.push({ id: 'gpt-4o-mini', name: '🟢 GPT-4o Mini', provider: 'openai' });
            models.cloud.push({ id: 'o1', name: '🧠 O1 (Reasoning)', provider: 'openai' });
            models.cloud.push({ id: 'o1-mini', name: '🧠 O1 Mini', provider: 'openai' });
            models.cloud.push({ id: 'o3-mini', name: '⚡ O3 Mini (Fast)', provider: 'openai' });
        }

        // HackerGPT
        models.cloud.push({
            id: 'hackergpt',
            name: process.env.GEMINI_API_KEY
                ? '🔓 HackerGPT + Gemini (Security)'
                : '🔓 HackerGPT (Security Expert)',
            provider: 'hackergpt'
        });

        return models;
    }

    /**
     * Analyzes OSINT tool output.
     */
    async analyzeOsintResult(toolId, output, provider = 'cloud', model = 'gemini-3-pro-preview') {
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

        let targetProvider = 'gemini';
        let targetModel = 'gemini-3-pro-preview';

        if (process.env.GEMINI_API_KEY) {
            targetProvider = 'gemini';
            targetModel = 'gemini-3-pro-preview';
        } else if (process.env.ANYTHING_LLM_KEY) {
            targetProvider = 'anythingllm';
            targetModel = 'gpt-4o';
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
            this.socketService.emitAgentStatus("Checking Cloud Services...");
        }

        try {
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
                case 'gemini':
                    response = await this.generateGeminiResponse(augmentedPrompt, modelId, systemPrompt);
                    break;
                case 'openrouter':
                    response = await this.generateOpenRouterResponse(augmentedPrompt, imageBase64, modelId, systemPrompt);
                    break;
                case 'anythingllm':
                case 'cloud':
                    response = await this.generateAnythingLLMResponse(augmentedPrompt, modelId, systemPrompt);
                    break;
                case 'lmstudio':
                    response = await this.generateLMStudioResponse(augmentedPrompt, modelId, systemPrompt);
                    break;
                case 'hackergpt':
                    // We need to pass sessionId/context if available. generateResponse doesn't accept context arg yet properly?
                    // Actually generateResponse is called with (prompt, imageBase64, providerId, modelId, systemPrompt)
                    // We need to find where sessionId is available. It might not be passed to generateResponse.
                    // Checking generateResponse signature... it doesn't take context.
                    // However, we can use a hack or assume sessionId is in the prompt or added later? 
                    // Wait, socketService emits agent start with prompt. 
                    // Let's modify generateResponse to accept context or extract it. 
                    // Ideally, LLMService needs session context. 
                    // For now, let's pass a placeholder or try to get it if we can.
                    // But wait, generateHackerGPTResponse definition was updated to take context.
                    // We need to pass it here. 
                    // Let's pass {} for now, relying on 'default-session' fallback, 
                    // UNLESS we update generateResponse to take context. 
                    // User didn't ask to refactor everything. 
                    // Let's pass null for context for now and rely on default, 
                    // OR better: pass { sessionId: this.currentSessionId } if we had it.
                    // We don't have it in LLMService instance.
                    // We will pass an empty object and let the agent fallback.
                    response = await this.generateHackerGPTResponse(augmentedPrompt, modelId, systemPrompt, { sessionId: 'global-chat' });
                    break;
                case 'local':
                    return "⚠️ ERREUR: Mode Local désactivé. Veuillez sélectionner un modèle Cloud.";
                default:
                    // Default fallback to Gemini if available, else AnythingLLM
                    if (process.env.GEMINI_API_KEY) {
                        return await this.generateGeminiResponse(augmentedPrompt, 'gemini-3-flash-preview', systemPrompt);
                    } else {
                        return "⚠️ ERREUR: Aucun fournisseur Cloud configuré et mode Local désactivé.";
                    }
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

        if (!apiKey && providerName !== 'lmstudio') {
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
                content: imageBase64 && providerName === 'openai'
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

    async generateGeminiResponse(prompt, modelId, systemPrompt) {
        const settings = settingsService.getSettings();
        const geminiKey = process.env.GEMINI_API_KEY || settings.apiKeys?.gemini;

        if (!geminiKey) throw new Error("GEMINI_API_KEY missing - configure in Settings");

        const { GoogleGenerativeAI } = require('@google/generative-ai');
        const genAI = new GoogleGenerativeAI(geminiKey);

        const { HarmCategory, HarmBlockThreshold } = require('@google/generative-ai');

        const safetySettings = [
            { category: HarmCategory.HARM_CATEGORY_HARASSMENT, threshold: HarmBlockThreshold.BLOCK_NONE },
            { category: HarmCategory.HARM_CATEGORY_HATE_SPEECH, threshold: HarmBlockThreshold.BLOCK_NONE },
            { category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, threshold: HarmBlockThreshold.BLOCK_NONE },
            { category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, threshold: HarmBlockThreshold.BLOCK_NONE },
        ];

        const model = genAI.getGenerativeModel({
            model: modelId || "gemini-3-flash-preview",
            systemInstruction: systemPrompt,
            safetySettings: safetySettings
        });

        const result = await model.generateContent(prompt);
        const text = result.response.text();
        if (!text) {
            throw new Error("Empty response from Gemini");
        }
        return text;
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
            this.socketService.emitAgentStatus("Accessing Private Web (AnythingLLM)...");
        }

        const startTime = Date.now();
        const workspaceName = this.anythingLLMWrapper.workspaceSlug || 'th3-thirty3-workspace';
        const metricsModelName = `[ANYTHINGLLM] ${workspaceName}`;

        try {
            const response = await this.anythingLLMWrapper.chat(prompt, 'chat');
            const responseTime = Date.now() - startTime;

            if (this.modelMetricsService) {
                const tokensEstimate = Math.floor((response?.length || 0) / 4);
                this.modelMetricsService.recordQuery(metricsModelName, {
                    responseTime,
                    tokensGenerated: tokensEstimate,
                    success: true,
                    category: 'chat',
                    qualityScore: 80
                });
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

    setMCPService(mcpService) {
        this.mcpService = mcpService;
    }

    /**
     * Generate response using HackerGPT persona
     * STRICTLY uses Gemini or AnythingLLM. NO OLLAMA FALLBACK.
     */
    async generateHackerGPTResponse(prompt, modelId, userSystemPrompt, context) {
        console.log('[HACKERGPT] Generating security-focused response with Gemini HexStrike Agent...');

        // Lazy load to avoid circular dependencies if any
        const geminiHexStrikeAgent = require('./gemini_hexstrike_agent');

        // Ensure socket service is injected if not already
        if (!geminiHexStrikeAgent.socketService && this.socketService) {
            geminiHexStrikeAgent.socketService = this.socketService;
        }

        if (geminiHexStrikeAgent.isReady()) {
            try {
                // Pass chat ID from context or generate a temporary one
                const chatId = context?.sessionId || 'default-session';

                const result = await geminiHexStrikeAgent.processRequest(prompt, {
                    history: [],
                    includeToolContext: true,
                    chatId: chatId
                });

                if (result.success) {
                    return result.response;
                } else {
                    console.warn('[HACKERGPT] Agent execution failed, falling back to standard personality:', result.error);
                }
            } catch (agentError) {
                console.error('[HACKERGPT] Agent error:', agentError);
            }
        }

        // FALLBACK: Standard Personality (No Tools)
        const hackerGPTPrompt = hackerGPTService.getSystemPrompt();
        const fullSystemPrompt = userSystemPrompt
            ? `${hackerGPTPrompt}\n\n--- Additional Instructions ---\n${userSystemPrompt}`
            : hackerGPTPrompt;

        // PRIMARY: Gemini (Chat Only)
        if (process.env.GEMINI_API_KEY) {
            try {
                return await this.generateGeminiResponse(prompt, 'gemini-3-flash-preview', fullSystemPrompt);
            } catch (geminiError) {
                console.error('[HACKERGPT] ❌ Gemini error:', geminiError.message);
                if (this.socketService) {
                    this.socketService.emitAgentStatus("Gemini failed, trying AnythingLLM...");
                }
            }
        }

        // FALLBACK: AnythingLLM
        console.log('[HACKERGPT] 🔄 Switching to AnythingLLM...');
        try {
            return await this.anythingLLMWrapper.chat(
                `${fullSystemPrompt}\n\n---\n\nUSER REQUEST: ${prompt}`,
                'chat'
            );
        } catch (anythingError) {
            throw new Error(`HackerGPT Error: Tous les backends Cloud ont échoué. Gemini & AnythingLLM inaccessibles.`);
        }
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
        // No-op in Cloud Mode
        return true;
    }
}

module.exports = LLMService;
