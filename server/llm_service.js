const { GoogleGenerativeAI } = require("@google/generative-ai");
const { Ollama } = require('ollama');
const OpenAI = require('openai');
const Anthropic = require('@anthropic-ai/sdk');

class LLMService {
    constructor() {
        this.ollama = new Ollama();
        this.providers = {
            local: { name: 'Local (Ollama)', type: 'local' },
            gemini: { name: 'Google Gemini', type: 'cloud' },
            openai: { name: 'OpenAI (ChatGPT)', type: 'cloud' },
            claude: { name: 'Anthropic Claude', type: 'cloud' },
            lmstudio: { name: 'LM Studio (Private)', type: 'local' },
            anythingllm: { name: 'AnythingLLM (Agents)', type: 'cloud' }
        };
    }

    /**
     * Lists all available models (Local + Cloud + Agents).
     */
    async listModels(computeMode = 'local') {
        const models = { local: [], cloud: [] };

        // --- LOCAL MODE (Always Available) ---
        // 1. Ollama
        try {
            const list = await this.ollama.list();
            models.local = list.models.map(m => m.name);
        } catch (e) {
            console.error("Failed to list local models:", e.message);
            models.local = ["Ollama Offline"];
        }

        // 2. LM Studio
        if (process.env.LM_STUDIO_URL) {
            try {
                const response = await fetch(`${process.env.LM_STUDIO_URL}/models`);
                if (response.ok) {
                    const data = await response.json();
                    const lmModels = data.data.map(m => `[LMS] ${m.id}`);
                    models.local.push(...lmModels);
                }
            } catch (e) {
                models.local.push("[LMS] Offline");
            }
        }

        // --- CLOUD MODE ---
        if (computeMode === 'cloud') {
            // Gemini
            if (process.env.GEMINI_API_KEY) {
                models.cloud.push({ id: 'gemini-1.5-flash', name: 'Gemini 1.5 Flash', provider: 'gemini' });
                models.cloud.push({ id: 'gemini-1.5-pro', name: 'Gemini 1.5 Pro', provider: 'gemini' });
            }

            // OpenAI
            if (process.env.OPENAI_API_KEY) {
                models.cloud.push({ id: 'gpt-4o', name: 'GPT-4o', provider: 'openai' });
                models.cloud.push({ id: 'gpt-4o-mini', name: 'GPT-4o Mini', provider: 'openai' });
            }

            // Claude
            if (process.env.ANTHROPIC_API_KEY) {
                models.cloud.push({ id: 'claude-3-5-sonnet-20241022', name: 'Claude 3.5 Sonnet', provider: 'claude' });
            }

            // Perplexity
            if (process.env.PERPLEXITY_API_KEY) {
                models.cloud.push({ id: 'llama-3.1-sonar-large-128k-online', name: 'Perplexity Sonar Large', provider: 'perplexity' });
            }

            // AnythingLLM (Agents)
            if (process.env.ANYTHING_LLM_URL && process.env.ANYTHING_LLM_KEY) {
                try {
                    const response = await fetch(`${process.env.ANYTHING_LLM_URL}/openai/models`, {
                        headers: { 'Authorization': `Bearer ${process.env.ANYTHING_LLM_KEY}` }
                    });
                    if (response.ok) {
                        const data = await response.json();
                        const agents = data.data.map(m => ({
                            id: m.id,
                            name: `[AGENT] ${m.id}`,
                            provider: 'anythingllm'
                        }));
                        models.cloud.push(...agents);
                    }
                } catch (e) {
                    console.error("Failed to list AnythingLLM agents:", e.message);
                }
            }
        }

        return models;
    }

    async generateResponse(prompt, imageBase64, providerId, modelId, systemPrompt) {
        console.log(`[LLM] Request: Provider=${providerId}, Model=${modelId}`);

        try {
            // RESOURCE MANAGEMENT:
            // If we are NOT using local/ollama, ensure we unload any loaded local models to free VRAM
            // This is critical when running AnythingLLM or other heavy local apps alongside.
            if (providerId !== 'local') {
                // We don't await this to avoid slowing down the request
                this.unloadModel('granite3.1-moe:1b').catch(e => console.log("[LLM] Background unload failed:", e.message));
            }

            switch (providerId) {
                case 'gemini':
                    return await this.generateGeminiResponse(prompt, imageBase64, modelId, systemPrompt);
                case 'openai':
                    return await this.generateOpenAIResponse(prompt, imageBase64, modelId, systemPrompt);
                case 'claude':
                    return await this.generateClaudeResponse(prompt, imageBase64, modelId, systemPrompt);
                case 'perplexity':
                    return await this.generatePerplexityResponse(prompt, modelId, systemPrompt);
                case 'openrouter':
                    return await this.generateOpenRouterResponse(prompt, imageBase64, modelId, systemPrompt);
                case 'anythingllm':
                    return await this.generateAnythingLLMResponse(prompt, modelId, systemPrompt);
                case 'lmstudio':
                    return await this.generateLMStudioResponse(prompt, modelId, systemPrompt);
                case 'local':
                default:
                    return await this.generateOllamaResponse(prompt, imageBase64, modelId, systemPrompt);
            }
        } catch (error) {
            console.error(`[LLM] Error with ${providerId}:`, error);
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
        return this.generateOpenAICompatibleResponse(prompt, null, modelId, systemPrompt, {
            apiKey: process.env.ANYTHING_LLM_KEY,
            baseURL: `${process.env.ANYTHING_LLM_URL}/openai`,
            providerName: 'anythingllm'
        });
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

    async generateGeminiResponse(prompt, imageBase64, modelId, systemPrompt) {
        if (!process.env.GEMINI_API_KEY) throw new Error("GEMINI_API_KEY missing");

        const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
        const model = genAI.getGenerativeModel({ model: modelId || "gemini-1.5-flash" });

        // Prepare Tools
        let tools = [];
        if (this.mcpService) {
            const mcpTools = await this.mcpService.listTools();
            if (mcpTools.length > 0) {
                tools = [{
                    functionDeclarations: mcpTools.map(t => ({
                        name: t.name,
                        description: t.description || "No description",
                        parameters: t.inputSchema
                    }))
                }];
            }
        }

        const parts = [{ text: systemPrompt + "\n\n" + prompt }];

        if (imageBase64) {
            parts.push({
                inlineData: {
                    data: imageBase64.replace(/^data:image\/\w+;base64,/, ""),
                    mimeType: "image/jpeg",
                },
            });
        }

        const chat = model.startChat({
            tools: tools,
        });

        const result = await chat.sendMessage(parts);
        const response = result.response;

        // Handle Function Calls
        const calls = response.functionCalls();
        if (calls && calls.length > 0) {
            console.log("[LLM] Tool Call Detected:", calls);
            const call = calls[0];
            const toolName = call.name;
            const args = call.args;
            const [serverName, ...rest] = toolName.split('__');
            const originalToolName = rest.join('__');

            try {
                console.log(`[MCP] Executing ${toolName} on ${serverName}...`);
                const toolResult = await this.mcpService.callTool(serverName, originalToolName, args);
                const resultParts = [{
                    functionResponse: {
                        functionResponse: {
                            name: toolName,
                            response: { result: toolResult }
                        }
                    }
                }];
                const finalResult = await chat.sendMessage(resultParts);
                return finalResult.response.text();
            } catch (err) {
                console.error("[MCP] Tool execution failed:", err);
                return `Erreur lors de l'exécution de l'outil ${toolName}: ${err.message}`;
            }
        }

        return response.text();
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
