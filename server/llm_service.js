
const { Ollama } = require('ollama');
const OpenAI = require('openai');
const Anthropic = require('@anthropic-ai/sdk');
const AnythingLLMWrapper = require('./anythingllm_wrapper');
const knowledgeBase = require('./knowledge_base_service');
const { SECURITY_RESEARCH_PROMPTS, getSecurityPrompt, buildSecurityQuery } = require('./security_research_prompts');
const FibonacciCognitiveOptimizer = require('./fibonacci_cognitive_optimizer');
const { modelListCache, withTimeout } = require('./performance_utils');
const runpodService = require('./runpod_service');

class LLMService {
    constructor() {
        this.ollama = new Ollama({ host: process.env.OLLAMA_URL || 'http://localhost:11434' });
        this.socketService = null;
        this.modelMetricsService = null;
        this.anythingLLMWrapper = new AnythingLLMWrapper();
        this.knowledgeBase = knowledgeBase; // RAG Knowledge Base
        this.cognitiveOptimizer = new FibonacciCognitiveOptimizer(); // Fibonacci Learning
        
        // Uncensored local models (priority order for offline/red-teaming)
        this.uncensoredModels = [
            'uandinotai/dolphin-uncensored:latest',
            'sadiq-bd/llama3.2-3b-uncensored:latest',
            'nidumai/nidum-llama-3.2-3b-uncensored:latest'
        ];
        this.defaultLocalModel = this.uncensoredModels[0];
        this.isOfflineMode = false;
        
        this.providers = {
            local: { name: 'Local (Ollama Uncensored)', type: 'local' },
            openai: { name: 'OpenAI (ChatGPT)', type: 'cloud' },
            claude: { name: 'Anthropic Claude', type: 'cloud' },
            groq: { name: 'Groq (Ultra-Fast)', type: 'cloud' },
            deepseek: { name: 'DeepSeek (Fast & Cheap)', type: 'cloud' },
            runpod: { name: 'RunPod (GPU Cloud)', type: 'cloud' },
            lmstudio: { name: 'LM Studio (Private)', type: 'local' },
            anythingllm: { name: 'AnythingLLM (Agents)', type: 'cloud' }
        };
        
        // RunPod service for GPU cloud inference
        this.runpodService = runpodService;
        
        console.log('[LLM] Service initialized - UNCENSORED MODE');
        console.log('[LLM] Default model:', this.defaultLocalModel);
    }

    setSocketService(socketService) {
        this.socketService = socketService;
    }

    setModelMetricsService(modelMetricsService) {
        this.modelMetricsService = modelMetricsService;
    }

    /**
     * Lists all available models (Local + Cloud + Agents).
     * OPTIMIZED: Results cached for 30 seconds to reduce latency
     */
    async listModels(computeMode = 'local') {
        const cacheKey = `models_${computeMode}`;
        
        // Return cached result if available (30 second TTL)
        return modelListCache.getOrCompute(cacheKey, async () => {
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
            // Gemini (Google AI)
            if (process.env.GEMINI_API_KEY) {
                models.cloud.push({ id: 'gemini-2.0-flash-exp', name: '🧠 Gemini 2.0 Flash (Teacher)', provider: 'gemini' });
                models.cloud.push({ id: 'gemini-1.5-flash', name: '⚡ Gemini 1.5 Flash', provider: 'gemini' });
                models.cloud.push({ id: 'gemini-1.5-pro', name: '🔵 Gemini 1.5 Pro', provider: 'gemini' });
            }

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

            // DeepSeek (Fast & Affordable)
            if (process.env.DEEPSEEK_API_KEY) {
                models.cloud.push({ id: 'deepseek-chat', name: '🔷 DeepSeek Chat', provider: 'deepseek' });
                models.cloud.push({ id: 'deepseek-reasoner', name: '🧠 DeepSeek Reasoner (R1)', provider: 'deepseek' });
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
        }, 30000); // 30 second cache TTL
    }

    /**
     * Analyzes OSINT tool output using a specific Expert Persona.
     * Uses uncensored models for unrestricted analysis.
     */
    async analyzeOsintResult(toolId, output, provider = 'local', model = null) {
        // Use uncensored model by default for OSINT analysis
        const defaultModel = model || this.defaultLocalModel;
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
        let targetModel = defaultModel;

        if (process.env.ANYTHING_LLM_KEY && provider === 'local') {
            targetProvider = 'anythingllm';
            targetModel = 'gpt-4o'; // Default to a strong model via AnythingLLM
        }

        return await this.generateResponse(prompt, null, targetProvider, targetModel, systemPrompt);
    }

    /**
     * Generate response with SECURITY RESEARCH context.
     * Uses specialized system prompts for defensive cybersecurity operations.
     * 
     * @param {string} query - User's security-related question
     * @param {string} role - Security role: 'reverseEngineer', 'pentester', 'vulnResearcher', 'networkAnalyst', 'osintInvestigator'
     * @param {string} provider - 'local' or cloud provider
     * @param {string} model - Specific model (optional, will use role default)
     * @returns {string} AI response with security research context
     */
    async generateSecurityResponse(query, role = 'pentester', provider = 'local', model = null) {
        console.log(`[LLM] Security Research Request: Role=${role}`);
        
        // Get the security-focused system prompt
        const securityConfig = getSecurityPrompt(role);
        const targetModel = model || securityConfig.model;
        
        // Add ethics reminder to query
        const contextualQuery = `[DEFENSIVE SECURITY RESEARCH CONTEXT]
This is an authorized security research request for defensive purposes only.
Target systems are owned or have explicit testing authorization.

USER QUERY: ${query}`;

        return await this.generateResponse(
            contextualQuery, 
            null, 
            provider, 
            targetModel, 
            securityConfig.systemPrompt
        );
    }

    /**
     * Get available security research roles
     */
    getSecurityRoles() {
        return Object.keys(SECURITY_RESEARCH_PROMPTS);
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
        
        // FIBONACCI COGNITIVE OPTIMIZATION
        // Get recommendations based on model's learning history
        const cognitiveRec = this.cognitiveOptimizer.getOptimizationRecommendations(modelId, 'general');
        
        // Augment system prompt with cognitive level
        let optimizedSystemPrompt = systemPrompt;
        if (cognitiveRec.fibonacciLevel > 1) {
            optimizedSystemPrompt = `${cognitiveRec.systemPromptAddition}\n\n${systemPrompt}`;
        }
        
        // Log cognitive state
        if (cognitiveRec.fibonacciLevel > 2) {
            console.log(`[FIBONACCI] ${modelId} - Level ${cognitiveRec.fibonacciLevel} | Thinking: ${cognitiveRec.thinkingReduction} reduced | Accuracy: ${(cognitiveRec.directToGoalProbability * 100).toFixed(0)}%`);
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
                this.unloadModel(this.defaultLocalModel).catch(e => console.log("[LLM] Background unload failed:", e.message));
            }

            let response;
            switch (providerId) {

                case 'openai':
                    response = await this.generateOpenAIResponse(augmentedPrompt, imageBase64, modelId, systemPrompt);
                    break;
                case 'claude':
                    response = await this.generateClaudeResponse(augmentedPrompt, imageBase64, modelId, systemPrompt);
                    break;
                case 'gemini':
                    response = await this.generateGeminiResponse(augmentedPrompt, modelId, systemPrompt);
                    break;
                case 'groq':
                    response = await this.generateGroqResponse(augmentedPrompt, modelId, systemPrompt);
                    break;
                case 'deepseek':
                    response = await this.generateDeepSeekResponse(augmentedPrompt, modelId, systemPrompt);
                    break;
                case 'runpod':
                    response = await this.generateRunPodResponse(augmentedPrompt, modelId, systemPrompt);
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
            
            // FIBONACCI: Record successful interaction
            this.cognitiveOptimizer.recordInteraction(modelId, {
                success: true,
                domain: 'general',
                prompt: augmentedPrompt.substring(0, 100)
            });
            
            return response;
        } catch (error) {
            console.error(`[LLM] Error with ${providerId}:`, error);
            if (this.socketService) this.socketService.emitAgentStatus("Error");
            
            // FIBONACCI: Record error for learning
            this.cognitiveOptimizer.recordInteraction(modelId, {
                success: false,
                errorType: error.name || 'UnknownError',
                domain: 'general',
                prompt: augmentedPrompt.substring(0, 100)
            });
            
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

    /**
     * Generate response using Google Gemini API
     * Used as the primary TEACHER model for AutoTeacher system
     */
    async generateGeminiResponse(prompt, modelId, systemPrompt) {
        if (!process.env.GEMINI_API_KEY) {
            throw new Error('GEMINI_API_KEY missing - Required for teacher model');
        }

        const model = modelId || 'gemini-2.0-flash-exp';
        const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`;

        const requestBody = {
            contents: [
                {
                    parts: [
                        { text: `${systemPrompt}\n\n${prompt}` }
                    ]
                }
            ],
            generationConfig: {
                temperature: 0.7,
                maxOutputTokens: 2048,
                topP: 0.95,
                topK: 40
            }
        };

        try {
            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(requestBody)
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Gemini API error: ${response.status} - ${errorText}`);
            }

            const data = await response.json();
            
            if (data.candidates && data.candidates[0]?.content?.parts?.[0]?.text) {
                return data.candidates[0].content.parts[0].text;
            }

            throw new Error('Invalid Gemini response structure');
        } catch (error) {
            console.error('[GEMINI] Error:', error.message);
            throw error;
        }
    }

    async generateGroqResponse(prompt, modelId, systemPrompt) {
        return this.generateOpenAICompatibleResponse(prompt, null, modelId || "llama-3.1-8b-instant", systemPrompt, {
            apiKey: process.env.GROQ_API_KEY,
            baseURL: 'https://api.groq.com/openai/v1',
            providerName: 'groq'
        });
    }

    /**
     * Generate response using DeepSeek API
     * Fast and affordable alternative to OpenAI
     * Models: deepseek-chat, deepseek-reasoner (R1)
     */
    async generateDeepSeekResponse(prompt, modelId, systemPrompt) {
        return this.generateOpenAICompatibleResponse(prompt, null, modelId || "deepseek-chat", systemPrompt, {
            apiKey: process.env.DEEPSEEK_API_KEY,
            baseURL: 'https://api.deepseek.com/v1',
            providerName: 'deepseek'
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

    /**
     * Generate response using RunPod GPU Cloud
     * Supports serverless endpoints and OpenAI-compatible pods
     * 
     * Models available:
     * - llama70b: Llama 3.3 70B (serverless)
     * - mistral: Mistral 7B/8x7B (serverless)
     * - qwen: Qwen 2.5 72B (serverless)
     * - vllm: Generic vLLM endpoint (custom models)
     * 
     * @param {string} prompt - User prompt
     * @param {string} modelId - Model to use (llama70b, mistral, qwen, vllm)
     * @param {string} systemPrompt - System prompt
     */
    async generateRunPodResponse(prompt, modelId, systemPrompt) {
        if (!this.runpodService) {
            throw new Error('RunPod service not initialized');
        }
        
        const status = this.runpodService.getStatus();
        
        if (!status.configured) {
            console.log('[LLM] RunPod not configured, falling back to Groq...');
            return await this.generateGroqResponse(prompt, 'llama-3.3-70b-versatile', systemPrompt);
        }
        
        const model = modelId || 'llama70b';
        console.log(`[LLM] RunPod request: model=${model}`);
        
        const startTime = Date.now();
        
        try {
            // Try serverless first (fastest)
            if (status.serverlessEndpoints.includes(model) || status.serverlessEndpoints.includes('vllm')) {
                const response = await this.runpodService.generateServerlessResponse(prompt, model, {
                    systemPrompt,
                    maxTokens: 2048,
                    temperature: 0.7
                });
                
                const responseTime = Date.now() - startTime;
                console.log(`[RUNPOD] Serverless response in ${responseTime}ms`);
                
                // Record metrics
                if (this.modelMetricsService) {
                    this.modelMetricsService.recordQuery(`[RUNPOD] ${model}`, {
                        responseTime,
                        tokensGenerated: Math.floor((response?.length || 0) / 4),
                        success: true,
                        category: 'chat',
                        qualityScore: 85
                    });
                }
                
                return response;
            }
            
            // Try OpenAI-compatible endpoint (for custom pods)
            if (process.env.RUNPOD_OPENAI_ENDPOINT) {
                const response = await this.runpodService.generateOpenAICompatibleResponse(prompt, {
                    systemPrompt,
                    model: model,
                    maxTokens: 2048
                });
                
                const responseTime = Date.now() - startTime;
                console.log(`[RUNPOD] OpenAI-compatible response in ${responseTime}ms`);
                
                return response;
            }
            
            // No RunPod endpoint available, fallback to Groq
            console.log('[LLM] No RunPod endpoint available, falling back to Groq...');
            return await this.generateGroqResponse(prompt, 'llama-3.3-70b-versatile', systemPrompt);
            
        } catch (error) {
            console.error('[RUNPOD] Error:', error.message);
            
            // SMART FAILOVER: Try Groq, then local
            console.log('[LLM] RunPod failed, attempting failover...');
            
            try {
                // Failover 1: Groq (fast cloud)
                if (process.env.GROQ_API_KEY) {
                    console.log('[LLM] Failover to Groq...');
                    return await this.generateGroqResponse(prompt, 'llama-3.3-70b-versatile', systemPrompt);
                }
            } catch (groqError) {
                console.error('[LLM] Groq failover failed:', groqError.message);
            }
            
            try {
                // Failover 2: Local Ollama
                console.log('[LLM] Failover to local Ollama...');
                return await this.generateOllamaResponse(prompt, null, null, systemPrompt);
            } catch (localError) {
                console.error('[LLM] Local failover failed:', localError.message);
                throw new Error(`All inference providers failed. RunPod: ${error.message}`);
            }
        }
    }

    /**
     * Smart inference with automatic provider selection
     * Chooses the best provider based on availability and model requirements
     * 
     * Priority: RunPod (big models) → Groq (fast) → Local (fallback)
     */
    async generateSmartResponse(prompt, options = {}) {
        const { 
            preferGPU = false, 
            requireUncensored = false,
            maxLatency = 30000,
            systemPrompt = 'You are a helpful AI assistant.'
        } = options;
        
        // If uncensored required, use local
        if (requireUncensored) {
            console.log('[LLM] Smart: Uncensored required, using local');
            return await this.generateOllamaResponse(prompt, null, null, systemPrompt);
        }
        
        // If GPU preferred and RunPod available
        if (preferGPU && this.runpodService?.getStatus().configured) {
            console.log('[LLM] Smart: GPU preferred, using RunPod');
            return await this.generateRunPodResponse(prompt, 'llama70b', systemPrompt);
        }
        
        // Fast response preferred - use Groq
        if (process.env.GROQ_API_KEY && maxLatency < 10000) {
            console.log('[LLM] Smart: Fast response needed, using Groq');
            return await this.generateGroqResponse(prompt, 'llama-3.1-8b-instant', systemPrompt);
        }
        
        // Default: Groq for speed, fallback to local
        if (process.env.GROQ_API_KEY) {
            try {
                return await this.generateGroqResponse(prompt, 'llama-3.3-70b-versatile', systemPrompt);
            } catch (e) {
                console.log('[LLM] Smart: Groq failed, falling back to local');
            }
        }
        
        return await this.generateOllamaResponse(prompt, null, null, systemPrompt);
    }


    async generateOllamaResponse(prompt, imageBase64, modelId, systemPrompt) {
        // Use uncensored model by default, with automatic fallback chain
        let model = modelId || this.defaultLocalModel;
        
        // If specified model fails, try fallback chain
        const modelsToTry = modelId ? [modelId, ...this.uncensoredModels] : this.uncensoredModels;

        const messages = [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: prompt }
        ];

        // Note: Most local models are text-only unless specified (llava)
        if (imageBase64 && !model.includes('llava') && !model.includes('vision')) {
            console.warn("[LLM] Image ignored for non-vision local model.");
        }

        let lastError = null;
        for (const tryModel of modelsToTry) {
            try {
                console.log(`[LLM] Trying model: ${tryModel}`);
                const response = await this.ollama.chat({
                    model: tryModel,
                    messages: messages,
                    images: (imageBase64 && (tryModel.includes('llava') || tryModel.includes('vision'))) ? [imageBase64] : undefined
                });
                
                // Update default if we had to fallback
                if (tryModel !== this.defaultLocalModel && !modelId) {
                    console.log(`[LLM] Switched default to: ${tryModel}`);
                    this.defaultLocalModel = tryModel;
                }
                
                // Mark offline mode active
                if (!this.isOfflineMode) {
                    this.isOfflineMode = true;
                    console.log('[LLM] ⚡ OFFLINE MODE ACTIVE - Using local uncensored models');
                }
                
                return response.message.content;
            } catch (err) {
                lastError = err;
                console.warn(`[LLM] Model ${tryModel} failed: ${err.message}`);
            }
        }
        
        throw lastError || new Error('All local models failed');
    }

    /**
     * Enable/disable offline mode
     */
    setOfflineMode(offline = true) {
        this.isOfflineMode = offline;
        console.log(`[LLM] ${offline ? '⚡ OFFLINE' : '🌐 ONLINE'} mode enabled`);
    }

    /**
     * Get available uncensored models
     */
    getUncensoredModels() {
        return this.uncensoredModels;
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
