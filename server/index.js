require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs'); // CRITICAL: Required for patterns route
const { getPatterns, getPatternContent } = require('./fabric_service');
const MemoryService = require('./memory_service');
const { v4: uuidv4 } = require('uuid');

const http = require('http');
const app = express();
const server = http.createServer(app);
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// ============================================
// AUTH ROUTES (Public - No middleware required)
// Must be BEFORE authMiddleware to allow login/register
// ============================================
const authRoutes = require('./auth_routes');
app.use('/auth', authRoutes);

// Auth Middleware (Applied to all routes AFTER auth routes)
const { authMiddleware, requireTier, requireFeature } = require('./middleware/auth');
const userService = require('./user_service');
app.use(authMiddleware); // Apply to all routes

// Security Middleware (Protection intrusions)
const securityRoutes = require('./security_routes');
app.use(securityRoutes.middleware); // Apply security checks to all routes
app.use('/api/security', securityRoutes); // Security management routes

// Zone Isolation Middleware (Conteneurisation par zone)
const SecurityZoneService = require('./security_zone_service');
const securityZoneService = new SecurityZoneService();
app.use(securityZoneService.zoneIsolationMiddleware()); // Apply zone isolation

// Subscription Management Routes
const subscriptionRoutes = require('./subscription_routes');
app.use('/api/subscription', subscriptionRoutes);

// Payment Routes (Stripe & PayPal)
const paymentRoutes = require('./payment_routes');
app.use('/api/payment', paymentRoutes);

// Payment Dashboard Routes (Stats temps réel)
const paymentDashboardRoutes = require('./payment_dashboard_routes');
app.use('/api/payment', paymentDashboardRoutes);

// Dart AI Routes (AI-Powered Project Management)
const dartRoutes = require('./routes/dart');
app.use('/api/dart', dartRoutes);

// Astronomy Routes (IPGeolocation Space Data)
const astronomyRoutes = require('./astronomy_routes');
app.use('/api/astronomy', astronomyRoutes);
console.log('[SYSTEM] Astronomy Service initialized (IPGeolocation API)');

// IP Location Routes (Free IP Geolocation - No API Key)
const iplocationRoutes = require('./iplocation_routes');
app.use('/api/iplocation', iplocationRoutes);
console.log('[SYSTEM] IP Location Service initialized (iplocation.net - FREE)');

// IP2Location Routes (Comprehensive Geolocation with API Key)
const ip2locationRoutes = require('./ip2location_routes');
app.use('/api/ip2location', ip2locationRoutes);
console.log('[SYSTEM] IP2Location Service initialized (City, Coords, Proxy Detection)');

// WHOIS Routes (Domain Lookup)
const whoisRoutes = require('./whois_routes');
app.use('/api/whois', whoisRoutes);
console.log('[SYSTEM] WHOIS Service initialized (Domain, Registrar, Expiration)');

// Network Scanner Routes (Nmap + TShark via WSL Ubuntu)
const networkScannerRoutes = require('./network_scanner_routes');
app.use('/api/network', networkScannerRoutes);
console.log('[SYSTEM] Network Scanner initialized (Nmap + TShark via WSL Ubuntu)');


// Model Configuration
const IDENTITY = require('./config/identity');

const { PERSONA, MINIMAL_PERSONA } = require('./config/prompts');

const ACCOUNTS = [
    'mikegauthierguillet@gmail.com',  // Priorité
    'th3thirty3@gmail.com',
    'mgauthierguillet@gmail.com'
];

// Model Configuration
const modelName = IDENTITY.default_model;
console.log(`[SYSTEM] ${IDENTITY.name} v${IDENTITY.version} connecté : ${modelName}`);

// Initialize Memory Service
const memoryService = new MemoryService();
memoryService.initialize();

// Initialize Settings & Load Keys
const settingsService = require('./settings_service');
const currentSettings = settingsService.getSettings();
if (currentSettings.apiKeys) {
    console.log("[SYSTEM] Loading API Keys from Settings...");

    if (currentSettings.apiKeys.openai) process.env.OPENAI_API_KEY = currentSettings.apiKeys.openai;
    if (currentSettings.apiKeys.anthropic) process.env.ANTHROPIC_API_KEY = currentSettings.apiKeys.anthropic;
    if (currentSettings.apiKeys.perplexity) process.env.PERPLEXITY_API_KEY = currentSettings.apiKeys.perplexity;
    if (currentSettings.apiKeys.anythingllm_url) process.env.ANYTHING_LLM_URL = currentSettings.apiKeys.anythingllm_url;
    if (currentSettings.apiKeys.anythingllm_key) process.env.ANYTHING_LLM_KEY = currentSettings.apiKeys.anythingllm_key;
}

// Initialize MCP Service (Protocol Nexus)
const MCPService = require('./mcp_service');
const mcpService = new MCPService();

// Initialize Context Service
const ContextService = require('./context_service');
const contextService = new ContextService(memoryService, mcpService);

// Initialize LLM Service
const LLMService = require('./llm_service');
const llmService = new LLMService();

// Initialize Google Service
const GoogleService = require('./google_service');
const googleService = new GoogleService();

// Initialize Finance Service
const FinanceService = require('./finance_service');
const financeService = new FinanceService();

// Initialize Project Service
const ProjectService = require('./project_service');
const projectService = new ProjectService();

// Register Local Tools
const pythonRunner = require('./tools/python_runner');
const webSearch = require('./tools/web_search');
mcpService.registerLocalTool(pythonRunner, pythonRunner.handler);
mcpService.registerLocalTool(webSearch, webSearch.handler);

// Connect to Obsidian MCP Server
// Connect to Obsidian MCP Server
// const vaultPath = process.env.OBSIDIAN_VAULT_PATH;
// if (vaultPath) {
//     mcpService.connectStdio(
//         'obsidian',
//         'npx',
//         ['-y', '@modelcontextprotocol/server-filesystem', vaultPath]
//     ).catch(err => console.error("[MCP] Failed to connect to Obsidian:", err));
// } else {
//     console.warn("[MCP] OBSIDIAN_VAULT_PATH not set. Skipping Obsidian connection.");
// }

// Connect to Pieces MCP Server
const PIECES_MCP_URL = 'http://localhost:39300/model_context_protocol/2024-11-05/sse';
const piecesSessionId = uuidv4();
mcpService.connectSSE('pieces', PIECES_MCP_URL, piecesSessionId)
    .catch(err => console.error("[MCP] Failed to connect to Pieces:", err));

// Pass MCP Service to LLM Service
llmService.setMCPService(mcpService);

// Initialize Style Service
const StyleService = require('./style_service');
const styleService = new StyleService();

// Initialize OSINT Service
const OsintService = require('./osint_service');
const osintService = new OsintService();

// Initialize Shodan Service (Cybersecurity Training Data)
const ShodanService = require('./shodan_service');
const shodanService = new ShodanService();
console.log('[SYSTEM] Shodan Service initialized (API training integration)');

// Initialize Socket Service
const SocketService = require('./socket_service');
const socketService = new SocketService();
const SessionManager = require('./session_manager');
const sessionManager = new SessionManager();

// Initialize Vision Service (Image/Video Analysis via AnythingLLM)
const VisionService = require('./vision_service');
const visionService = new VisionService(llmService);

// Initialize KeelClip Analyzer (5-Why Generator)
const KeelClipAnalyzer = require('./keelclip_analyzer');
const keelclipAnalyzer = new KeelClipAnalyzer(llmService);

// Initialize Model Metrics Service (Training Dashboard)
const ModelMetricsService = require('./model_metrics_service');
const modelMetricsService = new ModelMetricsService();
modelMetricsService.setMCPService(mcpService);
llmService.setModelMetricsService(modelMetricsService); // Connect for AnythingLLM metrics tracking
console.log('[SYSTEM] Model Metrics Service initialized (5s refresh, hourly benchmarks)');

// Initialize Training Commentary Service (LLM real-time analysis with Gemini/NotebookLM)
const TrainingCommentaryService = require('./training_commentary_service');
const trainingCommentaryService = new TrainingCommentaryService(llmService);
console.log('[SYSTEM] Training Commentary Service initialized (Gemini/NotebookLM, FR, email archive)');

// Initialize Real Training Service (intensive model training)
const RealTrainingService = require('./real_training_service');
const realTrainingService = new RealTrainingService(modelMetricsService, llmService, socketService);
realTrainingService.setShodanService(shodanService); // Connect Shodan for real-world training data
const realTrainingRoutes = require('./real_training_routes');
realTrainingRoutes.setRealTrainingService(realTrainingService);
realTrainingRoutes.setCommentaryService(trainingCommentaryService);

// Initialize Cloud Model Optimizer Service (Cloud to Local optimization)
const CloudModelOptimizerService = require('./cloud_model_optimizer');
const cloudOptimizerRoutes = require('./cloud_optimizer_routes');
const cloudModelOptimizer = new CloudModelOptimizerService(
    llmService,
    modelMetricsService,
    llmService.anythingLLMWrapper
);
cloudOptimizerRoutes.setCloudOptimizer(cloudModelOptimizer);
// Cloud Optimizer - runs every 1 hour (reduced from 30 min)
cloudModelOptimizer.startAutoOptimization(60);


// Initialize Agent Director Service (Th3 Thirty3 Manager)
const AgentDirectorService = require('./agent_director_service');
const agentDirectorRoutes = require('./agent_director_routes');
const agentDirector = new AgentDirectorService(llmService, llmService.anythingLLMWrapper);
agentDirectorRoutes.setAgentDirector(agentDirector);
console.log('[AGENT_DIRECTOR] Th3 Thirty3 Director initialized - Managing: Cybersécurité, OSINT, Agent Thirty3');
console.log('[SYSTEM] Real Training Service initialized (Shodan + model training)');

// Initialize WiFi Security Training Service (Specialized WiFi attack/defense training)
const { router: wifiTrainingRouter, initializeRoutes: initWifiTraining } = require('./wifi_training_routes');
const wifiTrainingRoutes = initWifiTraining(llmService, modelMetricsService);
app.use('/api/wifi-training', wifiTrainingRoutes);
console.log('[WIFI-TRAINING] WiFi Security Training Service initialized (50+ scenarios)');


// Helper: Inject File Content (Delegated to ContextService)
const injectFileContent = async (message) => {
    try {
        return await contextService.injectContext(message);
    } catch (error) {
        console.error("[CONTEXT] File injection failed:", error.message);
        return "";
    }
};

// Helper: Fetch Google Context
const fetchGoogleContext = async (message) => {
    const checks = [];
    const msg = message.toLowerCase();

    try {
        if (msg.includes('mail') || msg.includes('courriel')) {
            checks.push(Promise.all(ACCOUNTS.map(email => googleService.listUnreadEmails(email).catch(e => `Error: ${e.message}`)))
                .then(res => "\n\n[EMAILS RECENTS]\n" + res.map((r, i) => `--- Compte: ${ACCOUNTS[i]} ---\n${r}\n`).join('')));
        }

        if (msg.includes('calendrier') || msg.includes('agenda') || msg.includes('rendez-vous')) {
            checks.push(Promise.all(ACCOUNTS.map(email => googleService.listUpcomingEvents(email).catch(e => `Error: ${e.message}`)))
                .then(res => "\n\n[AGENDA]\n" + res.map((r, i) => `--- Compte: ${ACCOUNTS[i]} ---\n${r}\n`).join('')));
        }

        if (msg.includes('tâche') || msg.includes('todo')) {
            checks.push(Promise.all(ACCOUNTS.map(email => googleService.listTasks(email).catch(e => `Error: ${e.message}`)))
                .then(res => "\n\n[GOOGLE TASKS]\n" + res.map((r, i) => `--- Compte: ${ACCOUNTS[i]} ---\n${r}\n`).join('')));
        }

        if (msg.includes('drive') || msg.includes('fichiers')) {
            checks.push(Promise.all(ACCOUNTS.map(email => googleService.listDriveFiles(email).catch(e => `Error: ${e.message}`)))
                .then(res => "\n\n[GOOGLE DRIVE (Récents)]\n" + res.map((r, i) => `--- Compte: ${ACCOUNTS[i]} ---\n${r}\n`).join('')));
        }

        const results = await Promise.all(checks);
        return results.join('');
    } catch (error) {
        console.error("[CONTEXT] Google fetch failed:", error.message);
        return "";
    }
};

// Helper: Fetch Finance Context
const fetchFinanceContext = async (message) => {
    const msg = message.toLowerCase();
    let context = "";

    try {
        if (msg.includes('solde') || msg.includes('balance') || msg.includes('portefeuille') || msg.includes('kraken')) {
            try {
                const portfolio = await financeService.getPortfolio();
                context += `\n\n[FINANCE - KRAKEN]\n${portfolio}\n`;
            } catch (e) {
                console.error("[FINANCE] Portfolio fetch failed:", e.message);
            }
        }

        if (msg.includes('prix') || msg.includes('cours') || msg.includes('btc') || msg.includes('bitcoin')) {
            try {
                // Simple heuristic for now, default to BTC/USD
                const ticker = await financeService.getTicker('BTC/USD');
                context += `\n\n[MARCHE]\n${ticker}\n`;
            } catch (e) {
                console.error("[FINANCE] Ticker fetch failed:", e.message);
            }
        }
    } catch (error) {
        console.error("[CONTEXT] Finance fetch failed:", error.message);
    }

    return context;
};

// --- SESSION ENDPOINTS ---

app.get('/sessions', (req, res) => {
    const sessions = sessionManager.listSessions();
    res.json(sessions);
});

app.post('/sessions', (req, res) => {
    const session = sessionManager.createSession();
    res.json(session);
});

app.get('/sessions/:id', (req, res) => {
    const session = sessionManager.getSession(req.params.id);
    if (session) res.json(session);
    else res.status(404).json({ error: "Session not found" });
});

app.delete('/sessions/:id', (req, res) => {
    const success = sessionManager.deleteSession(req.params.id);
    res.json({ success });
});

app.delete('/sessions/:sessionId/messages/:messageId', (req, res) => {
    const { sessionId, messageId } = req.params;
    const success = sessionManager.deleteMessage(sessionId, messageId);
    if (success) {
        res.json({ success: true });
    } else {
        res.status(404).json({ error: "Message or session not found" });
    }
});

// --- EXISTING ENDPOINTS ---

// Fabric Patterns Endpoints
app.get('/patterns', (req, res) => {
    try {
        const patternsDir = path.join(__dirname, 'fabric', 'data', 'patterns');
        const patterns = fs.readdirSync(patternsDir)
            .filter(name => {
                const fullPath = path.join(patternsDir, name);
                return fs.statSync(fullPath).isDirectory();
            })
            .sort();
        res.json(patterns);
    } catch (error) {
        console.error("Error reading patterns:", error);
        res.status(500).json({ error: "Failed to read patterns" });
    }
});

app.get('/patterns/:name', (req, res) => {
    try {
        const patternName = req.params.name;
        const patternDir = path.join(__dirname, 'fabric', 'data', 'patterns', patternName);
        
        if (!fs.existsSync(patternDir)) {
            return res.status(404).json({ error: "Pattern not found" });
        }

        const systemPath = path.join(patternDir, 'system.md');
        const userPath = path.join(patternDir, 'user.md');

        const system = fs.existsSync(systemPath) ? fs.readFileSync(systemPath, 'utf8') : '';
        const user = fs.existsSync(userPath) ? fs.readFileSync(userPath, 'utf8') : '';

        res.json({ content: system, system, user });
    } catch (error) {
        console.error("Error reading pattern content:", error);
        res.status(500).json({ error: "Failed to read pattern content" });
    }
});

// Models Endpoint (NEW)
app.get('/models', async (req, res) => {
    try {
        const settings = settingsService.getSettings();
        // Use query param if present, otherwise use global setting
        const mode = req.query.computeMode || settings.computeMode;
        const models = await llmService.listModels(mode);
        res.json(models);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Sync all Ollama models with metrics system
app.post('/models/sync-ollama', async (req, res) => {
    try {
        // Fetch all Ollama models
        const ollamaUrl = process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
        const response = await fetch(`${ollamaUrl}/api/tags`);
        const data = await response.json();
        const models = (data.models || [])
            .map(m => m.name)
            .filter(n => !n.includes('embed'));
        
        // Initialize metrics for each model
        for (const modelName of models) {
            modelMetricsService.getOrCreateModelMetrics(modelName);
        }
        
        console.log('[METRICS] Synced ' + models.length + ' Ollama models');
        res.json({ 
            success: true, 
            message: 'Models synced with metrics',
            models: models,
            count: models.length 
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Model Metrics Endpoints (Training Dashboard)
app.get('/models/metrics', (req, res) => {
    try {
        const metrics = modelMetricsService.getAllMetrics();
        res.json(metrics);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// DELETE model metrics
app.delete('/models/:name/metrics', (req, res) => {
    try {
        const modelName = req.params.name;
        const result = modelMetricsService.deleteModelMetrics(modelName);
        if (result) {
            res.json({ success: true, message: 'Metrics deleted for ' + modelName });
        } else {
            res.status(404).json({ success: false, error: 'Model not found' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/models/:name/metrics', (req, res) => {
    try {
        const metrics = modelMetricsService.getModelMetrics(req.params.name);
        if (metrics) {
            res.json(metrics);
        } else {
            res.status(404).json({ error: 'Model metrics not found' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/models/:name/benchmark', async (req, res) => {
    try {
        const results = await modelMetricsService.runBenchmark(req.params.name, llmService);
        res.json({ success: true, results });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Cleanup orphaned model metrics (models that no longer exist in Ollama)
app.post('/models/cleanup', async (req, res) => {
    try {
        // Fetch current Ollama models
        const ollamaUrl = process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
        const response = await fetch(`${ollamaUrl}/api/tags`);
        const data = await response.json();
        const availableModels = (data.models || []).map(m => m.name);
        
        // Run cleanup
        const result = modelMetricsService.cleanupOrphanedModels(availableModels);
        
        res.json({ 
            success: true, 
            message: `Cleaned up ${result.removed.length} orphaned models`,
            removed: result.removed,
            kept: result.kept,
            availableOllama: availableModels
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================
// FIBONACCI COGNITIVE OPTIMIZATION API
// ========================
const FibonacciCognitiveOptimizer = require('./fibonacci_cognitive_optimizer');
const cognitiveOptimizer = new FibonacciCognitiveOptimizer();

// Get cognitive status for all models
app.get('/models/cognitive/status', (req, res) => {
    try {
        const status = cognitiveOptimizer.getAllModelsStatus();
        res.json({ success: true, models: status });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get cognitive status for specific model
app.get('/models/cognitive/:model', (req, res) => {
    try {
        const modelName = req.params.model;
        const status = cognitiveOptimizer.getFullStatus(modelName);
        res.json({ success: true, ...status });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get optimization recommendations for a model
app.get('/models/cognitive/:model/recommendations', (req, res) => {
    try {
        const modelName = req.params.model;
        const domain = req.query.domain || 'general';
        const recommendations = cognitiveOptimizer.getOptimizationRecommendations(modelName, domain);
        res.json({ success: true, ...recommendations });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================
// AUTO-TEACHER API
// ========================
const AutoTeacher = require('./auto_teacher');
let autoTeacher = null;

// Initialize AutoTeacher (lazy load)
const getAutoTeacher = () => {
    if (!autoTeacher) {
        autoTeacher = new AutoTeacher(llmService);
    }
    return autoTeacher;
};

// Train a model with a single session
app.post('/models/train/:model', async (req, res) => {
    try {
        const teacher = getAutoTeacher();
        const { domains, exerciseCount, teacherModel } = req.body;
        
        const result = await teacher.trainModel(req.params.model, {
            domains: domains || ['math', 'logic', 'coding'],
            exerciseCount: exerciseCount || 5,
            teacherModel: teacherModel || 'groq'
        });
        
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Start autonomous training
app.post('/models/train/:model/auto', async (req, res) => {
    try {
        const teacher = getAutoTeacher();
        const { interval, exercisesPerSession, maxSessions, domains } = req.body;
        
        const result = await teacher.startAutoTraining(req.params.model, {
            interval: interval || 60000,
            exercisesPerSession: exercisesPerSession || 3,
            maxSessions: maxSessions || 10,
            domains: domains || ['math', 'logic', 'coding', 'osint']
        });
        
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get training stats
app.get('/models/train/stats', (req, res) => {
    try {
        const teacher = getAutoTeacher();
        res.json({ success: true, ...teacher.getStats() });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================
// CURRICULUM AGENT API
// ========================
const { CurriculumAgent } = require('./curriculum_agent');
let curriculumAgent = null;

const getCurriculumAgent = () => {
    if (!curriculumAgent) {
        curriculumAgent = new CurriculumAgent();
    }
    return curriculumAgent;
};

// Get all available domains
app.get('/curriculum/domains', (req, res) => {
    try {
        const agent = getCurriculumAgent();
        res.json({ success: true, domains: agent.getAllDomains() });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get curriculum for a domain
app.get('/curriculum/:domain', (req, res) => {
    try {
        const agent = getCurriculumAgent();
        const curriculum = agent.getDomainCurriculum(req.params.domain);
        if (!curriculum) {
            return res.status(404).json({ success: false, error: 'Domain not found' });
        }
        res.json({ success: true, ...curriculum });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Create learning agenda for a model
app.post('/curriculum/:model/agenda', (req, res) => {
    try {
        const agent = getCurriculumAgent();
        const { domain, hoursPerDay, daysPerWeek } = req.body;
        const result = agent.createLearningAgenda(req.params.model, domain, {
            hoursPerDay,
            daysPerWeek
        });
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get next exercise for a model
app.get('/curriculum/:model/next/:domain', (req, res) => {
    try {
        const agent = getCurriculumAgent();
        const result = agent.getNextExercise(req.params.model, req.params.domain);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Complete an exercise
app.post('/curriculum/:model/complete/:domain', (req, res) => {
    try {
        const agent = getCurriculumAgent();
        const { score } = req.body;
        const result = agent.completeExercise(req.params.model, req.params.domain, score || 0);
        res.json({ success: true, progress: result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get model curriculum status
app.get('/curriculum/:model/status', (req, res) => {
    try {
        const agent = getCurriculumAgent();
        const status = agent.getModelStatus(req.params.model);
        res.json({ success: true, ...status });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================
// NOTEBOOKLM API
// ========================
const NotebookLMService = require('./notebooklm_service');
let notebookLMService = null;

const getNotebookLMService = () => {
    if (!notebookLMService) {
        notebookLMService = new NotebookLMService(llmService);
    }
    return notebookLMService;
};

// List all NotebookLM domains
app.get('/notebooklm/domains', (req, res) => {
    try {
        const service = getNotebookLMService();
        res.json({ success: true, domains: service.listDomains() });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get content from a domain
app.get('/notebooklm/:domain', (req, res) => {
    try {
        const service = getNotebookLMService();
        const result = service.getDomainContent(req.params.domain);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Add content to a domain
app.post('/notebooklm/:domain', (req, res) => {
    try {
        const service = getNotebookLMService();
        const { title, content, metadata } = req.body;
        const result = service.addContent(req.params.domain, title, content, metadata);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Import text from NotebookLM (copy-paste)
app.post('/notebooklm/:domain/import', (req, res) => {
    try {
        const service = getNotebookLMService();
        const { title, text } = req.body;
        const result = service.importFromText(req.params.domain, title, text);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Generate a lesson from NotebookLM content using Gemini
app.post('/notebooklm/:domain/generate-lesson', async (req, res) => {
    try {
        const service = getNotebookLMService();
        const { topic } = req.body;
        const result = await service.generateLesson(req.params.domain, topic);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Teach a model using NotebookLM content
app.post('/notebooklm/teach/:model', async (req, res) => {
    try {
        const service = getNotebookLMService();
        const { domain, exerciseCount } = req.body;
        const result = await service.teachModel(req.params.model, domain, { exerciseCount });
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Generate podcast-style summary
app.post('/notebooklm/:domain/podcast', async (req, res) => {
    try {
        const service = getNotebookLMService();
        const result = await service.generatePodcastSummary(req.params.domain);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get cached lessons
app.get('/notebooklm/lessons/:domain', (req, res) => {
    try {
        const service = getNotebookLMService();
        const lessons = service.getCachedLessons(req.params.domain);
        res.json({ success: true, lessons });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Track query for metrics (called from chat endpoint)
app.post('/models/:name/track-query', (req, res) => {
    try {
        const { responseTime, tokensGenerated, success, category, qualityScore } = req.body;
        const model = modelMetricsService.recordQuery(req.params.name, {
            responseTime,
            tokensGenerated,
            success,
            category,
            qualityScore
        });
        res.json({ success: true, cognitiveScore: model.cognitive.overallScore });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Training Commentary Endpoints (LLM real-time analysis)
app.get('/training/commentary', (req, res) => {
    try {
        const recent = trainingCommentaryService.getRecentCommentaries(10);
        const last = trainingCommentaryService.getLastCommentary();
        res.json({ success: true, recent, last });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/training/commentary/trigger', async (req, res) => {
    try {
        const { modelName } = req.body;
        const commentary = await trainingCommentaryService.triggerCommentary(modelName);
        if (commentary) {
            res.json({ success: true, commentary });
        } else {
            res.status(500).json({ error: 'Failed to generate commentary' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/training/commentary/archive', async (req, res) => {
    try {
        const result = await trainingCommentaryService.archiveToEmail();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Ingest Endpoint
app.post('/ingest', async (req, res) => {
    const vaultPath = process.env.OBSIDIAN_VAULT_PATH;
    if (!vaultPath) {
        return res.status(400).json({ error: "OBSIDIAN_VAULT_PATH not set in .env" });
    }

    try {
        console.log("[MEMORY] Triggering ingestion...");
        const count = await memoryService.ingestVault(vaultPath);
        res.json({ success: true, message: `Ingestion complete.Processed ${count} files.` });
    } catch (error) {
        console.error("Ingestion error:", error);
        res.status(500).json({ error: error.message });
    }
});

// Google Auth Routes
app.get('/auth/google', (req, res) => {
    const email = req.query.email;
    if (!email) return res.status(400).send("Email requis");
    try {
        const url = googleService.getAuthUrl(email);
        res.redirect(url);
    } catch (e) {
        res.status(500).send(e.message);
    }
});

app.get('/auth/google/callback', async (req, res) => {
    const { code, state } = req.query; // state is the email
    if (code && state) {
        await googleService.handleCallback(code, state);
        res.send("Connexion réussie ! Vous pouvez fermer cette fenêtre.");
    } else {
        res.status(400).send("Erreur d'authentification.");
    }
});

app.get('/google/status', async (req, res) => {
    const status = {};
    for (const email of ACCOUNTS) {
        const client = await googleService.getClient(email);
        status[email] = !!client;
    }
    res.json(status);
});

app.get('/google/calendar', async (req, res) => {
    const email = req.query.email || ACCOUNTS[0];
    if (!email) return res.status(400).json({ error: "No account configured" });

    try {
        const events = await googleService.getUpcomingEvents(email);
        res.json({ events });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/google/emails', async (req, res) => {
    const email = req.query.email || ACCOUNTS[0];
    try {
        const emails = await googleService.getUnreadEmails(email);
        res.json({ emails });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Alias: /google/mail → /google/emails (for API consistency)
app.get('/google/mail', async (req, res) => {
    const email = req.query.email || ACCOUNTS[0];
    try {
        const emails = await googleService.getUnreadEmails(email);
        res.json({ emails });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/google/tasks', async (req, res) => {
    const email = req.query.email || ACCOUNTS[0];
    try {
        const tasks = await googleService.getTasks(email);
        res.json({ tasks });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/google/drive', async (req, res) => {
    const email = req.query.email || ACCOUNTS[0];
    try {
        const files = await googleService.getDriveFiles(email);
        res.json({ files });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Complete/Uncomplete a Google Task
app.put('/google/tasks/:taskId', async (req, res) => {
    const { taskId } = req.params;
    const { completed, email } = req.body;
    const userEmail = email || ACCOUNTS[0];
    try {
        const result = await googleService.completeTask(userEmail, taskId, completed !== false);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// OSINT Endpoints
app.get('/osint/tools', (req, res) => {
    res.json(osintService.getTools());
});

app.post('/osint/run', async (req, res) => {
    const { toolId, target } = req.body;
    try {
        const result = await osintService.runTool(toolId, target);
        res.json({ result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// SpiderFoot Endpoints
app.post('/osint/spiderfoot/start', async (req, res) => {
    if (!userService.canUseTool(req.user, 'osint_full')) return res.status(403).json({ error: "Upgrade required for SpiderFoot" });
    try {
        const result = await osintService.startSpiderFoot();
        res.json({ result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/osint/spiderfoot/stop', async (req, res) => {
    if (!userService.canUseTool(req.user, 'osint_full')) return res.status(403).json({ error: "Upgrade required for SpiderFoot" });
    try {
        const result = await osintService.stopSpiderFoot();
        res.json({ result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/osint/spiderfoot/status', async (req, res) => {
    if (!userService.canUseTool(req.user, 'osint_full')) return res.status(403).json({ error: "Upgrade required for SpiderFoot" });
    try {
        const status = await osintService.getSpiderFootStatus();
        res.json({ status });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


// ===== KEELCLIP INCIDENT ANALYSIS ENDPOINTS =====

/**
 * Analyze incident from image/video
 * POST /incident/analyze
 * Body: { media: base64 or path, mediaType: 'image'|'video', description: 'optional operator input' }
 */
app.post('/incident/analyze', async (req, res) => {
    try {
        const { media, mediaType = 'image', description = '' } = req.body;
        
        if (!media) {
            return res.status(400).json({ error: 'Media (image or video) required' });
        }

        console.log(`[INCIDENT] Analyzing ${mediaType}...`);
        
        // Step 1: Vision Analysis
        const visionAnalysis = await visionService.analyzeKeelClipIncident(media, mediaType);
        console.log('[INCIDENT] Vision analysis complete');

        // Step 2: Generate Quick Summary
        const summary = keelclipAnalyzer.generateQuickSummary(visionAnalysis);

        res.json({
            success: true,
            analysis: visionAnalysis,
            summary: summary
        });

    } catch (error) {
        console.error('[INCIDENT] Analysis failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

/**
 * Generate 5-Why report from analysis
 * POST /incident/generate-5why
 * Body: { analysis: visionAnalysis object, description: 'operator input' }
 */
app.post('/incident/generate-5why', async (req, res) => {
    try {
        const { analysis, description = '' } = req.body;
        
        if (!analysis) {
            return res.status(400).json({ error: 'Vision analysis required' });
        }

        console.log('[INCIDENT] Generating 5-Why report...');
        
        // Generate complete 5-Why report
        const report = await keelclipAnalyzer.generate5Why(analysis, description);
        
        // Validate report quality
        const validation = keelclipAnalyzer.validate5WhyReport(report);
        
        console.log(`[INCIDENT] Report generated - Score: ${validation.score}/100`);

        res.json({
            success: true,
            report: report,
            validation: validation
        });

    } catch (error) {
        console.error('[INCIDENT] 5-Why generation failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

/**
 * Complete workflow: Analyze + Generate 5-Why in one call
 * POST /incident/complete
 * Body: { media: base64 or path, mediaType: 'image'|'video', description: 'operator input' }
 */
app.post('/incident/complete', async (req, res) => {
    try {
        const { media, mediaType = 'image', description = '' } = req.body;
        
        if (!media) {
            return res.status(400).json({ error: 'Media (image or video) required' });
        }

        console.log(`[INCIDENT] Complete workflow: ${mediaType} → 5-Why`);
        
        // Step 1: Vision Analysis
        const visionAnalysis = await visionService.analyzeKeelClipIncident(media, mediaType);
        console.log('[INCIDENT] ✓ Vision analysis');

        // Step 2: Generate 5-Why
        const report = await keelclipAnalyzer.generate5Why(visionAnalysis, description);
        console.log('[INCIDENT] ✓ 5-Why generated');

        // Step 3: Validate
        const validation = keelclipAnalyzer.validate5WhyReport(report);
        console.log(`[INCIDENT] ✓ Validation: ${validation.score}/100`);

        res.json({
            success: true,
            analysis: visionAnalysis,
            report: report,
            validation: validation,
            summary: keelclipAnalyzer.generateQuickSummary(visionAnalysis)
        });

    } catch (error) {
        console.error('[INCIDENT] Complete workflow failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

/**
 * Validate existing 5-Why report
 * POST /incident/validate
 * Body: { report: 'text of report' }
 */
app.post('/incident/validate', (req, res) => {
    try {
        const { report } = req.body;
        
        if (!report) {
            return res.status(400).json({ error: 'Report text required' });
        }

        const validation = keelclipAnalyzer.validate5WhyReport(report);
        
        res.json({
            success: true,
            validation: validation
        });

    } catch (error) {
        console.error('[INCIDENT] Validation failed:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Finance Endpoints
app.get('/finance/portfolio', async (req, res) => {
    if (!userService.canUseTool(req.user, 'finance_dashboard')) return res.status(403).json({ error: "Upgrade required for Finance" });
    try {
        const data = await financeService.getPortfolioData();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/finance/news', async (req, res) => {
    try {
        const news = await financeService.getNews();
        res.json(news);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/finance/ticker', async (req, res) => {
    const symbol = req.query.symbol || 'BTC/USD';
    try {
        const data = await financeService.getTickerData(symbol);
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Project Management Endpoints
app.get('/projects', (req, res) => {
    const projects = projectService.getProjects();
    res.json(projects);
});

app.post('/projects', (req, res) => {
    const { name, description } = req.body;
    if (!name) return res.status(400).json({ error: "Name required" });
    const project = projectService.createProject(name, description);
    res.json(project);
});

app.put('/projects/:id', (req, res) => {
    const project = projectService.updateProject(req.params.id, req.body);
    if (project) res.json(project);
    else res.status(404).json({ error: "Project not found" });
});

app.delete('/projects/:id', (req, res) => {
    const success = projectService.deleteProject(req.params.id);
    res.json({ success });
});

app.post('/projects/:id/tasks', (req, res) => {
    const { content, status } = req.body;
    if (!content) return res.status(400).json({ error: "Content required" });
    const task = projectService.addTask(req.params.id, content, status);
    if (task) res.json(task);
    else res.status(404).json({ error: "Project not found" });
});

app.put('/projects/:id/tasks/:taskId', (req, res) => {
    const task = projectService.updateTask(req.params.id, req.params.taskId, req.body);
    if (task) res.json(task);
    else res.status(404).json({ error: "Task not found" });
});

app.delete('/projects/:id/tasks/:taskId', (req, res) => {
    const success = projectService.deleteTask(req.params.id, req.params.taskId);
    res.json({ success });
});

app.post('/feedback', async (req, res) => {
    try {
        const { originalQuery, wrongResponse, correction } = req.body;
        if (!originalQuery || !correction) {
            return res.status(400).json({ error: "Missing fields" });
        }

        console.log(`[FEEDBACK] Received correction for: "${originalQuery}"`);
        await memoryService.addCorrection(originalQuery, wrongResponse, correction);

        res.json({ success: true, message: "Correction mémorisée. Je ne ferai plus cette erreur." });
    } catch (error) {
        console.error("Feedback error:", error);
        res.status(500).json({ error: error.message });
    }
});

// Settings Endpoints
app.get('/settings', (req, res) => {
    const settings = settingsService.getSettings();
    res.json(settings);
});

app.post('/settings', (req, res) => {
    try {
        const updated = settingsService.saveSettings(req.body);

        // Apply API Keys to Env
        if (updated.apiKeys) {

            if (updated.apiKeys.openai) process.env.OPENAI_API_KEY = updated.apiKeys.openai;
            if (updated.apiKeys.anthropic) process.env.ANTHROPIC_API_KEY = updated.apiKeys.anthropic;
            if (updated.apiKeys.perplexity) process.env.PERPLEXITY_API_KEY = updated.apiKeys.perplexity;
            if (updated.apiKeys.anythingllm_url) process.env.ANYTHING_LLM_URL = updated.apiKeys.anythingllm_url;
            if (updated.apiKeys.anythingllm_key) process.env.ANYTHING_LLM_KEY = updated.apiKeys.anythingllm_key;
        }

        res.json(updated);
    } catch (error) {
        res.status(500).json({ error: "Failed to save settings" });
    }
});

app.post('/chat', async (req, res) => {
    try {
        const { message, image, pattern, provider, model, sessionId } = req.body;
        const user = req.user;

        // PERMISSION CHECK: Model
        if (!userService.canUseModel(user, provider || 'local', model || '')) {
            return res.status(403).json({
                reply: `⛔ ACCÈS REFUSÉ : Votre niveau (${user.tier}) ne permet pas d'utiliser le modèle ${model} (${provider}).`,
                error: "Insufficient Permissions"
            });
        }

        // PERMISSION CHECK: Fabric Pattern
        if (pattern && !userService.canUseTool(user, `fabric_basic`)) {
            return res.status(403).json({
                reply: `⛔ ACCÈS REFUSÉ : Votre niveau (${user.tier}) ne permet pas d'utiliser la bibliothèque Fabric.`,
                error: "Insufficient Permissions"
            });
        }

        console.log(`[CHAT] User: ${user.username} (${user.tier}) | Provider: ${provider} | Model: ${model}`);

        // Load Session
        let currentSession = sessionId ? sessionManager.getSession(sessionId) : null;
        if (!currentSession) {
            // Create new if not exists or not provided
            currentSession = sessionManager.createSession(message.substring(0, 30) + "...");
        }

        // Update title if it's the first user message
        if (currentSession.messages.length <= 1) {
            currentSession.title = message.substring(0, 30) + "...";
        }

        let chatHistory = currentSession.messages;

        // Handle Commands
        if (message.trim().toLowerCase() === '/clear') {
            currentSession.messages = [{ role: "assistant", content: "Mémoire effacée. On repart à neuf." }];
            sessionManager.saveSession(currentSession.id, currentSession);
            return res.json({ reply: "Mémoire effacée.", sessionId: currentSession.id });
        }

        // Handle Ingest Command via Chat
        if (message.trim().toLowerCase() === '/ingest') {
            const vaultPath = process.env.OBSIDIAN_VAULT_PATH;
            if (!vaultPath) return res.json({ reply: "Erreur: OBSIDIAN_VAULT_PATH non configuré." });

            // Trigger async ingestion
            const count = await memoryService.ingestVault(vaultPath);
            return res.json({ reply: `Ingestion terminée.J'ai digéré ${count} notes.` });
        }

        // Handle Feedback (Correction)
        if (message.trim().startsWith('/feedback')) {
            return res.json({ reply: "Utilise l'interface graphique pour donner du feedback." });
        }

        // Handle Bye Command (Unload Memory for Gaming)
        if (message.trim().toLowerCase() === '/bye') {
            try {
                console.log("[BYE] Initiating System Integrity Check...");
                const { execSync } = require('child_process');

                try {
                    // Run self-healing script from project root
                    execSync('node server/self_heal.js', { stdio: 'inherit', cwd: require('path').join(__dirname, '..') });
                    console.log("[BYE] System Integrity Verified.");
                } catch (err) {
                    console.error("[BYE] System Integrity Check Failed:", err.message);
                    return res.json({ reply: "⚠️ ATTENTION : Les tests de sécurité ont échoué. Vérifiez les logs avant de fermer." });
                }

                await llmService.unloadModel(model || "granite3.1-moe:1b");

                const byeResponse = `### SYSTÈME TH3 THIRTY3

**PROTOCOLE DE SAUVEGARDE ACTIVÉ.**

Données enregistrées :
*   **Plan Global :** Phase 1 - Stabilisation Cashflow & Arrêt Hémorragie.
*   **Objectif Actuel (LOCK) :** Logistique de déploiement & Exécution du shift de travail (Cible : 484$).
*   **Statut :** EN ATTENTE D'EXÉCUTION.

Je coupe les processus cognitifs. Libère ta mémoire vive. Je garde la structure.

À ton retour, la première chose que tu verras sera :
> **RAPPEL OBJECTIF :** Shift Travail terminé ?
> **STATUS :** [YES/NO]

**SERVER SHUTDOWN...**
**VRAM CLEARED.**
**GO.**`;

                return res.json({ reply: byeResponse });
            } catch (e) {
                console.error("Error unloading model:", e);
                return res.json({ reply: "Erreur lors de la déconnexion du cerveau. Check la console." });
            }
        }

        const startTotal = Date.now();
        console.log("[CHAT] Step 1: Context Injection");

        // 1. Context Injection (Local Files + Vector Memory)
        console.time("ContextInjection");
        let messageWithContext = await injectFileContent(message);

        // RAG: Search Long-Term Memory
        console.log("[CHAT] Step 1b: Memory Search");
        const memoryResults = await memoryService.search(message, 3); // Top 3 relevant memories
        if (memoryResults.length > 0) {
            const memoryContext = memoryResults.map(m => m.text).join('\n---\n');
            messageWithContext += `\n\n[MÉMOIRE LONG-TERME (RAG)]\nVoici des informations pertinentes tirées de ta mémoire (notes ou conversations passées) :\n${memoryContext}\n[FIN MÉMOIRE]\n`;
            console.log(`[RAG] Injected ${memoryResults.length} memories.`);
        }

        // 1c. INCIDENT ANALYSIS (Auto-detect VPO context)
        const vpoKeywords = ['panne', 'incident', 'keelclip', '5 why', '5why', 'ewo', 'rca', 'machine', 'emballage', 'maintenance', 'défaut', 'bourrage'];
        const isIncidentContext = vpoKeywords.some(keyword => message.toLowerCase().includes(keyword));
        
        let incidentAnalysis = null;
        if (image && isIncidentContext) {
            console.log("[CHAT] 🔍 VPO INCIDENT DETECTED - Analyzing image...");
            try {
                // Analyze incident image
                incidentAnalysis = await visionService.analyzeKeelClipIncident(image, 'image');
                const summary = keelclipAnalyzer.generateQuickSummary(incidentAnalysis);
                
                messageWithContext += `\n\n[ANALYSE VISUELLE INCIDENT]\n${summary}\n[FIN ANALYSE]\n`;
                console.log("[CHAT] ✓ Incident analysis injected");
                
                // If user explicitly asks for 5-Why, generate it
                if (message.toLowerCase().includes('5 why') || message.toLowerCase().includes('5why') || message.toLowerCase().includes('rapport')) {
                    console.log("[CHAT] 📋 Generating 5-Why report...");
                    const report = await keelclipAnalyzer.generate5Why(incidentAnalysis, message);
                    const validation = keelclipAnalyzer.validate5WhyReport(report);
                    
                    messageWithContext += `\n\n[RAPPORT 5-WHY GÉNÉRÉ]\n${report}\n\n[VALIDATION: ${validation.score}/100 - ${validation.recommendation}]\n`;
                    console.log(`[CHAT] ✓ 5-Why report generated (Score: ${validation.score})`);
                }
            } catch (error) {
                console.error("[CHAT] Incident analysis failed:", error.message);
                messageWithContext += `\n\n[NOTE: Tentative d'analyse visuelle échouée - ${error.message}]\n`;
            }
        }
        
        console.timeEnd("ContextInjection");


        // 2. Google Data Requests (Parallelized)
        console.log("[CHAT] Step 2: Google Context");
        console.time("GoogleService");
        const googleContext = await fetchGoogleContext(message);
        messageWithContext += googleContext;
        console.timeEnd("GoogleService");

        // 3. Finance Data Requests
        console.log("[CHAT] Step 3: Finance Context");
        console.time("FinanceService");
        const financeContext = await fetchFinanceContext(message);
        messageWithContext += financeContext;
        console.timeEnd("FinanceService");

        // 3. System Prompt Construction
        console.log("[CHAT] Step 4: System Prompt");
        console.time("StyleAnalysis");
        let finalSystemPrompt;

        // CHECK FOR LOCAL/OLLAMA OPTIMIZATION
        // We treat 'ollama-studio' workspace in AnythingLLM as local/minimal
        const isLocal = provider === 'local'
            || provider === 'lmstudio'
            || (model && (model.includes('ollama') || model.includes('ollama-studio')));

        if (isLocal) {
            console.log("[OPTIMIZATION] Using Minimal Persona for Local/Ollama");
            finalSystemPrompt = MINIMAL_PERSONA;
            // Skip Style Analysis to save tokens
        } else {
            finalSystemPrompt = PERSONA;

            if (pattern) {
                // MODE FABRIC
                finalSystemPrompt += `
\n[MODE EXPERT ACTIVÉ]
1. **STYLE** : Français standard PROFESSIONNEL et TECHNIQUE.
2. **FORMAT** : Réponse directe. Juste le résultat.
3. **TON** : Efficacité maximale.
\n[PATTERN: ${pattern.toUpperCase()}]\n${getPatternContent(pattern)}`;
            } else {
                // MODE CHAT
                const styleProfile = styleService.analyzeHistory(chatHistory);
                const styleInstructions = styleService.generateStylePrompt(styleProfile);

                finalSystemPrompt += `
\n[MODE APPRENTISSAGE ACTIVÉ]
1. **OBJECTIF** : Analyse le style de l'utilisateur dans l'historique (vocabulaire, structure de phrase, jargon).
2. **ADAPTATION** : Imite son style. Deviens son miroir.
3. **ÉVOLUTION** : Plus tu parles avec lui, plus tu dois lui ressembler. Utilise ses expressions. Sois son extension numérique.
${styleInstructions}`;
            }
        }
        console.timeEnd("StyleAnalysis");

        // 4. LLM Generation
        console.log("[CHAT] Step 5: LLM Generation");
        console.time("LLMGeneration");
        // Pass provider and model to LLM Service
        const reply = await llmService.generateResponse(messageWithContext, image, provider, model, finalSystemPrompt);
        console.timeEnd("LLMGeneration");

        console.log(`[PERF] Total Request Time: ${Date.now() - startTotal}ms`);

        // Save to Session
        const { v4: uuidv4 } = require('uuid');
        const userMsgId = uuidv4();
        const agentMsgId = uuidv4();

        currentSession.messages.push({ id: userMsgId, role: 'user', content: message });
        currentSession.messages.push({ id: agentMsgId, role: 'assistant', content: reply });

        // Save to Long-Term Memory (Vector DB)
        // We do this asynchronously so we don't block the response
        memoryService.addChatExchange(message, reply).then(() => {
            console.log("[MEMORY] Chat exchange saved to vector DB.");
        }).catch(err => console.error("[MEMORY] Failed to save chat:", err));

        // Keep history manageable (last 20 for context, but we save all for session)
        // Actually, for context window we slice, but for storage we might want to keep more?
        // For now, let's just save everything to the file.
        sessionManager.saveSession(currentSession.id, currentSession);

        res.json({ reply, sessionId: currentSession.id, userMsgId, agentMsgId });

    } catch (error) {
        console.error('CRITICAL ERROR:', error);
        require('fs').writeFileSync('server_error.log', `[${new Date().toISOString()}] ${error.stack}\n`, { flag: 'a' });
        res.status(500).json({
            reply: "Erreur système critique.",
            error: error.message
        });
    }
});

// OSINT Analysis Endpoint
app.post('/osint/analyze', async (req, res) => {
    const { toolId, output } = req.body;
    if (!toolId || !output) return res.status(400).json({ error: "Missing toolId or output" });

    try {
        // Use Gemini Flash by default for speed/quality balance if available, otherwise local
        const analysis = await llmService.analyzeOsintResult(toolId, output);
        res.json({ analysis });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Cyber Training Routes (Ethical Hacking Agent Training)
const cyberTrainingRoutes = require('./cyber_training_routes');
app.use('/api/cyber-training', requireTier('operator'), cyberTrainingRoutes); // PREMIUM+

// Tracking Routes (5-Why Incident Tracking)
const trackingRoutes = require('./tracking_routes');
app.use('/api/tracking', trackingRoutes);

// Expert Agents Routes (Multi-Agent Specialized Experts)
const expertAgentsRoutes = require('./expert_agents_routes');
app.use('/api/experts', expertAgentsRoutes);

// OSINT Expert Agents Routes (Tool-Specific OSINT Experts)
const osintExpertAgentsRoutes = require('./osint_expert_agents_routes');
app.use('/api/osint-experts', requireTier('operator'), osintExpertAgentsRoutes); // PREMIUM+

// Hacking Expert Agents Routes (Tool-Specific Hacking Experts)
const hackingExpertAgentsRoutes = require('./hacking_expert_agents_routes');
app.use('/api/hacking-experts', requireTier('operator'), hackingExpertAgentsRoutes); // PREMIUM+

// Agent Memory Routes (Embeddings + Pieces Integration)
const agentMemoryRoutes = require('./agent_memory_routes');
app.use('/api/agent-memory', agentMemoryRoutes);

// Offline Mode Routes (Network Detection + Energy Optimization)
const offlineModeRoutes = require('./offline_mode_routes');
app.use('/api/offline-mode', offlineModeRoutes);

// Initialize Offline Mode Service (monitors network automatically)
const OfflineModeService = require('./offline_mode_service');
const offlineService = new OfflineModeService();
offlineService.on('offline', (data) => {
    console.log('[SYSTEM] 🔴 OFFLINE MODE ACTIVATED - Using local agents');
});
offlineService.on('online', (data) => {
    console.log('[SYSTEM] 🟢 ONLINE MODE RESTORED - Cloud services available');
});

// Orchestrator Routes (Multi-Agent Team Leader)
const orchestratorRoutes = require('./orchestrator_routes');
app.use('/api/orchestrator', orchestratorRoutes);

// KPI Dashboard Routes (Pilier XI - Codex Operandi - SOC Personnel)
const kpiDashboardRoutes = require('./kpi_dashboard_routes');
app.use('/api/dashboard', kpiDashboardRoutes);

// Tor Network Routes (Connexion anonyme pour OSINT/Hacking)
const torRoutes = require('./tor_routes');
app.use('/api/tor', torRoutes);

// Real Training Routes (intensive model training sessions)
app.use('/api/real-training', realTrainingRoutes);
app.use('/api/cloud-optimizer', cloudOptimizerRoutes);
app.use('/api/director', agentDirectorRoutes);

// Shodan Routes (Cybersecurity Training & OSINT)
const shodanRoutes = require('./shodan_routes')(shodanService, modelMetricsService, llmService);
app.use('/api/shodan', shodanRoutes);
console.log('[SYSTEM] Shodan routes mounted at /api/shodan');

// VPN Automation Routes (Connection, Rotation, Health Check)
const vpnRoutes = require('./vpn_routes');
app.use('/api/vpn', vpnRoutes);
console.log('[SYSTEM] VPN routes mounted at /api/vpn');

// Network Failover Routes (RISK-006 Mitigation - Cloud/Local failover)
const networkRoutes = require('./network_routes');
app.use('/api/network', networkRoutes);
console.log('[SYSTEM] Network Failover routes mounted at /api/network (RISK-006)');

// Server Logs Routes (RISK-006 - Internal Console Display)
const logsRoutes = require('./logs_routes');
app.use('/api/logs', logsRoutes);
console.log('[SYSTEM] Logs routes mounted at /api/logs (Internal Console)');

// Camera Control Routes (EasyLife IP Cameras)
const cameraRoutes = require('./camera_routes');
app.use('/api/cameras', cameraRoutes);
console.log('[SYSTEM] Camera routes mounted at /api/cameras (EasyLife Integration)');

// Tuya Camera Routes (Local Protocol Control)
const tuyaRoutes = require('./tuya_routes');
app.use('/api/tuya', tuyaRoutes);
console.log('[SYSTEM] Tuya routes mounted at /api/tuya (EasyLife Local Control)');

// Camera Discovery Routes (Passive Network Scanner for Personal Cameras)
const CameraDiscoveryService = require('./camera_discovery_service');
const cameraDiscoveryService = new CameraDiscoveryService();
const cameraDiscoveryRoutes = require('./camera_discovery_routes')(cameraDiscoveryService);
app.use('/api/camera-discovery', cameraDiscoveryRoutes);
console.log('[SYSTEM] Camera Discovery routes mounted at /api/camera-discovery (Passive Scanner)');

// Docker Management Routes (Container Auto-Start & Control)
const dockerRoutes = require('./docker_routes');
app.use('/api/docker', dockerRoutes);
console.log('[SYSTEM] Docker routes mounted at /api/docker (Container Management)');

// OSINT Expert Team Routes (Multi-Agent OSINT Investigation)
const osintTeamRoutes = require('./osint_team_routes');
app.use('/api/osint-team', osintTeamRoutes);
console.log('[SYSTEM] OSINT Team routes mounted at /api/osint-team (Expert Team 2025)');

// Security Research Routes - Set LLM Service (routes already mounted at line ~33)
securityRoutes.setLLMService(llmService);
console.log('[SYSTEM] Security Research LLM Service connected (Defensive Ops)');


// Initialize Socket.io with HTTP server
socketService.initialize(server);

// Connect logs routes to socket service for real-time streaming
if (logsRoutes.setSocketService) {
    logsRoutes.setSocketService(socketService);
    console.log('[SYSTEM] Logs connected to Socket.io for real-time streaming');
}

// Start Server
server.listen(port, async () => {
    console.log(`Server running on port ${port}`);
    console.log(`System ready. Identity: ${IDENTITY.name}`);
    
    // =========================================
    // AUTOMATIC DOCKER CONTAINER STARTUP
    // =========================================
    try {
        const dockerAutoStart = require('./docker_autostart_service');
        console.log('\n[SYSTEM] 🐳 Checking Docker infrastructure...');
        
        const dockerResult = await dockerAutoStart.startAllContainers();
        
        if (dockerResult.success) {
            console.log('[SYSTEM] ✅ Docker infrastructure ready');
        } else {
            console.log('[SYSTEM] ⚠️ Some Docker containers failed to start');
            console.log('[SYSTEM] 💡 Run: docker-compose -f docker/docker-compose.yml up -d');
        }
    } catch (error) {
        console.log('[SYSTEM] ⚠️ Docker auto-start skipped:', error.message);
        console.log('[SYSTEM] 💡 Docker Desktop may not be running');
    }
    
    // =========================================
    // AUTOMATIC TOR VERIFICATION
    // =========================================
    try {
        const torStartupCheck = require('./tor_startup_check');
        console.log('\n[SYSTEM] 🧅 Running automatic Tor verification...');
        const torResult = await torStartupCheck.performStartupCheck();
        
        if (torResult.isTor) {
            console.log('[SYSTEM] ✅ Tor is ACTIVE and VERIFIED');
            console.log(`[SYSTEM] 🧅 Exit IP: ${torResult.ip}`);
        } else if (torResult.portOpen) {
            console.log('[SYSTEM] ⚠️ Port 9050 active but NOT connected to Tor network');
            console.log('[SYSTEM] 💡 This may be Tor Browser - for best results use standalone tor.exe');
        } else {
            console.log('[SYSTEM] ⚠️ Tor not available - OSINT requests will use direct connection');
        }
    } catch (error) {
        console.log('[SYSTEM] ⚠️ Tor check skipped:', error.message);
    }
    
    console.log('\n[SYSTEM] ═══════════════════════════════════════════════');
    console.log('[SYSTEM]   TH3 THIRTY3 - FULLY OPERATIONAL');
    console.log('[SYSTEM] ═══════════════════════════════════════════════\n');
});












