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

// Initialize Settings & Load Keys (MOVED TO TOP)
const settingsService = require('./settings_service');
const currentSettings = settingsService.getSettings();
if (currentSettings.apiKeys) {
    console.log("[SYSTEM] Loading API Keys from Settings...");

    if (currentSettings.apiKeys.openai) process.env.OPENAI_API_KEY = currentSettings.apiKeys.openai;
    if (currentSettings.apiKeys.anthropic) process.env.ANTHROPIC_API_KEY = currentSettings.apiKeys.anthropic;
    if (currentSettings.apiKeys.perplexity) process.env.PERPLEXITY_API_KEY = currentSettings.apiKeys.perplexity;
    if (currentSettings.apiKeys.anythingllm_url) process.env.ANYTHING_LLM_URL = currentSettings.apiKeys.anythingllm_url;
    if (currentSettings.apiKeys.anythingllm_key) process.env.ANYTHING_LLM_KEY = currentSettings.apiKeys.anythingllm_key;
    if (currentSettings.apiKeys.gemini) process.env.GEMINI_API_KEY = currentSettings.apiKeys.gemini;
    if (!process.env.GEMINI_API_KEY && currentSettings.apiKeys.google) process.env.GEMINI_API_KEY = currentSettings.apiKeys.google;
}

// Connect to MongoDB
const mongoose = require('mongoose');
const MONGO_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/th3-thirty3';
mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.error('❌ MongoDB Connection Error:', err));

// Load Models
require('./models/User');
require('./models/Project');
require('./models/Task');
require('./models/Transaction');

app.use(cors());
const helmet = require('helmet');
app.use(helmet());
app.use(express.json({ limit: '50mb' }));

// ============================================
// SYSTEM & HEALTH ROUTES
// ============================================

// Initialize LLM Service (Required first)
const LLMService = require('./llm_service');
const llmService = new LLMService();
const GoogleService = require('./google_service');
const googleService = new GoogleService();

// Initialize Socket Service
const SocketService = require('./socket_service');
const socketService = new SocketService();

// Initialize Finance Service (Payment)
const PaymentService = require('./payment_service');
const paymentService = new PaymentService(socketService); // Inject Socket

// Initialize Project Service
const ProjectService = require('./project_service');
const projectService = new ProjectService(socketService); // Inject Socket

// Initialize Model Metrics Service (Early Init for Sync Route)
const ModelMetricsService = require('./model_metrics_service');
const modelMetricsService = new ModelMetricsService();

app.get('/health', (req, res) => {
    res.json({
        status: 'online',
        uptime: process.uptime(),
        timestamp: Date.now()
    });
});

app.get('/models', async (req, res) => {
    try {
        const models = await llmService.listModels();
        res.json(models);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Alias for compatibility
app.get('/api/models', async (req, res) => {
    try {
        const models = await llmService.listModels();
        res.json(models);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Ollama Sync Endpoint Removed (Cloud Only Mode)

// ============================================
// AUTH ROUTES (Public - No middleware required)
// Must be BEFORE authMiddleware to allow login/register
// ============================================
const authRoutes = require('./auth_routes');
app.use('/auth', authRoutes);

// Google OAuth Routes (Public)
// Google Auth Routes (Moved to public section)
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
        try {
            await googleService.handleCallback(code, state);
            // Redirect back to frontend with success parameter
            const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5174';
            res.redirect(`${frontendUrl}?google_auth=success&email=${encodeURIComponent(state)}`);
        } catch (error) {
            console.error('[GOOGLE] Callback error:', error);
            const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5174';
            res.redirect(`${frontendUrl}?google_auth=error&message=${encodeURIComponent(error.message)}`);
        }
    } else {
        const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5174';
        res.redirect(`${frontendUrl}?google_auth=error&message=missing_params`);
    }
});

// ============================================
// PUBLIC ROUTES (No auth required)
// Patterns & Models - needed by frontend before login
// ============================================

// HexStrike Expert Agents Routes (Moved to Public for Visibility)
const hexstrikeExpertRoutes = require('./hexstrike_expert_agents_routes');
app.use('/api/hexstrike-experts', hexstrikeExpertRoutes);

// Elite Hacker Scenarios Routes (Moved to Public for Visibility)
const eliteScenariosRoutes = require('./elite_scenarios_routes');
app.use('/api/elite-scenarios', eliteScenariosRoutes);


// Fabric Patterns Endpoints (PUBLIC)
app.get('/patterns', (req, res) => {
    try {
        const patterns = getPatterns().sort();
        if (!patterns || patterns.length === 0) {
            console.warn("[FABRIC] No patterns found. Check if 'fabric-official' is cloned in server directory.");
        }
        res.json(patterns);
    } catch (error) {
        console.error("Error reading patterns:", error);
        res.status(500).json({ error: "Failed to read patterns" });
    }
});

app.get('/patterns/:name', (req, res) => {
    try {
        const patternName = req.params.name;
        // Now returns object { system, user } or null
        const content = getPatternContent(patternName);

        if (!content) {
            return res.status(404).json({ error: "Pattern not found" });
        }

        res.json({
            content: content.system || '', // Backward compatibility
            system: content.system || '',
            user: content.user || ''
        });
    } catch (error) {
        console.error("Error reading pattern content:", error);
        res.status(500).json({ error: "Failed to read pattern content" });
    }
});

// Models Endpoint (PUBLIC - needed for model selector)
app.get('/models', async (req, res) => {
    try {
        const models = await llmService.listModels();
        res.json(models);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Settings Endpoints (PUBLIC - needed for settings page before login)
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
            if (updated.apiKeys.gemini) process.env.GEMINI_API_KEY = updated.apiKeys.gemini;
        }

        res.json(updated);
    } catch (error) {
        res.status(500).json({ error: "Failed to save settings" });
    }
});

// Google Data Routes (PUBLIC - for Gmail sidebar)
// Account list for Google services
const ACCOUNTS_PUBLIC = [
    'th3thirty3@gmail.com',
    'mikegauthierguillet@gmail.com',
    'mgauthierguillet@gmail.com'
];

app.get('/google/status', async (req, res) => {
    const status = {};
    console.log("[GOOGLE] /google/status called. Checking accounts:", ACCOUNTS_PUBLIC);
    for (const email of ACCOUNTS_PUBLIC) {
        try {
            const client = await googleService.getClient(email);
            status[email] = !!client;
            console.log(`[GOOGLE] Status for ${email}: ${!!client}`);
        } catch (e) {
            console.error(`[GOOGLE] Error checking status for ${email}:`, e.message);
            status[email] = false;
        }
    }
    res.json(status);
});

app.get('/google/emails', async (req, res) => {
    const email = req.query.email || ACCOUNTS_PUBLIC[0];
    try {
        const emails = await googleService.getUnreadEmails(email);
        res.json({ emails: emails || [] });
    } catch (error) {
        console.error('[GOOGLE] Email fetch error:', error.message);
        res.json({ emails: [], error: error.message });
    }
});

app.get('/google/emails/:id', async (req, res) => {
    const email = req.query.email || ACCOUNTS_PUBLIC[0];
    const messageId = req.params.id;
    try {
        const emailData = await googleService.getEmailById(email, messageId);
        if (emailData) {
            res.json(emailData);
        } else {
            res.status(404).json({ error: 'Email not found' });
        }
    } catch (error) {
        console.error('[GOOGLE] Email detail error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.get('/google/calendar', async (req, res) => {
    const email = req.query.email || ACCOUNTS_PUBLIC[0];
    try {
        const events = await googleService.getUpcomingEvents(email);
        res.json({ events: events || [] });
    } catch (error) {
        res.json({ events: [], error: error.message });
    }
});

app.get('/google/tasks', async (req, res) => {
    const email = req.query.email || ACCOUNTS_PUBLIC[0];
    try {
        const tasks = await googleService.getTasks(email);
        res.json({ tasks: tasks || [] });
    } catch (error) {
        res.json({ tasks: [], error: error.message });
    }
});

app.get('/google/drive', async (req, res) => {
    const email = req.query.email || ACCOUNTS_PUBLIC[0];
    try {
        const files = await googleService.getDriveFiles(email);
        res.json({ files: files || [] });
    } catch (error) {
        res.json({ files: [], error: error.message });
    }
});

// Auth Middleware (Applied to all routes AFTER public routes)
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
const paymentRoutes = require('./payment_routes')(paymentService);
app.use('/api/payment', paymentRoutes);

// Payment Dashboard Routes (Stats temps rel)
const paymentDashboardRoutes = require('./payment_dashboard_routes');
app.use('/api/payment', paymentDashboardRoutes);

// Initialize Dart Service
const DartService = require('./dart_service');
const dartService = new DartService(llmService);

// Dart AI Routes - pass injected service
const dartRoutes = require('./routes/dart')(dartService);
app.use('/api/dart', dartRoutes);

// HexStrike AI Routes (150+ Security Tools + Gemini 3 Integration)
const hexstrikeRoutes = require('./hexstrike_routes');
app.use('/api/hexstrike', hexstrikeRoutes);
console.log('[SYSTEM] HexStrike AI integration loaded (150+ security tools)');



// Docker Container Routes (Kali, Tor, Security Tools)
const dockerRoutes = require('./docker_routes');
app.use('/api/docker', dockerRoutes);
console.log('[SYSTEM] Docker Container Routes loaded (Kali-Tor, OSINT, Cyber)');

// Initialize Tools Standby Service (auto-start tools except Tor)
const toolsStandby = require('./tools_standby_service');
toolsStandby.initialize().then(status => {
    console.log('[SYSTEM] Tools Standby Service initialized:', Object.keys(status.tools).map(t => `${t}:${status.tools[t].status}`).join(', '));
}).catch(err => {
    console.error('[SYSTEM] Tools Standby init failed:', err.message);
});


// Model Configuration
const IDENTITY = require('./config/identity');

const { PERSONA, MINIMAL_PERSONA } = require('./config/prompts');

const ACCOUNTS = [
    'th3thirty3@gmail.com',           // PRIORITÉ - Compte principal
    'mikegauthierguillet@gmail.com',
    'mgauthierguillet@gmail.com'
];

// Model Configuration
const modelName = IDENTITY.default_model;
console.log(`[SYSTEM] ${IDENTITY.name} v${IDENTITY.version} connect� : ${modelName}`);

// Initialize Memory Service
const memoryService = new MemoryService();
memoryService.initialize();



// Initialize MCP Service (Protocol Nexus)
const MCPService = require('./mcp_service');
const mcpService = new MCPService();

// Initialize Context Service
const ContextService = require('./context_service');
const contextService = new ContextService(memoryService, mcpService);




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

// Connect to Desktop Commander (Docker)
// Mounts the project root to /workspace for file management capabilities
const projectRoot = path.join(__dirname, '..');
mcpService.connectStdio(
    'desktop-commander',
    'docker',
    [
        'run', '-i', '--rm',
        '-v', `${projectRoot}:/workspace`,
        'mcp/desktop-commander:latest'
    ]
).then(() => console.log(`[MCP] Desktop Commander connected (workspace: ${projectRoot})`))
    .catch(err => console.error("[MCP] Failed to connect to Desktop Commander:", err));

// Connect to Stripe MCP (Docker)
// Uses API keys from .env
const stripeKey = process.env.STRIPE_SECRET_KEY;
if (stripeKey) {
    mcpService.connectStdio(
        'stripe',
        'docker',
        [
            'run', '-i', '--rm',
            '-e', `STRIPE_SECRET_KEY=${stripeKey}`,
            'mcp/stripe:latest'
        ]
    ).then(() => console.log("[MCP] Stripe MCP connected"))
        .catch(err => console.error("[MCP] Failed to connect to Stripe:", err));
} else {
    console.warn("[MCP] STRIPE_SECRET_KEY not set. Skipping Stripe connection.");
}

// Connect to Pieces MCP Server
const PIECES_HOST = process.env.PIECES_HOST || 'localhost';
const PIECES_MCP_URL = `http://${PIECES_HOST}:39300/model_context_protocol/2025-03-26/mcp`;
const piecesSessionId = uuidv4();

// Attempt connection but don't crash if missing (Optional Integration)
mcpService.connectSSE('pieces', PIECES_MCP_URL, piecesSessionId)
    .catch(err => {
        // Suppress verbose error if just "connection refused" (common if Pieces not installed)
        if (err.code === 'ECONNREFUSED' || (err.message && err.message.includes('ECONNREFUSED'))) {
            console.log("[MCP] Pieces OS not detected (Optional). Integration disabled.");
        } else {
            console.error("[MCP] Failed to connect to Pieces:", err.message);
        }
    });

// Pass MCP Service to LLM Service
llmService.setMCPService(mcpService);

// Initialize Agent Director Service (Th3 Thirty3 Manager)
// Initialize Agent Director Service (Th3 Thirty3 Manager)
const Th3AgentDirectorService = require('./agent_director_service');
const agentDirectorRoutes = require('./agent_director_routes');
const agentDirector = new Th3AgentDirectorService(llmService, llmService.anythingLLMWrapper);
agentDirectorRoutes.setAgentDirector(agentDirector);
app.use('/api/director', agentDirectorRoutes);
console.log('[AGENT_DIRECTOR] Th3 Thirty3 Director initialized - Managing: Cybersécurité, OSINT');

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

// Initialize Socket Service - MOVED TO TOP
const SessionManager = require('./session_manager');
const sessionManager = new SessionManager();

// Initialize Vision Service (Image/Video Analysis via AnythingLLM)
const VisionService = require('./vision_service');
const visionService = new VisionService(llmService);





// Initialize Model Metrics Service (Training Dashboard)

modelMetricsService.setMCPService(mcpService);
llmService.setModelMetricsService(modelMetricsService); // Connect for AnythingLLM metrics tracking
console.log('[SYSTEM] Model Metrics Service initialized (5s refresh, hourly benchmarks)');

// Initialize Training Commentary Service (LLM real-time analysis)
const TrainingCommentaryService = require('./training_commentary_service');
const trainingCommentaryService = new TrainingCommentaryService();
console.log('[SYSTEM] Training Commentary Service initialized (Mistral, FR, email archive)');

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
// Project Management Routes
const projectRoutes = require('./routes/projects');
app.use('/api/projects', projectRoutes);

// Cloud Optimizer - runs every 1 hour (reduced from 30 min)
cloudModelOptimizer.startAutoOptimization(60);


console.log('[SYSTEM] Real Training Service initialized (Shodan + model training)');


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

        if (msg.includes('t�che') || msg.includes('todo')) {
            checks.push(Promise.all(ACCOUNTS.map(email => googleService.listTasks(email).catch(e => `Error: ${e.message}`)))
                .then(res => "\n\n[GOOGLE TASKS]\n" + res.map((r, i) => `--- Compte: ${ACCOUNTS[i]} ---\n${r}\n`).join('')));
        }

        if (msg.includes('drive') || msg.includes('fichiers')) {
            checks.push(Promise.all(ACCOUNTS.map(email => googleService.listDriveFiles(email).catch(e => `Error: ${e.message}`)))
                .then(res => "\n\n[GOOGLE DRIVE (R�cents)]\n" + res.map((r, i) => `--- Compte: ${ACCOUNTS[i]} ---\n${r}\n`).join('')));
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
// Note: /patterns and /models are now defined BEFORE auth middleware (PUBLIC routes)


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
// NOTE: Google Auth Routes moved to PUBLIC section (before authMiddleware) - lines 110-290
// This prevents duplicate route handlers and ensures OAuth callback works properly

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

// Astrometry.net Routes
const astrometryRoutes = require('./astrometry_routes');
app.use('/api/astrometry', astrometryRoutes);
console.log('[SYSTEM] Astrometry Routes loaded (Plate Solving)');





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

        console.log('[INCIDENT] Vision analysis complete');

        // Step 2: Generate Quick Summary


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


        // Validate report quality


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

        console.log(`[INCIDENT] Complete workflow: ${mediaType} ? 5-Why`);

        // Step 1: Vision Analysis

        console.log('[INCIDENT] ? Vision analysis');

        // Step 2: Generate 5-Why

        console.log('[INCIDENT] ? 5-Why generated');

        // Step 3: Validate

        console.log(`[INCIDENT] ? Validation: ${validation.score}/100`);

        res.json({
            success: true,
            analysis: visionAnalysis,
            report: report,
            validation: validation,

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

        res.json({ success: true, message: "Correction m�moris�e. Je ne ferai plus cette erreur." });
    } catch (error) {
        console.error("Feedback error:", error);
        res.status(500).json({ error: error.message });
    }
});

// Settings Endpoints - MOVED TO PUBLIC ROUTES SECTION (before authMiddleware)

app.post('/chat', async (req, res) => {
    try {
        const { message, image, pattern, provider, model, sessionId } = req.body;
        const user = req.user;

        // PERMISSION CHECK: Model
        if (!userService.canUseModel(user, provider || 'local', model || '')) {
            return res.status(403).json({
                reply: `? ACC�S REFUS� : Votre niveau (${user.tier}) ne permet pas d'utiliser le mod�le ${model} (${provider}).`,
                error: "Insufficient Permissions"
            });
        }

        // PERMISSION CHECK: Fabric Pattern
        if (pattern && !userService.canUseTool(user, `fabric_basic`)) {
            return res.status(403).json({
                reply: `? ACC�S REFUS� : Votre niveau (${user.tier}) ne permet pas d'utiliser la biblioth�que Fabric.`,
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
            currentSession.messages = [{ role: "assistant", content: "M�moire effac�e. On repart � neuf." }];
            sessionManager.saveSession(currentSession.id, currentSession);
            return res.json({ reply: "M�moire effac�e.", sessionId: currentSession.id });
        }

        // Handle Ingest Command via Chat
        if (message.trim().toLowerCase() === '/ingest') {
            const vaultPath = process.env.OBSIDIAN_VAULT_PATH;
            if (!vaultPath) return res.json({ reply: "Erreur: OBSIDIAN_VAULT_PATH non configur�." });

            // Trigger async ingestion
            const count = await memoryService.ingestVault(vaultPath);
            return res.json({ reply: `Ingestion termin�e.J'ai dig�r� ${count} notes.` });
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
                    return res.json({ reply: "?? ATTENTION : Les tests de s�curit� ont �chou�. V�rifiez les logs avant de fermer." });
                }

                await llmService.unloadModel(model || "dolphin-mistral:7b");

                const byeResponse = `### SYST�ME TH3 THIRTY3

**PROTOCOLE DE SAUVEGARDE ACTIV�.**

Donn�es enregistr�es :
*   **Plan Global :** Phase 1 - Stabilisation Cashflow & Arr�t H�morragie.
*   **Objectif Actuel (LOCK) :** Logistique de d�ploiement & Ex�cution du shift de travail (Cible : 484$).
*   **Statut :** EN ATTENTE D'EX�CUTION.

Je coupe les processus cognitifs. Lib�re ta m�moire vive. Je garde la structure.

� ton retour, la premi�re chose que tu verras sera :
> **RAPPEL OBJECTIF :** Shift Travail termin� ?
> **STATUS :** [YES/NO]

**SERVER SHUTDOWN...**
**VRAM CLEARED.**
**GO.**`;

                return res.json({ reply: byeResponse });
            } catch (e) {
                console.error("Error unloading model:", e);
                return res.json({ reply: "Erreur lors de la d�connexion du cerveau. Check la console." });
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
            messageWithContext += `\n\n[MMOIRE LONG-TERME (RAG)]\nVoici des informations pertinentes tires de ta mmoire (notes ou conversations passes) :\n${memoryContext}\n[FIN MMOIRE]\n`;
            console.log(`[RAG] Injected ${memoryResults.length} memories.`);
        }

        // 1c. IMAGE ANALYSIS (Generic - if image provided)
        if (image) {
            console.log("[CHAT] 🖼️ Image detected - Generic analysis available");
            // Generic image analysis can be added here if needed
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
\n[MODE EXPERT ACTIV�]
1. **STYLE** : Fran�ais standard PROFESSIONNEL et TECHNIQUE.
2. **FORMAT** : R�ponse directe. Juste le r�sultat.
3. **TON** : Efficacit� maximale.
\n[PATTERN: ${pattern.toUpperCase()}]\n${getPatternContent(pattern)}`;
            } else {
                // MODE CHAT
                const styleProfile = styleService.analyzeHistory(chatHistory);
                const styleInstructions = styleService.generateStylePrompt(styleProfile);

                finalSystemPrompt += `
\n[MODE APPRENTISSAGE ACTIV�]
1. **OBJECTIF** : Analyse le style de l'utilisateur dans l'historique (vocabulaire, structure de phrase, jargon).
2. **ADAPTATION** : Imite son style. Deviens son miroir.
3. **�VOLUTION** : Plus tu parles avec lui, plus tu dois lui ressembler. Utilise ses expressions. Sois son extension num�rique.
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
            reply: "Erreur syst�me critique.",
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
const createCyberTrainingRoutes = require('./cyber_training_routes');
app.use('/api/cyber-training', requireTier('operator'), createCyberTrainingRoutes(llmService)); // PREMIUM+

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
    console.log('[SYSTEM] ?? OFFLINE MODE ACTIVATED - Using local agents');
});
offlineService.on('online', (data) => {
    console.log('[SYSTEM] ?? ONLINE MODE RESTORED - Cloud services available');
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
// HackerGPT Routes - Offensive Security Companion
const hackerGPTRoutes = require('./routes/hackergpt_routes');
app.use('/api/hackergpt', hackerGPTRoutes);
console.log('[HACKERGPT] Routes registered at /api/hackergpt');
console.log('[SYSTEM] Logs routes mounted at /api/logs (Internal Console)');


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

    // Automatic Tor Verification at Startup
    try {
        const torStartupCheck = require('./tor_startup_check');
        console.log('\n[SYSTEM] Running automatic Tor verification...');
        const torResult = await torStartupCheck.performStartupCheck();

        if (torResult.isTor) {
            console.log('[SYSTEM] ? Tor is ACTIVE and VERIFIED');
            console.log(`[SYSTEM] ?? Exit IP: ${torResult.ip}`);
        } else if (torResult.portOpen) {
            console.log('[SYSTEM] ?? Port 9050 active but NOT connected to Tor network');
            console.log('[SYSTEM] ?? This may be Tor Browser - for best results use standalone tor.exe');
        } else {
            console.log('[SYSTEM] ?? Tor not available - OSINT requests will use direct connection');
        }
    } catch (error) {
        console.log('[SYSTEM] ?? Tor check skipped:', error.message);
    }
});















