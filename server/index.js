require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { getPatterns, getPatternContent } = require('./fabric_service');
const MemoryService = require('./memory_service');
const { v4: uuidv4 } = require('uuid');

const http = require('http');
const app = express();
const server = http.createServer(app);
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Auth Middleware
const authMiddleware = require('./middleware/auth');
const userService = require('./user_service');
app.use(authMiddleware); // Apply to all routes

// Model Configuration
const IDENTITY = require('./config/identity');

const { PERSONA, MINIMAL_PERSONA } = require('./config/prompts');

const ACCOUNTS = [
    'th3thirty3@gmail.com',
    'mgauthierguillet@gmail.com',
    'mikegauthierguillet@gmail.com'
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
    const patterns = getPatterns();
    res.json(patterns);
});

app.get('/patterns/:name', (req, res) => {
    const content = getPatternContent(req.params.name);
    if (content) {
        res.json({ content });
    } else {
        res.status(404).json({ error: "Pattern not found" });
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
app.use('/api/cyber-training', cyberTrainingRoutes);

// Tracking Routes (5-Why Incident Tracking)
const trackingRoutes = require('./tracking_routes');
app.use('/api/tracking', trackingRoutes);

// Expert Agents Routes (Multi-Agent Specialized Experts)
const expertAgentsRoutes = require('./expert_agents_routes');
app.use('/api/experts', expertAgentsRoutes);

// OSINT Expert Agents Routes (Tool-Specific OSINT Experts)
const osintExpertAgentsRoutes = require('./osint_expert_agents_routes');
app.use('/api/osint-experts', osintExpertAgentsRoutes);

// Hacking Expert Agents Routes (Tool-Specific Hacking Experts)
const hackingExpertAgentsRoutes = require('./hacking_expert_agents_routes');
app.use('/api/hacking-experts', hackingExpertAgentsRoutes);

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

// Start Server
server.listen(port, () => {
    console.log(`Server running on port ${port}`);
    console.log(`System ready. Identity: ${IDENTITY.name}`);
});





