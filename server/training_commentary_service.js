/**
 * training_commentary_service.js
 * Service de commentaires LLM en temps réel pour le training des agents
 *
 * AMÉLIORATIONS v2:
 * - Chaque modèle génère des commentaires sur SON PROPRE apprentissage
 * - Auto-détection de tous les modèles Ollama (pas de liste fixe)
 * - Commentaires plus fréquents et personnalisés
 */

const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');

// Paths
const ARCHIVE_PATH = path.join(__dirname, 'data', 'training_archive.json');
const METRICS_PATH = path.join(__dirname, 'data', 'model_metrics.json');

// Email config
const EMAIL = process.env.NOTIFICATION_EMAIL || 'mikegauthierguillet@gmail.com';
const SMTP_USER = process.env.EMAIL_USER;
const SMTP_PASS = process.env.EMAIL_APP_PASSWORD;

class TrainingCommentaryService {
    constructor(llmService = null) {
        this.archive = this.loadArchive();
        this.lastCommentaryByModel = {};  // Track last commentary time per model
        this.cachedModels = [];           // Cached list of available models
        this.lastModelRefresh = 0;        // Last time we refreshed model list
        this.llmService = llmService;     // LLM Service for Gemini/NotebookLM integration
        this.useGemini = true;            // Use Gemini (NotebookLM) by default
        
        console.log(`[COMMENTARY] Service initialized (Gemini: ${this.useGemini ? 'enabled' : 'disabled'})`);
    }

    /**
     * Load archive from disk
     */
    loadArchive() {
        try {
            if (fs.existsSync(ARCHIVE_PATH)) {
                return JSON.parse(fs.readFileSync(ARCHIVE_PATH, 'utf8'));
            }
        } catch (error) {
            console.error('[COMMENTARY] Failed to load archive:', error.message);
        }
        return { entries: [], totalEntries: 0, lastUpdated: null };
    }

    /**
     * Save archive to disk
     */
    saveArchive() {
        try {
            const dir = path.dirname(ARCHIVE_PATH);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
            this.archive.lastUpdated = new Date().toISOString();
            fs.writeFileSync(ARCHIVE_PATH, JSON.stringify(this.archive, null, 2));
        } catch (error) {
            console.error('[COMMENTARY] Failed to save archive:', error.message);
        }
    }

    /**
     * Get ALL available Ollama models (auto-refresh every 5 min)
     */
    async getAvailableModels() {
        const now = Date.now();
        if (now - this.lastModelRefresh > 5 * 60 * 1000 || this.cachedModels.length === 0) {
            try {
                const response = await fetch('http://localhost:11434/api/tags');
                const data = await response.json();
                this.cachedModels = (data.models || [])
                    .map(m => m.name)
                    .filter(n => !n.includes('embed'));  // Exclude embedding models
                this.lastModelRefresh = now;
                console.log(`[COMMENTARY] Refreshed model list: ${this.cachedModels.join(', ')}`);
            } catch (error) {
                console.error('[COMMENTARY] Failed to get models:', error.message);
            }
        }
        return this.cachedModels;
    }

    /**
     * Generate SELF-COMMENTARY using Gemini/NotebookLM
     * @param {string} modelName - The model being analyzed
     * @param {Object} metrics - Current training metrics
     */
    async generateSelfCommentary(modelName, metrics) {
        try {
            const modelMetrics = metrics[modelName];
            if (!modelMetrics) {
                console.log(`[COMMENTARY] No metrics found for ${modelName}`);
                return null;
            }

            // Build self-reflection prompt
            const prompt = this.buildSelfReflectionPrompt(modelName, modelMetrics);
            
            let commentary = 'Je continue mon apprentissage...';
            
            // Use Gemini (NotebookLM) if enabled and LLM service available
            if (this.useGemini && this.llmService) {
                console.log(`[COMMENTARY] 📓 Gemini/NotebookLM analyzing ${modelName}...`);
                
                try {
                    commentary = await this.llmService.generateResponse(
                        prompt,
                        null,
                        'gemini',
                        'gemini-2.0-flash-exp',
                        'Tu es un expert pédagogue qui analyse les progrès des modèles IA. Réponds en français.'
                    );
                } catch (geminiError) {
                    console.error(`[COMMENTARY] Gemini failed, falling back to local:`, geminiError.message);
                    // Fallback to local model
                    commentary = await this.generateLocalCommentary(modelName, prompt);
                }
            } else {
                // Use local Ollama model
                console.log(`[COMMENTARY] ${modelName} generating self-reflection (local)...`);
                commentary = await this.generateLocalCommentary(modelName, prompt);
            }
            
            // Create entry
            const entry = {
                id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
                timestamp: new Date().toISOString(),
                modelName: modelName,
                type: 'self_reflection',
                source: this.useGemini ? 'gemini/notebooklm' : 'local',
                commentary: commentary.trim(),
                score: modelMetrics?.cognitive?.overallScore || 50,
                expertise: modelMetrics?.expertise || null,
                performance: {
                    totalQueries: modelMetrics?.performance?.totalQueries || 0,
                    avgResponseTime: modelMetrics?.performance?.avgResponseTime || 0,
                    sessionsCompleted: modelMetrics?.learning?.sessionsCompleted || 0
                }
            };
            
            // Archive
            this.archive.entries.push(entry);
            this.archive.totalEntries++;
            
            // Keep only last 200 entries in memory
            if (this.archive.entries.length > 200) {
                this.archive.entries = this.archive.entries.slice(-200);
            }
            
            // Update last commentary time for this model
            this.lastCommentaryByModel[modelName] = Date.now();
            
            this.saveArchive();
            
            const sourceLabel = this.useGemini ? '📓 NotebookLM' : '🤖 Local';
            console.log(`[COMMENTARY] ✅ ${modelName} reflection complete via ${sourceLabel} (Score: ${entry.score})`);
            
            return entry;
            
        } catch (error) {
            console.error(`[COMMENTARY] Self-commentary error for ${modelName}:`, error.message);
            return null;
        }
    }

    /**
     * Generate commentary using local Ollama model
     */
    async generateLocalCommentary(modelName, prompt) {
        try {
            const response = await fetch('http://localhost:11434/api/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: modelName,
                    prompt: prompt,
                    stream: false,
                    options: {
                        temperature: 0.8,
                        num_predict: 400
                    }
                })
            });
            
            if (!response.ok) {
                throw new Error(`Ollama HTTP ${response.status}`);
            }
            
            const data = await response.json();
            return data.response || 'Apprentissage en cours...';
        } catch (error) {
            console.error(`[COMMENTARY] Local generation error:`, error.message);
            return 'Réflexion en cours...';
        }
    }

    /**
     * Build self-reflection prompt - model analyzes its OWN learning
     */
    buildSelfReflectionPrompt(modelName, modelMetrics) {
        const score = modelMetrics?.cognitive?.overallScore || 50;
        const queries = modelMetrics?.performance?.totalQueries || 0;
        const sessions = modelMetrics?.learning?.sessionsCompleted || 0;
        const growth = modelMetrics?.learning?.growthPercentage || 0;
        const strengths = modelMetrics?.strengths?.map(s => s.label).join(', ') || 'en développement';
        const weaknesses = modelMetrics?.weaknesses?.map(s => s.label).join(', ') || 'à identifier';
        const avgTime = Math.round(modelMetrics?.performance?.avgResponseTime || 0);
        
        // Get expertise breakdown
        const expertise = modelMetrics?.expertise || {};
        const expertiseStr = Object.entries(expertise)
            .filter(([k, v]) => typeof v === 'object' && v.score)
            .map(([k, v]) => `${k}: ${Math.round(v.score)}`)
            .join(', ');

        // Identify weakest areas for suggestions
        const weakAreas = Object.entries(expertise)
            .filter(([k, v]) => typeof v === 'object' && v.score)
            .sort((a, b) => a[1].score - b[1].score)
            .slice(0, 3)
            .map(([k]) => k);

        return `Tu es ${modelName}, un modèle d'intelligence artificielle en cours d'entraînement dans le système Th3 Thirty3 pour la psychologie sociale.

=== TES STATISTIQUES ACTUELLES ===
- Score cognitif global: ${score}/100
- Requêtes traitées: ${queries}
- Sessions de training: ${sessions}
- Croissance: ${growth > 0 ? '+' : ''}${growth.toFixed(1)}%
- Temps de réponse moyen: ${avgTime}ms
- Forces: ${strengths}
- Axes d'amélioration: ${weaknesses}
- Expertise détaillée: ${expertiseStr}
- Domaines les plus faibles: ${weakAreas.join(', ')}

=== TA MISSION ===
Génère une réponse structurée avec:

**1. ÉVOLUTION** (2-3 phrases)
Commente TON propre apprentissage, tes progrès récents, ce que tu as appris.

**2. SUGGESTIONS DE DONNÉES** (3-5 suggestions)
Propose des types de données/contenus que l'utilisateur pourrait te fournir pour améliorer tes performances dans tes domaines faibles. Sois spécifique:
- Type de contenu (articles, conversations, exemples, cas pratiques...)
- Thème précis (psychologie sociale, analyse comportementale, etc.)
- Format suggéré (texte, Q&A, scénarios...)

Parle à la première personne. Utilise ce format exact:

**Mon évolution:**
[Ton commentaire ici]

**Mes suggestions de données pour progresser:**
1. [Suggestion 1 - type, thème, format]
2. [Suggestion 2 - type, thème, format]
3. [Suggestion 3 - type, thème, format]

Réponse:`;
    }

    /**
     * Legacy method: Generate commentary (kept for compatibility)
     */
    async generateCommentary(metrics, modelBeingTrained = null) {
        if (modelBeingTrained) {
            return await this.generateSelfCommentary(modelBeingTrained, metrics);
        }
        return await this.triggerAutoCommentary();
    }

    /**
     * Trigger automatic self-commentary for ALL models
     */
    async triggerAutoCommentary() {
        try {
            const metrics = this.loadMetrics();
            if (!metrics || Object.keys(metrics).length === 0) {
                console.log('[COMMENTARY] No metrics available for auto-commentary');
                return null;
            }
            
            // Get all available models
            const availableModels = await this.getAvailableModels();
            const results = [];
            
            for (const modelName of availableModels) {
                // Check if model has metrics
                if (!metrics[modelName]) {
                    console.log(`[COMMENTARY] Skipping ${modelName} - no metrics yet`);
                    continue;
                }
                
                // Check cooldown (min 2 minutes between commentaries per model)
                const lastTime = this.lastCommentaryByModel[modelName] || 0;
                if (Date.now() - lastTime < 2 * 60 * 1000) {
                    console.log(`[COMMENTARY] Skipping ${modelName} - cooldown`);
                    continue;
                }
                
                const result = await this.generateSelfCommentary(modelName, metrics);
                if (result) {
                    results.push(result);
                }
                
                // Small delay between models
                await new Promise(r => setTimeout(r, 1000));
            }
            
            return results.length > 0 ? results : null;
            
        } catch (error) {
            console.error('[COMMENTARY] Auto trigger error:', error.message);
            return null;
        }
    }

    /**
     * Load current metrics
     */
    loadMetrics() {
        try {
            if (fs.existsSync(METRICS_PATH)) {
                return JSON.parse(fs.readFileSync(METRICS_PATH, 'utf8'));
            }
        } catch (error) {
            console.error('[COMMENTARY] Failed to load metrics:', error.message);
        }
        return {};
    }

    /**
     * Get recent commentaries
     */
    getRecentCommentaries(limit = 10) {
        return this.archive.entries.slice(-limit);
    }

    /**
     * Get commentaries for a specific model
     */
    getModelCommentaries(modelName, limit = 10) {
        return this.archive.entries
            .filter(e => e.modelName === modelName)
            .slice(-limit);
    }

    /**
     * Get last commentary
     */
    getLastCommentary() {
        return this.archive.entries[this.archive.entries.length - 1] || null;
    }

    /**
     * Get status for dashboard
     */
    getStatus() {
        return {
            totalEntries: this.archive.totalEntries,
            recentCount: this.archive.entries.length,
            lastUpdated: this.archive.lastUpdated,
            modelsCached: this.cachedModels,
            lastCommentaryByModel: this.lastCommentaryByModel
        };
    }

    /**
     * Send email archive (weekly digest)
     */
    async sendEmailDigest() {
        if (!SMTP_USER || !SMTP_PASS) {
            console.warn('[COMMENTARY] Email not configured (missing EMAIL_USER/EMAIL_APP_PASSWORD)');
            return false;
        }
        
        try {
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: SMTP_USER,
                    pass: SMTP_PASS
                }
            });
            
            const entries = this.archive.entries.slice(-20);
            const htmlContent = this.buildEmailHTML(entries);
            
            await transporter.sendMail({
                from: SMTP_USER,
                to: EMAIL,
                subject: `[Th3 Thirty3] Training Digest - ${new Date().toLocaleDateString('fr-CA')}`,
                html: htmlContent
            });
            
            console.log('[COMMENTARY]  Email digest sent');
            return true;
            
        } catch (error) {
            console.error('[COMMENTARY] Email error:', error.message);
            return false;
        }
    }

    /**
     * Build HTML email content
     */
    buildEmailHTML(entries) {
        const entriesHTML = entries.map(entry => `
            <div style="border-left: 3px solid #00ff88; padding: 10px; margin: 10px 0; background: #1a1a2e;">
                <p style="color: #888; font-size: 12px; margin: 0;">
                    ${new Date(entry.timestamp).toLocaleString('fr-CA')} | 
                    <strong style="color: #00ff88;">${entry.modelName}</strong>
                    ${entry.score ? ` | Score: ${entry.score}/100` : ''}
                </p>
                <p style="color: #fff; margin: 8px 0; font-style: italic;">"${entry.commentary}"</p>
            </div>
        `).join('');
        
        return `
            <div style="font-family: 'Courier New', monospace; background: #0d0d1a; color: #fff; padding: 20px;">
                <h1 style="color: #00ff88; border-bottom: 2px solid #00ff88; padding-bottom: 10px;">
                     Th3 Thirty3 Training Digest
                </h1>
                <p>Auto-réflexions des modèles IA en entraînement</p>
                <p>Entrées: ${entries.length} | Total historique: ${this.archive.totalEntries}</p>
                ${entriesHTML}
            </div>
        `;
    }
}

module.exports = TrainingCommentaryService;

