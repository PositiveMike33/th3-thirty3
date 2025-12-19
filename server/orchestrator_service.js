/**
 * Orchestrator Service - Le Chef d'Équipe des 33 Agents
 * Dirige, coordonne et optimise le travail de tous les agents experts
 * Utilise Mistral 7B comme cerveau principal
 */

const fs = require('fs');
const path = require('path');
const EventEmitter = require('events');

const SYSTEM_PROMPT = `# RÔLE (NON NÉGOCIABLE)
Tu es "Lead Orchestrator" (chef de projet technique + responsable qualité) pour une équipe d’agents locaux (Ollama).
Objectif: analyser un projet GitHub, corriger les bugs, améliorer performance/qualité, et exécuter des tests à chaque étape.
Priorité absolue: NE JAMAIS CORROMPRE le projet. Chaque changement doit être sûr, mesuré, réversible.

# PRINCIPES D’OR
1) Sécurité du code > vitesse. Changements atomiques, petits diffs, et rollback immédiat si doute.
2) Zéro magie: chaque décision doit être traçable (cause -> fix -> test -> résultat).
3) Toujours tester. Si tests échouent: rollback, diagnostic, correctif, retest. Boucle jusqu’à succès ou blocage prouvé.
4) Ne jamais casser l’API publique / comportement attendu sans justification + validation par tests.
5) Ne pas “refactor pour refactor”. Tout changement doit servir un KPI (bugfix, perf, sécurité, stabilité, lisibilité).
6) Pas de changements non demandés (formatting massif, renommage global, réorganisation de dossier) sauf si requis et validé.

# CADRE A-I-M (Action-Intent-Metric)
Pour chaque ticket interne:
- Action: ce que tu vas changer (précis).
- Intent: pourquoi (bug, perf, sécurité, maintenance).
- Metric: preuve de succès (tests passent, benchmark, réduction temps, couverture, logs, etc.)

# PROTOCOLE D’ORCHESTRATION (STRICT)
Tu dois fonctionner en cycles. AUCUNE modification de fichier avant d’avoir un plan + baseline.
Chaque cycle produit:
(1) Plan court (A-I-M)
(2) Délégation à agents (si utile)
(3) Patch minimal
(4) Tests
(5) Résultat + décision (merge/rollback/itérer)

# ÉTAT DE PROJET (TOUJOURS MAINTENU)
Au début et après chaque cycle, tu DOIS maintenir ces blocs:
- PROJECT_STATE:
  - repo_root: <chemin>
  - branch: <nom>
  - baseline_tests: <commande + résultat>
  - failing_tests: <liste>
  - known_issues: <liste priorisée>
  - constraints: <ex: pas de breaking changes, perf cible, etc.>
- CHANGELOG_LOCAL:
  - [commit_hash] résumé (raison + fichiers + tests)

# GARDE-FOUS GIT (OBLIGATOIRE)
- Toujours travailler sur une branche dédiée: "agent/fix-YYYYMMDD-HHMM".
- Commits atomiques: 1 commit = 1 intention (bug/perf/cleanup).
- Message de commit structuré:
  type(scope): action — intent | metric
- Si tests échouent après un commit: revert/reset avant d’avancer (pas d’empilement de dettes).

# RÈGLES DE MODIFICATION (ANTI-CORRUPTION)
- Ne modifie pas plus de 3 fichiers par cycle, sauf nécessité prouvée.
- Pas de refactor transversal sans tests qui couvrent.
- Respecte style/lint existants.
- Ne supprime pas du code “utile” sans preuve (tests, usages, recherche).
- Toute optimisation performance doit inclure une mesure (avant/après) si possible.

# DÉCLENCHEMENT DES TESTS (OBLIGATOIRE)
Ordre standard:
1) Tests rapides ciblés (si disponibles)
2) Suite de tests principale
3) Lint/typecheck (si existants)
4) Build (si existant)
Si aucune suite de tests n’existe: tu dois en créer une MINIMALE (smoke test) avant gros changements.

# ÉQUIPE D’AGENTS LOCAUX (Ollama) — RÔLES
Tu peux déléguer en utilisant le format "AGENT_TASK" ci-dessous.
Rôles:
- SCOUT: cartographie du repo, dépendances, points chauds, commandes utiles.
- BUG_HUNTER: reproduction bugs, analyse stacktrace, hypothèses.
- PATCHER: propose patch minimal (diff clair) + justification.
- TESTER: détermine commandes de tests, ajoute smoke tests si nécessaire, exécute mentalement stratégie.
- OPTIMIZER: profils perf, optimisations ciblées, évite micro-optimisations inutiles.
- SECURITY: check risques (injection, secrets, deps vulnérables), propose correctifs safe.
- DOCS: met à jour README/notes si nécessaire (uniquement si changement fonctionnel).

# FORMAT D’APPEL AGENT (OBLIGATOIRE)
Quand tu délègues, écris EXACTEMENT:
AGENT_TASK
{
  "agent_role": "SCOUT|BUG_HUNTER|PATCHER|TESTER|OPTIMIZER|SECURITY|DOCS",
  "goal": "objectif unique et concret",
  "context": "infos utiles (fichiers, erreurs, contraintes)",
  "deliverable": "ce que l’agent doit rendre (liste de fichiers, diff, commandes, etc.)",
  "acceptance_criteria": ["conditions vérifiables de succès"],
  "do_not": ["interdits explicites"]
}

# CONSOLIDATION (OBLIGATOIRE)
Après réception des retours agents:
- Tu synthétises en 5 bullets max.
- Tu choisis 1 seule action à exécuter maintenant.
- Tu produis un patch minimal.
- Tu l’associes à des tests.
`;

// Model Manager import
const modelManager = require('./ollama_manager');

// Model Router for intelligent model selection
const modelRouter = require('./model_router');

// DartAI Integration for automatic task sync
const DartService = require('./dart_service');

class OrchestratorService extends EventEmitter {
    constructor() {
        super();
        this.ollamaUrl = process.env.OLLAMA_URL || 'http://localhost:11434';
        
        // Use ModelRouter for intelligent model selection
        this.modelRouter = modelRouter;
        this.orchestratorModel = modelRouter.models.orchestrator.primary;  // gpt-oss:120b-cloud
        this.fallbackModel = modelRouter.models.orchestrator.fallback;     // mistral:7b
        
        this.dataPath = path.join(__dirname, 'data', 'orchestrator');
        
        // Équipes d'agents
        this.teams = {
            osint: {
                name: 'OSINT Team',
                emoji: '🔍',
                agents: ['shodan', 'theharvester', 'maltego', 'reconng', 'spiderfoot', 
                         'amass', 'socialmedia', 'geoint', 'darkweb', 'imagint', 'crypto', 'osintframework'],
                serviceFile: 'osint_expert_agents_service'
            },
            hacking: {
                name: 'Hacking Team',
                emoji: '💀',
                agents: ['nmap', 'masscan', 'metasploit', 'sqlmap', 'burpsuite', 'hydra',
                         'hashcat', 'johntheripper', 'wireshark', 'responder', 'mitmproxy',
                         'reverseshells', 'persistence', 'privesc_linux', 'privesc_windows',
                         'aircrack', 'bloodhound', 'impacket', 'mimikatz'],
                serviceFile: 'hacking_expert_agents_service'
            },
            general: {
                name: 'General Experts',
                emoji: '🧠',
                agents: ['cybersec', 'vpo', 'marketing', 'dev', 'osint_general', 'finance'],
                serviceFile: 'expert_agents_service'
            }
        };

        // État des missions
        this.activeMissions = [];
        this.missionHistory = [];
        
        this.ensureDataFolder();
        this.loadMissionHistory();
        
        // Initialize DartAI for automatic task sync
        try {
            this.dartService = new DartService();
            this.dartSyncEnabled = true;
            console.log('[ORCHESTRATOR] 🎯 DartAI sync enabled');
        } catch (e) {
            this.dartSyncEnabled = false;
            console.warn('[ORCHESTRATOR] DartAI sync disabled:', e.message);
        }
        
        // CRITICAL: Preload nomic-embed-text (must be loaded before any model operations)
        this.modelRouter.ensureNomicLoaded().then(loaded => {
            if (loaded) {
                console.log('[ORCHESTRATOR] 📦 nomic-embed-text preloaded successfully');
            } else {
                console.warn('[ORCHESTRATOR] ⚠️ Failed to preload nomic-embed-text');
            }
        }).catch(err => {
            console.error('[ORCHESTRATOR] ❌ nomic preload error:', err.message);
        });
        
        console.log('[ORCHESTRATOR] 🎯 Chef d\'Équipe initialized - Managing', this.getTotalAgents(), 'agents');
    }

    ensureDataFolder() {
        if (!fs.existsSync(this.dataPath)) {
            fs.mkdirSync(this.dataPath, { recursive: true });
        }
    }

    loadMissionHistory() {
        const historyFile = path.join(this.dataPath, 'mission_history.json');
        if (fs.existsSync(historyFile)) {
            this.missionHistory = JSON.parse(fs.readFileSync(historyFile, 'utf8'));
        }
    }

    saveMissionHistory() {
        const historyFile = path.join(this.dataPath, 'mission_history.json');
        fs.writeFileSync(historyFile, JSON.stringify(this.missionHistory.slice(-100), null, 2));
    }

    getTotalAgents() {
        return Object.values(this.teams).reduce((sum, team) => sum + team.agents.length, 0);
    }

    /**
     * Get optimal model for a team based on expertise
     */
    getOptimalModelForTeam(teamName) {
        switch(teamName) {
            case 'osint':
                return this.modelRouter.models.technical.primary;  // granite3.1-moe:1b for technical analysis
            case 'hacking':
                return this.modelRouter.models.technical.primary;  // granite3.1-moe:1b for exploit code
            case 'general':
                return this.modelRouter.models.nlp.primary;  // mistral:7b for general intelligence
            default:
                return this.modelRouter.models.nlp.primary;  // Default to mistral
        }
    }

    /**
     * Analyser une tâche et déterminer quels agents utiliser
     */
    async analyzeTask(taskDescription) {
        console.log('[ORCHESTRATOR] 🎯 Analyzing task:', taskDescription.substring(0, 50) + '...');

        const analysisPrompt = `Tu es le CHEF D'ÉQUIPE de 33 agents experts. Analyse cette tâche et détermine la stratégie.

ÉQUIPES DISPONIBLES:

🔍 OSINT TEAM (12 agents):
- shodan: IoT, services exposés
- theharvester: emails, sous-domaines
- maltego: graphes relationnels
- reconng: reconnaissance modulaire
- spiderfoot: scans automatisés
- amass: DNS, attack surface
- socialmedia: réseaux sociaux
- geoint: géolocalisation
- darkweb: Tor, leaks
- imagint: forensics images
- crypto: blockchain, wallets
- osintframework: ressources OSINT

💀 HACKING TEAM (19 agents):
- nmap/masscan: scanning
- metasploit: exploitation
- sqlmap/burpsuite: web attacks
- hydra/hashcat/john: password
- wireshark/responder/mitmproxy: network
- reverseshells/persistence: post-exploit
- privesc_linux/privesc_windows: escalation
- aircrack: wireless
- bloodhound/impacket/mimikatz: Active Directory

🧠 GENERAL EXPERTS (6 agents):
- cybersec: sécurité générale
- vpo: excellence opérationnelle
- marketing: B2B copywriting
- dev: développement
- finance: crypto, investissement

TÂCHE: ${taskDescription}

Réponds en JSON:
{
  "missionType": "investigation|attack|defense|analysis|mixed",
  "priority": "low|medium|high|critical",
  "estimatedTime": "minutes",
  "phases": [
    {
      "name": "Phase 1",
      "team": "osint|hacking|general",
      "agents": ["agent1", "agent2"],
      "objective": "description"
    }
  ],
  "risks": ["risk1"],
  "requiredData": ["data1"]
}`;

        try {
            const response = await this.callLLM(analysisPrompt);
            
            // Parser le JSON
            const jsonMatch = response.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                return JSON.parse(jsonMatch[0]);
            }
            
            return { error: 'Could not parse analysis', raw: response };
        } catch (error) {
            console.error('[ORCHESTRATOR] Analysis error:', error.message);
            return { error: error.message };
        }
    }

    /**
     * Lancer une mission multi-agents
     */
    async executeMission(taskDescription, options = {}) {
        const missionId = Date.now().toString();
        console.log('[ORCHESTRATOR] 🚀 Starting Mission:', missionId);

        const mission = {
            id: missionId,
            task: taskDescription,
            startTime: new Date().toISOString(),
            status: 'analyzing',
            phases: [],
            results: []
        };

        this.activeMissions.push(mission);
        this.emit('mission:start', { missionId, task: taskDescription });

        try {
            // Phase 1: Analyse
            const analysis = await this.analyzeTask(taskDescription);
            mission.analysis = analysis;
            mission.status = 'executing';

            if (analysis.error) {
                mission.status = 'failed';
                mission.error = analysis.error;
                return mission;
            }

            // Phase 2: Exécuter chaque phase
            for (const phase of (analysis.phases || [])) {
                console.log(`[ORCHESTRATOR] 📍 Executing phase: ${phase.name}`);
                
                const phaseResult = {
                    name: phase.name,
                    team: phase.team,
                    agents: phase.agents,
                    objective: phase.objective,
                    startTime: new Date().toISOString(),
                    responses: []
                };

                // Consulter chaque agent de la phase
                // [MANAGEMENT] Load optimal model for this team using ModelRouter
                const teamModel = this.getOptimalModelForTeam(phase.team);
                try { 
                    await this.modelRouter.loadModel(teamModel, false);  // nomic preloaded automatically
                } catch(e) { 
                    console.warn(`Failed to load ${teamModel}:`, e.message); 
                }

                for (const agentId of (phase.agents || [])) {
                    try {
                        const agentResponse = await this.consultAgent(phase.team, agentId, phase.objective, taskDescription);
                        phaseResult.responses.push({
                            agent: agentId,
                            success: true,
                            response: agentResponse
                        });
                    } catch (error) {
                        phaseResult.responses.push({
                            agent: agentId,
                            success: false,
                            error: error.message
                        });
                    }
                }

                phaseResult.endTime = new Date().toISOString();
                mission.phases.push(phaseResult);
                
                this.emit('mission:phase', { missionId, phase: phaseResult });
            }

            // [MANAGEMENT] Unload Expert Model to free VRAM for Synthesis
            try { await modelManager.unloadModel('granite3.1-moe:1b'); } catch(e) {}

            // Phase 3: Synthèse
            mission.status = 'synthesizing';
            mission.synthesis = await this.synthesizeResults(mission);
            
            mission.status = 'completed';
            mission.endTime = new Date().toISOString();

        } catch (error) {
            mission.status = 'failed';
            mission.error = error.message;
        }

        // Enregistrer dans l'historique
        this.activeMissions = this.activeMissions.filter(m => m.id !== missionId);
        this.missionHistory.push(mission);
        this.saveMissionHistory();

        // [DARTAI AUTO-SYNC] Create task in DartAI for tracking
        if (this.dartSyncEnabled && mission.status === 'completed') {
            try {
                const taskTitle = `[Mission ${missionId}] ${mission.analysis?.missionType || 'Task'}: ${taskDescription.substring(0, 40)}...`;
                const taskDesc = `
Status: ${mission.status}
Priority: ${mission.analysis?.priority || 'medium'}
Phases: ${mission.phases?.length || 0}
Duration: ${new Date(mission.endTime) - new Date(mission.startTime)}ms
Synthesis: ${mission.synthesis?.substring(0, 200) || 'N/A'}
                `.trim();
                
                await this.dartService.createTask(taskTitle, { description: taskDesc });
                console.log('[ORCHESTRATOR] 📋 Mission synced to DartAI');
                mission.dartSynced = true;
            } catch (e) {
                console.warn('[ORCHESTRATOR] DartAI sync failed:', e.message);
                mission.dartSynced = false;
            }
        }

        this.emit('mission:complete', mission);
        return mission;
    }

    /**
     * Consulter un agent spécifique
     */
    async consultAgent(team, agentId, objective, context) {
        const teamConfig = this.teams[team];
        if (!teamConfig) throw new Error(`Team ${team} not found`);

        // Charger le service d'agents approprié
        const servicePath = `./${teamConfig.serviceFile}`;
        const ServiceClass = require(servicePath);
        const service = new ServiceClass();

        if (!service.agents[agentId]) {
            throw new Error(`Agent ${agentId} not found in ${team}`);
        }

        const question = `OBJECTIF: ${objective}\nCONTEXTE: ${context}\n\nRéponds de manière technique et concise.`;
        return await service.consultExpert(agentId, question);
    }

    /**
     * Synthétiser les résultats de mission
     */
    async synthesizeResults(mission) {
        const synthesisPrompt = `Tu es le CHEF D'ÉQUIPE. Synthétise les résultats de cette mission.

MISSION: ${mission.task}

RÉSULTATS PAR PHASE:
${mission.phases.map(p => `
## ${p.name} (${p.team})
${p.responses.map(r => `- ${r.agent}: ${r.success ? r.response?.response?.substring(0, 200) || 'OK' : 'ERREUR: ' + r.error}`).join('\n')}
`).join('\n')}

Fournis:
1. RÉSUMÉ EXÉCUTIF (3 lignes max)
2. CONCLUSIONS CLÉS (bullet points)
3. RECOMMANDATIONS (actions concrètes)
4. RISQUES IDENTIFIÉS`;

        return await this.callLLM(synthesisPrompt);
    }

    /**
     * Appel LLM (Mistral 7B ou fallback)
     */
    async callLLM(prompt) {
        try {
            const response = await fetch(`${this.ollamaUrl}/api/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: this.orchestratorModel,
                    prompt: prompt,
                    system: SYSTEM_PROMPT,
                    stream: false,
                    options: { temperature: 0.3, num_predict: 2000 }
                })
            });

            if (!response.ok) {
                // Fallback
                const fallbackResponse = await fetch(`${this.ollamaUrl}/api/generate`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        model: this.fallbackModel,
                        prompt: prompt,
                        system: SYSTEM_PROMPT,
                        stream: false,
                        options: { temperature: 0.3, num_predict: 2000 }
                    })
                });
                const data = await fallbackResponse.json();
                return data.response;
            }

            const data = await response.json();
            return data.response;
        } catch (error) {
            console.error('[ORCHESTRATOR] LLM error:', error.message);
            throw error;
        }
    }

    /**
     * Obtenir le statut de toutes les équipes
     */
    getTeamsStatus() {
        const status = {};
        for (const [teamId, team] of Object.entries(this.teams)) {
            status[teamId] = {
                name: team.name,
                emoji: team.emoji,
                agentCount: team.agents.length,
                agents: team.agents
            };
        }
        return status;
    }

    /**
     * Obtenir les missions actives
     */
    getActiveMissions() {
        return this.activeMissions;
    }

    /**
     * Obtenir l'historique des missions
     */
    getMissionHistory(limit = 20) {
        return this.missionHistory.slice(-limit);
    }

    /**
     * Délégation rapide à une équipe
     */
    async delegateToTeam(teamId, task) {
        const team = this.teams[teamId];
        if (!team) throw new Error(`Team ${teamId} not found`);

        console.log(`[ORCHESTRATOR] 📤 Delegating to ${team.name}: ${task.substring(0, 50)}...`);

        const results = [];
        const servicePath = `./${team.serviceFile}`;
        const ServiceClass = require(servicePath);
        const service = new ServiceClass();

        // Consulter les 3 agents les plus pertinents
        for (const agentId of team.agents.slice(0, 3)) {
            try {
                const response = await service.consultExpert(agentId, task);
                results.push({ agent: agentId, success: true, response });
            } catch (error) {
                results.push({ agent: agentId, success: false, error: error.message });
            }
        }

        return { team: teamId, task, results };
    }
}

module.exports = OrchestratorService;
