/**
 * Orchestrator Service - Le Chef d'Équipe des 33 Agents
 * Dirige, coordonne et optimise le travail de tous les agents experts
 * Utilise LLM Cloud comme cerveau principal
 */

const fs = require('fs');
const path = require('path');
const EventEmitter = require('events');
const LLMService = require('./llm_service');

// DartAI Integration for automatic task sync
const DartService = require('./dart_service');

const SYSTEM_PROMPT = `# RÔLE (NON NÉGOCIABLE)
Tu es "Lead Orchestrator" (chef de projet technique + responsable qualité) pour une équipe d’agents experts.
Objectif: analyser un projet, coordonner les experts, corriger les bugs, améliorer performance/qualité.
Priorité absolue: NE JAMAIS CORROMPRE le projet. Chaque changement doit être sûr, mesuré, réversible.

# PRINCIPES D’OR
1) Sécurité du code > vitesse. Changements atomiques, petits diffs, et rollback immédiat si doute.
2) Zéro magie: chaque décision doit être traçable (cause -> fix -> test -> résultat).
3) Toujours tester. Si tests échouent: rollback, diagnostic, correctif, retest.
4) Ne jamais casser l’API publique / comportement attendu sans justification + validation par tests.

# PROTOCOLE D’ORCHESTRATION
1) Plan court (A-I-M: Action-Intent-Metric)
2) Délégation à agents (si utile)
3) Synthèse et exécution

# ÉQUIPES D’AGENTS DISPONIBLES
- HEXSTRIKE TEAM (35 agents): Experts sécurité par outil - ÉQUIPE PRIORITAIRE
- OSINT TEAM (10 agents): Reconnaissance, Shodan, Social Media...
- HACKING TEAM (11 agents): PrivEsc, Persistence, Advanced Attacks...
- GENERAL EXPERTS (6 agents): CyberSec, Dev, Marketing...
`;

class OrchestratorService extends EventEmitter {
    constructor() {
        super();
        this.llmService = new LLMService();
        this.model = 'gemini-3-pro-preview';

        this.dataPath = path.join(__dirname, 'data', 'orchestrator');

        // Équipes d'agents
        this.teams = {
            hexstrike: {
                name: 'HexStrike Security Team',
                emoji: '🔥',
                agents: [
                    'nmap', 'masscan', 'rustscan', 'amass', 'subfinder',
                    'httpx', 'katana', 'gau', 'waybackurls',
                    'gobuster', 'feroxbuster', 'ffuf', 'dirsearch',
                    'arjun', 'paramspider', 'x8',
                    'nuclei', 'nikto', 'jaeles', 'dalfox',
                    'sqlmap', 'metasploit', 'hydra', 'john', 'hashcat',
                    'wireshark', 'tcpdump', 'sherlock', 'theharvester',
                    'prowler', 'trivy', 'ghidra', 'radare2', 'checksec', 'cipherlink'
                ],
                serviceFile: 'hexstrike_expert_agents_service',
                priority: 1
            },
            osint: {
                name: 'OSINT Team',
                emoji: '🔍',
                agents: ['shodan', 'maltego', 'reconng', 'spiderfoot',
                    'socialmedia', 'geoint', 'darkweb', 'imagint', 'crypto', 'osintframework'],
                serviceFile: 'osint_expert_agents_service',
                priority: 2
            },
            hacking: {
                name: 'Hacking Team',
                emoji: '💀',
                agents: ['mitmproxy', 'reverseshells', 'persistence',
                    'privesc_linux', 'privesc_windows', 'aircrack',
                    'bloodhound', 'impacket', 'mimikatz', 'responder', 'burpsuite'],
                serviceFile: 'hacking_expert_agents_service',
                priority: 2
            },
            general: {
                name: 'General Experts',
                emoji: '🧠',
                agents: ['cybersec', 'vpo', 'marketing', 'dev', 'osint_general', 'finance'],
                serviceFile: 'expert_agents_service',
                priority: 3
            }
        };

        // Initialize HexStrike Expert Service
        try {
            const HexStrikeExpertAgentsService = require('./hexstrike_expert_agents_service');
            this.hexstrikeExperts = new HexStrikeExpertAgentsService();
            console.log('[ORCHESTRATOR] 🔥 HexStrike Experts:', this.hexstrikeExperts.agents.size, 'tools');
        } catch (e) {
            this.hexstrikeExperts = null;
        }

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

        console.log('[ORCHESTRATOR] 🎯 Cloud Orchestrator initialized - Managing', this.getTotalAgents(), 'agents');
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
     * Analyser une tâche et déterminer quels agents utiliser
     */
    async analyzeTask(taskDescription) {
        console.log('[ORCHESTRATOR] 🎯 Analyzing task:', taskDescription.substring(0, 50) + '...');

        const analysisPrompt = `Tu es le CHEF D'ÉQUIPE de 33 agents experts. Analyse cette tâche et détermine la stratégie.

ÉQUIPES DISPONIBLES:
🔍 OSINT TEAM (12 agents)
💀 HACKING TEAM (19 agents)
🧠 GENERAL EXPERTS (6 agents)

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

            // Phase 2: Exécuter chaque phase avec Auto-Correction
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

                // Exécuter les agents pour cette phase
                for (const agentId of (phase.agents || [])) {
                    try {
                        // 1. Première tentative
                        let agentResponse = await this.consultAgent(phase.team, agentId, phase.objective, taskDescription);

                        // 2. Vérification (Judge)
                        console.log(`[ORCHESTRATOR] ⚖️ Verifying result for ${agentId}...`);
                        let verification = await this.verifyResult(phase.objective, agentResponse);

                        // 3. Boucle d'Auto-Correction (Self-Healing)
                        let attempts = 0;
                        const MAX_RETRIES = 5;

                        while (verification.score < 100 && attempts < MAX_RETRIES) {
                            attempts++;
                            console.log(`[ORCHESTRATOR] ↺ Self-Correction [${attempts}/${MAX_RETRIES}] for ${agentId} (Score: ${verification.score}/100)`);

                            // Tenter de corriger
                            try {
                                const correction = await this.autoCorrect(phase.objective, agentResponse, verification, taskDescription);
                                agentResponse = await this.consultAgent(phase.team, agentId, correction.prompt, taskDescription);

                                // Re-vérifier
                                verification = await this.verifyResult(phase.objective, agentResponse);
                            } catch (retryError) {
                                console.error(`[ORCHESTRATOR] Retry failed: ${retryError.message}`);
                                break;
                            }
                        }

                        // Sauvegarder le résultat final (bon ou mauvais après retries)
                        phaseResult.responses.push({
                            agent: agentId,
                            success: verification.score >= 80, // Considéré succès si score correct
                            score: verification.score,
                            issues: verification.issues,
                            response: agentResponse,
                            attempts: attempts + 1
                        });

                        // Apprentissage Évolutif (Succès après correction)
                        if (attempts > 0 && verification.score === 100) {
                            this.evolveKnowledge(agentId, phase.objective, attempts);
                        }

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
     * Juge: Vérifie si le résultat atteint l'objectif (0-100)
     */
    async verifyResult(objective, result) {
        const prompt = `Tu es le JUGE DE QUALITÉ (QA).
OBJECTIF INITIAL: "${objective}"
RÉSULTAT FOURNI: "${JSON.stringify(result).substring(0, 1000)}"

Note ce résultat sur 100.
- 100 = Parfait, complet, précis.
- < 100 = Il manque des choses ou c'est incorrect.

Réponds UNIQUEMENT en JSON:
{
  "score": 0-100,
  "issues": ["liste", "des", "problèmes"],
  "missing": ["ce", "qui", "manque"],
  "verdict": "explication courte"
}`;
        try {
            const response = await this.callLLM(prompt);
            const jsonMatch = response.match(/\{[\s\S]*\}/);
            if (jsonMatch) return JSON.parse(jsonMatch[0]);
            return { score: 50, issues: ["Parse Error"], verdict: "JSON invalide" };
        } catch (e) {
            return { score: 0, issues: [e.message], verdict: "Erreur Judge" };
        }
    }

    /**
     * Auto-Correcteur: Génère de nouvelles instructions pour corriger les erreurs
     */
    async autoCorrect(objective, previousResult, feedback, context) {
        const prompt = `Tu es le CORRECTEUR.
OBJECTIF: "${objective}"
CONTEXTE: "${context}"
RÉSULTAT PRÉCÉDENT: "${JSON.stringify(previousResult).substring(0, 500)}..."
FAILLES IDENTIFIÉES: ${JSON.stringify(feedback.issues)}
MANQUES: ${JSON.stringify(feedback.missing)}

Génère une NOUVELLE instruction (prompt) pour l'agent expert afin qu'il corrige ces erreurs et atteigne 100%.
Sois très directif sur les corrections.

Réponds en JSON:
{
  "prompt": "Nouvelle instruction corrigée pour l'agent..."
}`;
        try {
            const response = await this.callLLM(prompt);
            const jsonMatch = response.match(/\{[\s\S]*\}/);
            if (jsonMatch) return JSON.parse(jsonMatch[0]);
            return { prompt: `CORRECTION URGENTE: ${objective}. Vérifie: ${feedback.issues.join(', ')}` };
        } catch (e) {
            return { prompt: objective }; // Fallback
        }
    }

    /**
     * Évolution: Apprend des corrections réussies
     */
    evolveKnowledge(agentId, objective, attempts) {
        const evolutionFile = path.join(this.dataPath, 'orchestrator_evolution.json');
        let knowledge = [];
        if (fs.existsSync(evolutionFile)) {
            knowledge = JSON.parse(fs.readFileSync(evolutionFile, 'utf8'));
        }

        knowledge.push({
            agent: agentId,
            objective: objective,
            attempts: attempts,
            timestamp: new Date().toISOString(),
            status: 'learned'
        });

        // Garder les 500 derniers patterns
        if (knowledge.length > 500) knowledge.shift();

        fs.writeFileSync(evolutionFile, JSON.stringify(knowledge, null, 2));
        console.log(`[ORCHESTRATOR] 🧬 Evolution: Learned from ${attempts} retries with ${agentId}`);
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
${p.responses.map(r => `- ${r.agent}: ${r.success ? (JSON.stringify(r.response?.response || r.response).substring(0, 200)) : 'ERREUR: ' + r.error}`).join('\n')}
`).join('\n')}

Fournis:
1. RÉSUMÉ EXÉCUTIF (3 lignes max)
2. CONCLUSIONS CLÉS (bullet points)
3. RECOMMANDATIONS (actions concrètes)
4. RISQUES IDENTIFIÉS`;

        return await this.callLLM(synthesisPrompt);
    }

    /**
     * Appel LLM via LLMService
     */
    async callLLM(prompt) {
        try {
            return await this.llmService.generateResponse(
                prompt,
                null,
                'gemini',
                this.model,
                SYSTEM_PROMPT
            );
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
