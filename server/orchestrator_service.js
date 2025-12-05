/**
 * Orchestrator Service - Le Chef d'Équipe des 33 Agents
 * Dirige, coordonne et optimise le travail de tous les agents experts
 * Utilise Mistral 7B comme cerveau principal
 */

const fs = require('fs');
const path = require('path');
const EventEmitter = require('events');

class OrchestratorService extends EventEmitter {
    constructor() {
        super();
        this.ollamaUrl = process.env.OLLAMA_URL || 'http://localhost:11434';
        this.orchestratorModel = 'mistral:7b';        // Cerveau principal
        this.fallbackModel = 'qwen2.5:3b';           // Fallback
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
