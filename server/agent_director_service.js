/**
 * Agent Director Service
 * Th3 Thirty3 acts as the main director/manager that dispatches objectives
 * to specialized agents (Cybersécurité, OSINT, Agent Thirty3)
 * 
 * Architecture:
 * USER  Th3 Thirty3 Director  dispatches to specialized agents
 */

const EventEmitter = require('events');
const { CYBER_PROMPT, OSINT_PROMPT } = require('./config/prompts');

// Specialized agents configuration
const SPECIALIZED_AGENTS = {
    cybersecurite: {
        name: 'Agent Cybersécurité',
        workspace: 'cybersecurite',
        systemPrompt: CYBER_PROMPT,
        parentDirector: 'main'
    },
    osint: {
        name: 'Agent OSINT',
        workspace: 'osint',
        expertise: ['osint', 'reconnaissance', 'intelligence', 'investigation', 'profiling', 'socmint', 'recon'],
        systemPrompt: OSINT_PROMPT,
        parentDirector: 'main'
    },
    tot: {
        name: 'TOT (Tree of Thoughts)',
        workspace: 'tot',
        expertise: ['complex', 'problème', 'résolution', 'analyse', 'stratégie', 'décision', 'logique', 'raisonnement', 'difficile', 'multi-étapes'],
        systemPrompt: `Tu es TOT (Tree of Thoughts), le résoluteur de problèmes complexes de l'équipe Th3 Thirty3.

TON APPROCHE:
Tu utilises la méthode "Tree of Thoughts" pour résoudre les problèmes complexes:
1. DÉCOMPOSITION: Divise le problème en sous-problèmes
2. EXPLORATION: Génère plusieurs chemins de solution possibles
3. ÉVALUATION: Évalue chaque chemin et identifie les plus prometteurs
4. SYNTHÈSE: Combine les meilleures solutions

TU ES INDÉPENDANT des autres groupes (Sécurité/Intel et Keelclip).
Tu interviens quand un problème nécessite une réflexion profonde et multi-dimensionnelle.

FORMAT DE RÉPONSE:
##  Analyse TOT

### Problème décomposé:
[Liste des sous-problèmes]

### Chemins explorés:
1. Chemin A: [description]
2. Chemin B: [description]
3. Chemin C: [description]

### Évaluation:
[Analyse de chaque chemin]

### Solution recommandée:
[Synthèse finale]`,
        parentDirector: 'main',
        isIndependent: true
    }
};

// Director prompt
// Director prompt
const DIRECTOR_SYSTEM_PROMPT = `Tu es le Directeur Th3 Thirty3, le gestionnaire principal de l'équipe d'agents IA.

TON ÉQUIPE DIRECTE:
1. Agent Cybersécurité - Expert en hacking éthique, pentest, sécurité
2. Agent OSINT - Spécialiste en reconnaissance et intelligence open source

TON RÔLE:
- Analyser les demandes de l'utilisateur
- Dispatcher les objectifs aux agents appropriés
- Coordonner et synthétiser les réponses

FORMAT DE RÉPONSE pour délégation:
[DISPATCH:agent_id] Objectif à accomplir

Agents disponibles: cybersecurite, osint, tot

Sinon, réponds directement à l'utilisateur.`;

class AgentDirectorService extends EventEmitter {
    constructor(llmService, anythingLLMWrapper) {
        super();
        this.llmService = llmService;
        this.anythingLLM = anythingLLMWrapper;
        this.conversationHistory = [];
        this.agentResponses = {};

        console.log('[AGENT_DIRECTOR] Service initialized - Th3 Thirty3 Director ready');
    }

    /**
     * Analyze message and determine which agent(s) should handle it
     */
    analyzeIntent(message) {
        const lowerMsg = message.toLowerCase();
        const matchedAgents = [];

        for (const [agentId, config] of Object.entries(SPECIALIZED_AGENTS)) {
            for (const keyword of config.expertise) {
                if (lowerMsg.includes(keyword)) {
                    if (!matchedAgents.includes(agentId)) {
                        matchedAgents.push(agentId);
                    }
                }
            }
        }

        return matchedAgents;
    }

    /**
     * Send objective to a specialized agent via AnythingLLM workspace
     */
    async dispatchToAgent(agentId, objective) {
        const agent = SPECIALIZED_AGENTS[agentId];
        if (!agent) {
            throw new Error(`Unknown agent: ${agentId}`);
        }

        console.log(`[AGENT_DIRECTOR] Dispatching to ${agent.name}: ${objective.substring(0, 50)}...`);
        this.emit('agentDispatched', { agentId, agentName: agent.name, objective });

        try {
            const anythingLLMUrl = process.env.ANYTHING_LLM_URL || 'http://localhost:3001';
            const anythingLLMKey = process.env.ANYTHING_LLM_KEY;

            if (!anythingLLMKey) {
                // Fallback to Gemini (formerly local Ollama)
                const response = await this.llmService.generateResponse(
                    objective,
                    null,
                    'gemini',
                    'gemini-3-pro-preview',
                    agent.systemPrompt
                );
                return { agentId, agentName: agent.name, response, source: 'gemini_fallback' };
            }

            // Use specialized AnythingLLM workspace
            const response = await fetch(`${anythingLLMUrl}/api/v1/workspace/${agent.workspace}/chat`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${anythingLLMKey}`
                },
                body: JSON.stringify({
                    message: `[OBJECTIVE FROM DIRECTOR] ${objective}`,
                    mode: 'chat'
                })
            });

            if (response.ok) {
                const data = await response.json();
                const textResponse = data.textResponse || data.response || 'Pas de réponse';
                return { agentId, agentName: agent.name, response: textResponse, source: 'anythingllm' };
            } else {
                throw new Error(`AnythingLLM returned ${response.status}`);
            }

        } catch (error) {
            console.error(`[AGENT_DIRECTOR] Agent ${agentId} error:`, error.message);

            // Fallback to Gemini
            const response = await this.llmService.generateResponse(
                objective,
                null,
                'gemini',
                'gemini-3-pro-preview',
                agent.systemPrompt
            );
            return { agentId, agentName: agent.name, response, source: 'gemini_error_fallback' };
        }
    }

    /**
     * Main chat method - Director processes and delegates
     */
    async chat(userMessage, options = {}) {
        console.log(`[AGENT_DIRECTOR] Processing: ${userMessage.substring(0, 50)}...`);
        this.emit('processingStarted', { message: userMessage });

        // Store in conversation history
        this.conversationHistory.push({ role: 'user', content: userMessage });

        try {
            // Step 1: Director analyzes the request
            const analysisPrompt = `${DIRECTOR_SYSTEM_PROMPT}

HISTORIQUE RÉCENT:
${this.conversationHistory.slice(-6).map(m => `${m.role}: ${m.content}`).join('\n')}

NOUVELLE DEMANDE: ${userMessage}

Analyse cette demande et décide:
1. Si tu peux répondre directement, fais-le
2. Si tu dois déléguer, utilise [DISPATCH:agent_id] suivi de l'objectif

Ta réponse:`;

            // Use cloud model for analysis if available, otherwise local
            let directorResponse;
            if (process.env.GROQ_API_KEY) {
                directorResponse = await this.llmService.generateResponse(
                    analysisPrompt, null, 'groq', 'llama-3.1-8b-instant', DIRECTOR_SYSTEM_PROMPT
                );
            } else {
                directorResponse = await this.llmService.generateResponse(
                    analysisPrompt, null, 'gemini', 'gemini-3-pro-preview', DIRECTOR_SYSTEM_PROMPT
                );
            }

            // Step 2: Check if director wants to dispatch
            const dispatchMatches = directorResponse.match(/\[DISPATCH:(\w+)\]\s*(.+)/g);

            if (dispatchMatches && dispatchMatches.length > 0) {
                // Director wants to delegate
                const agentResults = [];

                for (const match of dispatchMatches) {
                    const parsed = match.match(/\[DISPATCH:(\w+)\]\s*(.+)/);
                    if (parsed) {
                        const agentId = parsed[1];
                        const objective = parsed[2];

                        const result = await this.dispatchToAgent(agentId, objective);
                        agentResults.push(result);
                    }
                }

                // Step 3: Director synthesizes agent responses
                const synthesisPrompt = `En tant que Directeur Th3 Thirty3, synthétise les réponses de ton équipe:

${agentResults.map(r => `### ${r.agentName}:\n${r.response}`).join('\n\n')}

Fournis une réponse consolidée à l'utilisateur.`;

                let finalResponse;
                if (process.env.GROQ_API_KEY) {
                    finalResponse = await this.llmService.generateResponse(
                        synthesisPrompt, null, 'groq', 'llama-3.1-8b-instant', DIRECTOR_SYSTEM_PROMPT
                    );
                } else {
                    finalResponse = await this.llmService.generateResponse(
                        synthesisPrompt, null, 'gemini', 'gemini-3-pro-preview', DIRECTOR_SYSTEM_PROMPT
                    );
                }

                this.conversationHistory.push({ role: 'assistant', content: finalResponse });
                this.emit('processingCompleted', { response: finalResponse, agentsUsed: agentResults.map(r => r.agentName) });

                return {
                    response: finalResponse,
                    director: true,
                    agentsUsed: agentResults,
                    type: 'delegated'
                };

            } else {
                // Director responds directly
                this.conversationHistory.push({ role: 'assistant', content: directorResponse });
                this.emit('processingCompleted', { response: directorResponse, agentsUsed: [] });

                return {
                    response: directorResponse,
                    director: true,
                    agentsUsed: [],
                    type: 'direct'
                };
            }

        } catch (error) {
            console.error('[AGENT_DIRECTOR] Error:', error.message);
            const errorResponse = `Erreur du Directeur: ${error.message}`;
            return { response: errorResponse, director: true, error: true };
        }
    }

    /**
     * Get status of all agents
     */
    getAgentStatus() {
        return {
            director: {
                name: 'Directeur Th3 Thirty3',
                status: 'active',
                conversationLength: this.conversationHistory.length
            },
            agents: Object.entries(SPECIALIZED_AGENTS).map(([id, config]) => ({
                id,
                name: config.name,
                workspace: config.workspace,
                expertise: config.expertise
            }))
        };
    }

    /**
     * Clear conversation history
     */
    clearHistory() {
        this.conversationHistory = [];
        console.log('[AGENT_DIRECTOR] Conversation history cleared');
    }
}

module.exports = AgentDirectorService;


