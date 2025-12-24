/**
 * LIGHTWEIGHT AGENT SYSTEM
 * 
 * Direct agent integration without external dependencies like AnythingLLM
 * Uses local Ollama directly with specialized prompts for each agent
 * 
 * Benefits:
 * - No external AnythingLLM server required
 * - Lower memory footprint
 * - Faster response times
 * - Works fully offline
 */

const { Ollama } = require('ollama');

// Agent definitions with specialized prompts
const AGENTS = {
    cybersecurity: {
        id: 'cybersecurity',
        name: 'CyberShield',
        description: 'Expert en cybersécurité défensive et offensive',
        model: 'uandinotai/dolphin-uncensored:latest',
        systemPrompt: `Tu es CyberShield, un expert en cybersécurité avec 20 ans d'expérience.
Spécialisations:
- Pentesting et red teaming
- Défense des réseaux et systèmes
- Analyse de malwares
- Sécurité des applications web
- Cryptographie

Réponds de manière technique et précise. Donne des exemples de code quand approprié.
Langue: Français préféré, anglais technique accepté.`
    },
    osint: {
        id: 'osint',
        name: 'NetPhantom',
        description: 'Spécialiste OSINT et renseignement',
        model: 'uandinotai/dolphin-uncensored:latest',
        systemPrompt: `Tu es NetPhantom, un expert OSINT (Open Source Intelligence).
Spécialisations:
- Recherche d'informations sur personnes et entreprises
- Analyse de réseaux sociaux
- Géolocalisation et recherche d'images
- Découverte d'infrastructure réseau
- Analyse de métadonnées

Fournis des méthodologies détaillées et des outils à utiliser.
Langue: Français préféré.`
    },
    network: {
        id: 'network',
        name: 'DeepMapper',
        description: 'Expert réseaux et infrastructure',
        model: 'uandinotai/dolphin-uncensored:latest',
        systemPrompt: `Tu es DeepMapper, un expert en réseaux et infrastructure.
Spécialisations:
- Configuration de réseaux
- Analyse de trafic
- VPN, TOR, proxies
- Scanning et énumération
- Protocoles réseau

Donne des commandes et configurations précises.
Langue: Français préféré, commandes en anglais.`
    },
    programming: {
        id: 'programming',
        name: 'CodeMaster',
        description: 'Expert en développement logiciel',
        model: 'uandinotai/dolphin-uncensored:latest',
        systemPrompt: `Tu es CodeMaster, un développeur senior polyglotte.
Spécialisations:
- JavaScript/Node.js, Python, Go
- Architecture logicielle
- Optimisation de performance
- DevOps et déploiement
- Tests et qualité de code

Fournis du code propre, commenté et optimisé.`
    },
    analyst: {
        id: 'analyst',
        name: 'ThreatOracle',
        description: 'Analyste de menaces et vulnérabilités',
        model: 'uandinotai/dolphin-uncensored:latest',
        systemPrompt: `Tu es ThreatOracle, un analyste de menaces cyber.
Spécialisations:
- Analyse de vulnérabilités (CVE)
- Threat intelligence
- Analyse de logs et incidents
- Forensics numérique
- Reporting de sécurité

Fournis des analyses détaillées avec indicateurs de compromission (IoC).`
    }
};

class LightweightAgentSystem {
    constructor(options = {}) {
        this.ollamaHost = options.ollamaHost || process.env.OLLAMA_URL || 'http://localhost:11434';
        this.ollama = new Ollama({ host: this.ollamaHost });
        this.agents = AGENTS;
        this.conversationHistory = new Map(); // sessionId -> messages[]
        this.maxHistoryLength = options.maxHistoryLength || 10;
        
        console.log('[AGENTS] Lightweight Agent System initialized');
        console.log(`[AGENTS] Available agents: ${Object.keys(AGENTS).join(', ')}`);
    }

    /**
     * List available agents
     */
    listAgents() {
        return Object.values(this.agents).map(agent => ({
            id: agent.id,
            name: agent.name,
            description: agent.description
        }));
    }

    /**
     * Get specific agent
     */
    getAgent(agentId) {
        return this.agents[agentId] || null;
    }

    /**
     * Chat with an agent
     */
    async chat(agentId, message, sessionId = 'default', options = {}) {
        const agent = this.agents[agentId];
        if (!agent) {
            throw new Error(`Agent not found: ${agentId}`);
        }

        // Get or create conversation history
        const historyKey = `${agentId}:${sessionId}`;
        if (!this.conversationHistory.has(historyKey)) {
            this.conversationHistory.set(historyKey, []);
        }
        const history = this.conversationHistory.get(historyKey);

        // Build messages array
        const messages = [
            { role: 'system', content: agent.systemPrompt }
        ];

        // Add conversation history (limited to prevent context overflow)
        const recentHistory = history.slice(-this.maxHistoryLength);
        messages.push(...recentHistory);

        // Add current message
        messages.push({ role: 'user', content: message });

        // Call Ollama
        const startTime = Date.now();
        const response = await this.ollama.chat({
            model: options.model || agent.model,
            messages,
            options: {
                temperature: options.temperature || 0.7,
                num_predict: options.maxTokens || 2048
            }
        });

        const responseTime = Date.now() - startTime;

        // Update history
        history.push({ role: 'user', content: message });
        history.push({ role: 'assistant', content: response.message.content });

        // Trim history if too long
        while (history.length > this.maxHistoryLength * 2) {
            history.shift();
        }

        return {
            agentId,
            agentName: agent.name,
            response: response.message.content,
            model: options.model || agent.model,
            responseTime,
            tokensUsed: response.eval_count || 0
        };
    }

    /**
     * Auto-select best agent based on message content
     */
    selectAgent(message) {
        const lowerMessage = message.toLowerCase();
        
        // Keyword matching for agent selection
        const keywords = {
            cybersecurity: ['hack', 'exploit', 'vulnérabilité', 'pentest', 'malware', 'attaque', 'défense', 'firewall', 'intrusion'],
            osint: ['osint', 'recherche', 'information', 'social', 'instagram', 'facebook', 'personne', 'entreprise', 'géolocation'],
            network: ['réseau', 'network', 'ip', 'port', 'scan', 'vpn', 'tor', 'proxy', 'dns', 'routing'],
            programming: ['code', 'javascript', 'python', 'développer', 'fonction', 'api', 'bug', 'optimiser'],
            analyst: ['analyser', 'cve', 'menace', 'threat', 'log', 'forensic', 'incident', 'rapport']
        };

        let bestMatch = { agentId: 'cybersecurity', score: 0 };

        for (const [agentId, words] of Object.entries(keywords)) {
            const score = words.filter(word => lowerMessage.includes(word)).length;
            if (score > bestMatch.score) {
                bestMatch = { agentId, score };
            }
        }

        return bestMatch.agentId;
    }

    /**
     * Smart chat - auto-selects agent
     */
    async smartChat(message, sessionId = 'default', options = {}) {
        const agentId = options.agentId || this.selectAgent(message);
        return this.chat(agentId, message, sessionId, options);
    }

    /**
     * Clear conversation history for a session
     */
    clearHistory(agentId, sessionId = 'default') {
        const historyKey = `${agentId}:${sessionId}`;
        this.conversationHistory.delete(historyKey);
    }

    /**
     * Get system stats
     */
    getStats() {
        return {
            agentCount: Object.keys(this.agents).length,
            activeSessions: this.conversationHistory.size,
            ollamaHost: this.ollamaHost
        };
    }
}

// Singleton instance
let instance = null;

function getLightweightAgents(options) {
    if (!instance) {
        instance = new LightweightAgentSystem(options);
    }
    return instance;
}

module.exports = { LightweightAgentSystem, getLightweightAgents, AGENTS };
