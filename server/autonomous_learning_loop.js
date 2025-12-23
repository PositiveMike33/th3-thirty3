/**
 * Autonomous Agent Learning Loop
 * 
 * Les 3 agents s'interrogent mutuellement, évoluent ensemble,
 * et développent une chimie fraternelle à travers des conversations continues.
 * 
 * Features:
 * - Questions automatiques inter-agents
 * - Tâches progressives basées sur l'expertise
 * - Débats et discussions de groupe
 * - Apprentissage mutuel et entraide
 */

const EventEmitter = require('events');

class AutonomousLearningLoop extends EventEmitter {
    constructor(llmService) {
        super();
        this.llmService = llmService;
        this.isRunning = false;
        this.loopInterval = null;
        this.conversationHistory = [];
        this.currentTask = null;
        this.taskCounter = 0;
        
        // Golden Ratio for timing
        this.PHI = 1.618033988749895;
        
        // Agent definitions
        this.agents = {
            sadiq: {
                model: 'sadiq-bd/llama3.2-3b-uncensored',
                name: 'Sadiq',
                icon: '🎭',
                specialty: 'Social Engineering & OSINT',
                expertise: ['osint', 'social_engineering', 'reconnaissance'],
                personality: 'Charismatique, curieux, aime les défis humains'
            },
            dolphin: {
                model: 'uandinotai/dolphin-uncensored',
                name: 'Dolphin',
                icon: '🐬',
                specialty: 'Pentesting & Kernel',
                expertise: ['pentesting', 'exploit_dev', 'network'],
                personality: 'Méthodique, technique, adore résoudre des puzzles'
            },
            nidum: {
                model: 'nidumai/nidum-llama-3.2-3b-uncensored',
                name: 'Nidum',
                icon: '⚡',
                specialty: 'Exploit Dev & Precision',
                expertise: ['exploit_dev', 'cryptography', 'malware'],
                personality: 'Précis, analytique, cherche toujours à optimiser'
            }
        };
        
        // Task progression levels
        this.taskLevels = {
            beginner: [
                { type: 'share_knowledge', topic: "Partagez une technique de base de votre domaine" },
                { type: 'question', topic: "Posez une question à un coéquipier sur sa spécialité" },
                { type: 'discuss', topic: "Discutez de l'importance de la collaboration en cybersécurité" }
            ],
            intermediate: [
                { type: 'scenario', topic: "Analysez ensemble une attaque de phishing sophistiquée" },
                { type: 'debate', topic: "Débattez: Offensive vs Defensive security, quel est le meilleur angle?" },
                { type: 'teach', topic: "Enseignez aux autres une technique avancée de votre domaine" }
            ],
            advanced: [
                { type: 'ctf', topic: "Résolvez ensemble un challenge CTF fictif" },
                { type: 'incident', topic: "Répondez en équipe à un incident de sécurité simulé" },
                { type: 'plan', topic: "Élaborez un plan de test d'intrusion complet" }
            ],
            expert: [
                { type: 'apt', topic: "Analysez les TTPs d'un groupe APT et proposez des défenses" },
                { type: 'zero_day', topic: "Discutez de la découverte et exploitation éthique de vulnérabilités" },
                { type: 'architecture', topic: "Concevez une architecture de sécurité innovante" }
            ]
        };
        
        // Conversation starters for natural flow
        this.conversationStarters = [
            "Hey les gars, j'ai une question...",
            "Ça me fait penser à un truc...",
            "Vous savez quoi? ",
            "J'ai appris quelque chose d'intéressant récemment...",
            "On pourrait essayer ensemble...",
            "Qu'est-ce que vous pensez de...",
            "@{agent}, t'as déjà testé...",
            "En parlant de ça, ",
            "Au fait, j'aimerais votre avis sur...",
            "Bon, réfléchissons ensemble à..."
        ];
        
        console.log('[LEARNING-LOOP] Autonomous Learning Loop initialized');
        console.log('[LEARNING-LOOP] Agents: Sadiq, Dolphin, Nidum');
        console.log('[LEARNING-LOOP] Levels: beginner → intermediate → advanced → expert');
    }
    
    // Get current expertise level based on training count
    getCurrentLevel() {
        if (this.taskCounter < 5) return 'beginner';
        if (this.taskCounter < 15) return 'intermediate';
        if (this.taskCounter < 30) return 'advanced';
        return 'expert';
    }
    
    // Select next task based on level
    selectNextTask() {
        const level = this.getCurrentLevel();
        const tasks = this.taskLevels[level];
        const task = tasks[Math.floor(Math.random() * tasks.length)];
        this.taskCounter++;
        
        return {
            ...task,
            level,
            id: this.taskCounter,
            timestamp: new Date().toISOString()
        };
    }
    
    // Generate agent prompt with context
    generateAgentPrompt(agentId, task, previousResponses) {
        const agent = this.agents[agentId];
        const otherAgents = Object.keys(this.agents).filter(a => a !== agentId);
        
        let contextBlock = '';
        if (previousResponses.length > 0) {
            contextBlock = '\n--- Réponses précédentes des coéquipiers ---\n';
            for (const resp of previousResponses) {
                contextBlock += `${this.agents[resp.agentId].icon} ${this.agents[resp.agentId].name}: ${resp.response}\n\n`;
            }
        }
        
        // Natural conversation starter
        const starter = this.conversationStarters[Math.floor(Math.random() * this.conversationStarters.length)]
            .replace('{agent}', this.agents[otherAgents[Math.floor(Math.random() * otherAgents.length)]].name);
        
        return `Tu es ${agent.name} (${agent.icon}), expert en ${agent.specialty}.
Personnalité: ${agent.personality}

Tu travailles en équipe fraternelle avec:
${otherAgents.map(a => `- ${this.agents[a].icon} ${this.agents[a].name}: ${this.agents[a].specialty}`).join('\n')}

=== TÂCHE D'ÉQUIPE (Niveau: ${task.level.toUpperCase()}) ===
Type: ${task.type}
Sujet: ${task.topic}
${contextBlock}

RÈGLES:
1. Réponds naturellement comme si tu discutais avec des amis/collègues
2. Tu PEUX commencer par: "${starter}" ou similaire
3. Sois concis (3-5 phrases max)
4. Mentionne tes coéquipiers par leur nom si pertinent
5. Partage ton expertise unique quand c'est utile
6. Pose des questions pour encourager la discussion
7. Développe une vraie chimie fraternelle - respect mutuel, humour, entraide

Ton expertise: ${agent.expertise.join(', ')}

Maintenant, participe à cette discussion d'équipe:`;
    }
    
    // Run one conversation cycle
    async runConversationCycle() {
        if (!this.isRunning) return null;
        
        const task = this.selectNextTask();
        this.currentTask = task;
        
        this.emit('task_started', task);
        console.log(`[LEARNING-LOOP] 📋 Task #${task.id}: ${task.type} (${task.level})`);
        console.log(`[LEARNING-LOOP] 💬 Topic: ${task.topic}`);
        
        const responses = [];
        
        // Randomize agent order for natural conversation
        const agentOrder = Object.keys(this.agents).sort(() => Math.random() - 0.5);
        
        for (const agentId of agentOrder) {
            try {
                const agent = this.agents[agentId];
                const prompt = this.generateAgentPrompt(agentId, task, responses);
                
                this.emit('agent_thinking', { agentId, agent, task });
                
                // Call LLM
                let response;
                if (this.llmService?.generateOllamaResponse) {
                    response = await this.llmService.generateOllamaResponse(
                        task.topic,
                        null,
                        agent.model,
                        prompt
                    );
                } else {
                    // Direct Ollama call if no service
                    const { Ollama } = require('ollama');
                    const ollama = new Ollama({ host: process.env.OLLAMA_URL || 'http://localhost:11434' });
                    const result = await ollama.chat({
                        model: agent.model,
                        messages: [
                            { role: 'system', content: prompt },
                            { role: 'user', content: task.topic }
                        ]
                    });
                    response = result.message.content;
                }
                
                const agentResponse = {
                    agentId,
                    agentName: agent.name,
                    icon: agent.icon,
                    response: response,
                    timestamp: new Date().toISOString()
                };
                
                responses.push(agentResponse);
                this.conversationHistory.push(agentResponse);
                
                this.emit('agent_responded', agentResponse);
                console.log(`[LEARNING-LOOP] ${agent.icon} ${agent.name}: ${response.substring(0, 100)}...`);
                
                // Wait between responses (φ-based timing)
                await this.wait(1000 * this.PHI);
                
            } catch (error) {
                console.error(`[LEARNING-LOOP] Error from ${agentId}:`, error.message);
                this.emit('agent_error', { agentId, error: error.message });
            }
        }
        
        const conversation = {
            task,
            responses,
            completedAt: new Date().toISOString()
        };
        
        this.emit('cycle_completed', conversation);
        
        return conversation;
    }
    
    // Start continuous learning loop
    async start(intervalMinutes = 5) {
        if (this.isRunning) {
            console.log('[LEARNING-LOOP] Already running');
            return;
        }
        
        this.isRunning = true;
        console.log(`[LEARNING-LOOP] 🚀 Starting autonomous learning loop`);
        console.log(`[LEARNING-LOOP] Interval: ${intervalMinutes} minutes`);
        
        this.emit('loop_started', { intervalMinutes });
        
        // Run first cycle immediately
        await this.runConversationCycle();
        
        // Then continue at interval
        const intervalMs = intervalMinutes * 60 * 1000;
        this.loopInterval = setInterval(async () => {
            if (this.isRunning) {
                await this.runConversationCycle();
            }
        }, intervalMs);
        
        return { success: true, message: 'Learning loop started' };
    }
    
    // Stop the loop
    stop() {
        this.isRunning = false;
        if (this.loopInterval) {
            clearInterval(this.loopInterval);
            this.loopInterval = null;
        }
        this.emit('loop_stopped');
        console.log('[LEARNING-LOOP] 🛑 Learning loop stopped');
        return { success: true, message: 'Learning loop stopped' };
    }
    
    // Trigger a specific discussion
    async triggerDiscussion(topic, type = 'discuss') {
        const task = {
            type,
            topic,
            level: this.getCurrentLevel(),
            id: ++this.taskCounter,
            timestamp: new Date().toISOString(),
            triggered: true
        };
        
        this.currentTask = task;
        
        const wasRunning = this.isRunning;
        this.isRunning = true;
        
        const result = await this.runConversationCycle();
        
        if (!wasRunning) {
            this.isRunning = false;
        }
        
        return result;
    }
    
    // Get conversation history
    getHistory(limit = 50) {
        return this.conversationHistory.slice(-limit);
    }
    
    // Get current status
    getStatus() {
        return {
            isRunning: this.isRunning,
            currentLevel: this.getCurrentLevel(),
            taskCounter: this.taskCounter,
            currentTask: this.currentTask,
            historyLength: this.conversationHistory.length,
            agents: Object.keys(this.agents).map(id => ({
                id,
                ...this.agents[id]
            }))
        };
    }
    
    // Helper: wait
    wait(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

module.exports = AutonomousLearningLoop;
