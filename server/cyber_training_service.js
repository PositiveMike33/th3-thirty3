/**
 * Cyber Training Service - Entraînement d'agents cybersécurité
 * Uses Centralized Cloud LLM Service (Gemini/AnythingLLM)
 * ENVIRONNEMENT: Kali Linux 2024.1
 */

const KALI_ENVIRONMENT = require('./config/kali_environment');
const settingsService = require('./settings_service');

class CyberTrainingService {
    constructor(llmService) {
        this.llmService = llmService;
        this.kaliEnv = KALI_ENVIRONMENT;
        console.log(`[CYBER-TRAINING] Service initialized (Cloud Only)`);
    }

    /**
     * Entraîner l'agent sur un module spécifique
     */
    async trainOnModule(module, commands) {
        const trainingPrompt = this.generateTrainingPrompt(module, commands);

        try {
            // Use Cloud LLM Service (Provider: hackergpt or gemini)
            const response = await this.llmService.generateResponse(trainingPrompt, null, 'hackergpt', null, this.kaliEnv.getSystemPrompt());

            return {
                success: true,
                response: response,
                module: module
            };
        } catch (error) {
            console.error('[CYBER-TRAINING] Error:', error.message);
            return { success: false, error: error.message };
        }
    }

    /**
     * Générer le prompt d'entraînement
     */
    generateTrainingPrompt(module, commands) {
        const moduleDescriptions = {
            recon: 'Reconnaissance et collecte d\'informations OSINT',
            network: 'Scanning réseau et découverte de services',
            http: 'Énumération web et analyse HTTP',
            sniffing: 'Capture de trafic et attaques MITM',
            shells: 'Shells, pivoting et persistence',
            tls: 'Cryptographie et TLS/SSL',
            defense: 'Techniques de défense et hardening'
        };

        const commandsList = commands.map(c => `- ${c.cmd}: ${c.desc}`).join('\n');

        return `${this.kaliEnv.getSystemPrompt()}
Tu es un expert en cybersécurité éthique sur Kali Linux. Tu dois apprendre ces commandes du module "${moduleDescriptions[module] || module}".

COMMANDES À APPRENDRE:
${commandsList}

Pour CHAQUE commande, explique brièvement:
1. Ce qu'elle fait techniquement (avec syntaxe Kali Linux)
2. Comment détecter et bloquer cette technique

Réponds de manière structurée et concise. Toutes les commandes doivent être compatibles Kali Linux.`;
    }

    /**
     * Expliquer une commande spécifique
     */
    async explainCommand(command) {
        const prompt = `Tu es un expert en cybersécurité éthique. Explique cette commande:

COMMANDE: ${command}

Explique:
1. **Fonction**: Que fait cette commande?
2. **Offensive**: Comment un attaquant l'utilise?
3. **Défense**: Comment détecter et bloquer?

Réponds de manière technique et concise.`;

        try {
            const response = await this.llmService.generateResponse(prompt, null, 'hackergpt', null, this.kaliEnv.getSystemPrompt());
            return {
                success: true,
                explanation: response,
                command: command
            };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * Générer un scénario d'attaque simulée
     */
    async generateAttackScenario(targetType = 'web_server') {
        const scenarios = {
            web_server: 'Un serveur web Apache/Nginx avec une application vulnérable',
            network: 'Un réseau d\'entreprise avec plusieurs subnets',
            database: 'Un serveur de base de données exposé',
            iot: 'Des appareils IoT sur un réseau domestique'
        };

        const prompt = `Tu es un formateur en pentesting. Crée un scénario d'entraînement.

CIBLE: ${scenarios[targetType]}

Génère brièvement:
1. Reconnaissance: Commandes à utiliser
2. Exploitation: Techniques d'attaque
3. Défense: Comment sécuriser

Format concis comme un CTF.`;

        try {
            const response = await this.llmService.generateResponse(prompt, null, 'hackergpt', null, this.kaliEnv.getSystemPrompt());
            return {
                success: true,
                scenario: response,
                targetType: targetType
            };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * Quiz l'agent sur ses connaissances
     */
    async quizAgent(topic) {
        const prompt = `Tu es un examinateur en cybersécurité. Réponds à ces questions sur "${topic}":

1. Quelle est la différence entre scan SYN et TCP complet?
2. Comment détecter une attaque ARP spoofing?
3. Qu'est-ce qu'un reverse shell et comment s'en protéger?

Réponds de manière précise et concise.`;

        try {
            const response = await this.llmService.generateResponse(prompt, null, 'hackergpt', 'gemini-3-pro-preview', this.kaliEnv.getSystemPrompt());
            return {
                success: true,
                answers: response,
                topic: topic
            };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }
}

module.exports = CyberTrainingService;
