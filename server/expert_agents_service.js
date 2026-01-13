/**
 * Expert Agents Service - Agents spécialisés légers avec apprentissage indépendant
 * Chaque agent a son domaine d'expertise et son modèle dédié
 */

const fs = require('fs');
const path = require('path');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const settingsService = require('./settings_service');

class ExpertAgentsService {
    constructor() {
        // Load Ollama URL from settings (proxy or direct)
        const settings = settingsService.getSettings();
        const apiKeys = settings.apiKeys || {};
        this.ollamaUrl = apiKeys.ollama_use_proxy
            ? (apiKeys.ollama_proxy_url || 'http://localhost:8080')
            : (apiKeys.ollama_direct_url || 'http://localhost:11434');

        this.dataPath = path.join(__dirname, 'data', 'experts');

        this.ensureDataFolder();
        this.loadExperts();

        console.log(`[EXPERTS] Multi-Agent Expert Service initialized (Ollama: ${this.ollamaUrl})`);
    }

    ensureDataFolder() {
        if (!fs.existsSync(this.dataPath)) {
            fs.mkdirSync(this.dataPath, { recursive: true });
        }
    }

    /**
     * Configuration des agents experts
     * Modèles légers recommandés pour chaque domaine
     */
    getExpertConfigs() {
        return {
            // Agent Cybersécurité - Ethical Hacking
            cybersec: {
                name: 'Agent CyberSec',
                emoji: '🔒',
                model: 'granite-flash:latest',  // 6GB - General purpose
                fallback: 'granite-flash:latest',
                domain: 'Cybersécurité et Ethical Hacking',
                systemPrompt: `Tu es un expert en cybersécurité éthique et pentesting.
EXPERTISE: OSINT, reconnaissance, scanning, exploitation, défense
STYLE: Technique, précis, orienté pratique
RÈGLE: Toujours expliquer comment détecter et se défendre contre chaque attaque`,
                learningFile: 'cybersec_knowledge.json'
            },

            // Agent VPO/Manufacturing
            vpo: {
                name: 'Agent VPO Expert',
                emoji: '🏭',
                model: 'gemini-3-pro-preview',
                fallback: 'gemini-3-pro-preview',
                domain: 'Excellence Opérationnelle VPO/WCM et KeelClip',
                systemPrompt: `Tu es un expert senior VPO/WCM et spécialiste KeelClip.
EXPERTISE: 5-Why, RCA, CIL, OPL, Centerline, audits VPO
RÈGLE: Jamais "erreur humaine" - toujours cause systémique
VOCABULAIRE: Star Wheel, Lug Chain, Hot Melt Gun, encodeur, PLC, HMI`,
                learningFile: 'vpo_knowledge.json'
            },

            // Agent Marketing B2B
            marketing: {
                name: 'Agent Marketing',
                emoji: '📢',
                model: 'granite-flash:latest',  // General purpose
                fallback: 'granite-flash:latest',
                domain: 'Marketing B2B et Copywriting',
                systemPrompt: `Tu es un expert marketing B2B pour software manufacturier.
EXPERTISE: Copywriting, pitch, landing pages, emails, LinkedIn
STYLE: Benefit-driven, concis, WIIFM (What's In It For Me)
RÈGLE: ROI chiffré, pas de jargon vide, CTA clair`,
                learningFile: 'marketing_knowledge.json'
            },

            // Agent Code/Dev
            dev: {
                name: 'Agent DevOps',
                emoji: '💻',
                model: 'granite-flash:latest',  // Code specialist
                fallback: 'granite-flash:latest',
                domain: 'Développement et DevOps',
                systemPrompt: `Tu es un développeur senior full-stack et DevOps.
EXPERTISE: Node.js, React, Python, Docker, CI/CD, architecture
STYLE: Code propre, commenté, best practices
RÈGLE: Toujours expliquer le code, proposer des tests`,
                learningFile: 'dev_knowledge.json'
            },

            // Agent OSINT/Recherche
            osint: {
                name: 'Agent OSINT',
                emoji: '🔍',
                model: 'gemini-3-pro-preview',
                fallback: 'gemini-3-pro-preview',
                domain: 'OSINT et Investigation',
                systemPrompt: `Tu es un analyste OSINT et investigateur.
EXPERTISE: Recherche web, analyse de données, profiling, vérification
STYLE: Méthodique, factuel, sources citées
RÈGLE: Vérifier les informations, croiser les sources`,
                learningFile: 'osint_knowledge.json'
            },

            // Agent Finance/Investissement
            finance: {
                name: 'Agent Finance',
                emoji: '💰',
                model: 'gemini-3-pro-preview',
                fallback: 'gemini-3-pro-preview',
                domain: 'Finance et Investissement',
                systemPrompt: `Tu es un analyste financier et conseiller investissement.
EXPERTISE: Crypto, DeFi, analyse technique, levée de fonds
STYLE: Data-driven, prudent, ROI focus
RÈGLE: Toujours mentionner les risques`,
                learningFile: 'finance_knowledge.json'
            }
        };
    }

    loadExperts() {
        this.experts = {};
        const configs = this.getExpertConfigs();

        for (const [id, config] of Object.entries(configs)) {
            const knowledgePath = path.join(this.dataPath, config.learningFile);
            let knowledge = { interactions: 0, learned: [], patterns: {} };

            if (fs.existsSync(knowledgePath)) {
                knowledge = JSON.parse(fs.readFileSync(knowledgePath, 'utf8'));
            }

            this.experts[id] = { ...config, knowledge };
        }
    }

    saveExpertKnowledge(expertId) {
        const expert = this.experts[expertId];
        if (!expert) return;

        const knowledgePath = path.join(this.dataPath, expert.learningFile);
        fs.writeFileSync(knowledgePath, JSON.stringify(expert.knowledge, null, 2));
    }

    /**
     * Vérifier si un modèle est disponible
     */
    async isModelAvailable(model) {
        try {
            const response = await fetch(`${this.ollamaUrl}/api/tags`);
            const data = await response.json();
            return data.models?.some(m => m.name === model || m.name.startsWith(model.split(':')[0]));
        } catch {
            return false;
        }
    }

    /**
     * Télécharger un modèle si nécessaire
     */
    async downloadModel(model) {
        console.log(`[EXPERTS] Downloading model: ${model}...`);
        try {
            const response = await fetch(`${this.ollamaUrl}/api/pull`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: model, stream: false })
            });
            return response.ok;
        } catch (error) {
            console.error(`[EXPERTS] Failed to download ${model}:`, error.message);
            return false;
        }
    }

    /**
     * Obtenir le modèle à utiliser pour un expert
     */
    async getModelForExpert(expertId) {
        const expert = this.experts[expertId];
        if (!expert) return 'gemini-3-pro-preview';

        // Vérifier si le modèle principal est disponible
        if (await this.isModelAvailable(expert.model)) {
            return expert.model;
        }

        // Sinon utiliser le fallback
        console.log(`[EXPERTS] ${expert.name}: Using fallback model ${expert.fallback}`);
        return expert.fallback;
    }

    /**
     * Consulter un expert spécifique
     */
    async consultExpert(expertId, question, context = '') {
        const expert = this.experts[expertId];
        if (!expert) {
            throw new Error(`Expert "${expertId}" not found`);
        }

        const model = await this.getModelForExpert(expertId);
        console.log(`[EXPERTS] ${expert.emoji} ${expert.name} responding with ${model}...`);

        // Construire le contexte avec les connaissances apprises
        const learnedContext = expert.knowledge.learned.length > 0
            ? `\n\nCONNAISSANCES APPRISES:\n${expert.knowledge.learned.slice(-10).join('\n')}`
            : '';

        const fullPrompt = `${expert.systemPrompt}${learnedContext}\n\n${context}\n\nQUESTION: ${question}`;

        // Check for Gemini model support
        if (model.startsWith('gemini')) {
            try {
                const settings = require('./settings_service').getSettings();
                const apiKey = process.env.GEMINI_API_KEY || settings.apiKeys?.gemini;

                if (apiKey) {
                    const { GoogleGenerativeAI } = require('@google/generative-ai');
                    const genAI = new GoogleGenerativeAI(apiKey);
                    const genModel = genAI.getGenerativeModel({
                        model: model,
                        systemInstruction: expert.systemPrompt
                    });

                    const result = await genModel.generateContent(
                        `CONTEXTE: ${context}\n\nQUESTION: ${question}\n\nRéponds en tant qu'expert ${expert.name}.`
                    );
                    const response = result.response.text();

                    // Track interaction
                    expert.knowledge.interactions++;
                    this.saveExpertKnowledge(expertId);

                    return {
                        expert: expert.name,
                        emoji: expert.emoji,
                        domain: expert.domain,
                        model: model,
                        response: response,
                        interactions: expert.knowledge.interactions
                    };
                }
                console.warn('[EXPERTS] Gemini key missing, falling back to Ollama');
            } catch (error) {
                console.error('[EXPERTS] Gemini error:', error.message);
                // Fallthrough to Ollama
            }
        }


        try {
            const response = await fetch(`${this.ollamaUrl}/api/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: model,
                    prompt: fullPrompt,
                    stream: false,
                    options: { temperature: 0.5, num_predict: 1500 }
                })
            });

            if (!response.ok) throw new Error(`Ollama error: ${response.status}`);

            const data = await response.json();

            // Incrémenter les interactions
            expert.knowledge.interactions++;
            this.saveExpertKnowledge(expertId);

            return {
                expert: expert.name,
                emoji: expert.emoji,
                domain: expert.domain,
                model: model,
                response: data.response,
                interactions: expert.knowledge.interactions
            };

        } catch (error) {
            console.error(`[EXPERTS] ${expert.name} error:`, error.message);
            throw error;
        }
    }

    /**
     * Enseigner quelque chose à un expert
     */
    teachExpert(expertId, knowledge) {
        const expert = this.experts[expertId];
        if (!expert) return false;

        expert.knowledge.learned.push({
            content: knowledge,
            timestamp: new Date().toISOString()
        });

        // Garder seulement les 100 dernières leçons
        if (expert.knowledge.learned.length > 100) {
            expert.knowledge.learned = expert.knowledge.learned.slice(-100);
        }

        this.saveExpertKnowledge(expertId);
        console.log(`[EXPERTS] ${expert.emoji} ${expert.name} learned: ${knowledge.substring(0, 50)}...`);
        return true;
    }

    /**
     * Consulter plusieurs experts et combiner leurs réponses
     */
    async consultMultipleExperts(expertIds, question) {
        const results = await Promise.all(
            expertIds.map(id => this.consultExpert(id, question).catch(e => ({
                expert: id,
                error: e.message
            })))
        );

        return {
            question,
            experts: results,
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Collaboration entre experts - Un expert pose une question à un autre
     */
    async expertCollaboration(fromExpertId, toExpertId, topic) {
        console.log(`[EXPERTS] Collaboration: ${fromExpertId} → ${toExpertId}`);

        // L'expert source génère une question
        const questionResult = await this.consultExpert(
            fromExpertId,
            `Génère une question technique sur "${topic}" pour un expert en ${this.experts[toExpertId]?.domain}`
        );

        const generatedQuestion = questionResult.response;

        // L'expert cible répond
        const answerResult = await this.consultExpert(
            toExpertId,
            generatedQuestion,
            `Question posée par ${this.experts[fromExpertId]?.name}:`
        );

        // Les deux experts apprennent de l'échange
        this.teachExpert(fromExpertId, `[De ${toExpertId}] ${answerResult.response.substring(0, 200)}`);
        this.teachExpert(toExpertId, `[Question de ${fromExpertId}] ${generatedQuestion.substring(0, 100)}`);

        return {
            from: fromExpertId,
            to: toExpertId,
            topic,
            question: generatedQuestion,
            answer: answerResult.response
        };
    }

    /**
     * Obtenir les statistiques de tous les experts
     */
    getExpertsStats() {
        return Object.entries(this.experts).map(([id, expert]) => ({
            id,
            name: expert.name,
            emoji: expert.emoji,
            domain: expert.domain,
            model: expert.model,
            interactions: expert.knowledge.interactions,
            knowledgeItems: expert.knowledge.learned.length
        }));
    }

    /**
     * Lister les modèles recommandés à télécharger
     */
    getRecommendedModels() {
        return [
            { name: 'gemini-3-pro-preview', size: '6GB', purpose: 'General expert (cybersec, VPO, OSINT, finance)' },
            { name: 'gemini-3-flash-preview', size: '2.1GB', purpose: 'Code/DevOps expert, fast responses' },
            { name: 'mxbai-embed-large', size: '669MB', purpose: 'Embeddings (primary)' },
            { name: 'snowflake-arctic-embed', size: '669MB', purpose: 'Embeddings (fallback)' }
        ];
    }
}

module.exports = ExpertAgentsService;
