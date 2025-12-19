/**
 * Expert Model Training Service
 * Service pour créer et gérer les modèles LLM experts spécialisés
 * Th3 Thirty3 - Cybersecurity Training Platform
 */

const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

class ExpertModelService {
    constructor() {
        this.modelsDir = path.join(__dirname, '..', '');
        this.trainingDataDir = path.join(__dirname, 'data', 'training');
        this.expertModels = {
            'ddos-expert-33': {
                name: 'DDoS Expert',
                description: 'Expert en attaques DDoS et stratégies de défense',
                baseModel: 'granite3.1-moe:1b',
                modelfile: 'Modelfile.ddos-expert',
                trainingData: 'ddos_expert_training.json',
                expertise: ['volumetric', 'layer7', 'botnet', 'defense', 'http2-rapid-reset']
            },
            'osint-shodan-33': {
                name: 'OSINT Shodan Expert',
                description: 'Expert en reconnaissance passive Shodan',
                baseModel: 'granite3.1-moe:1b',
                modelfile: 'Modelfile.osint-shodan',
                trainingData: 'osint_shodan_training.json',
                expertise: ['shodan', 'infrastructure', 'ports', 'ssl', 'risk-scoring']
            }
        };
    }

    /**
     * Vérifie si un modèle expert existe
     */
    async checkModelExists(modelName) {
        return new Promise((resolve) => {
            exec('ollama list', (error, stdout) => {
                if (error) {
                    resolve(false);
                    return;
                }
                resolve(stdout.includes(modelName));
            });
        });
    }

    /**
     * Crée un modèle expert
     */
    async createExpertModel(modelName) {
        const config = this.expertModels[modelName];
        if (!config) {
            throw new Error(`Unknown model: ${modelName}`);
        }

        const modelfilePath = path.join(this.modelsDir, config.modelfile);
        
        return new Promise((resolve, reject) => {
            console.log(`[EXPERT] Creating ${modelName} from ${config.modelfile}...`);
            
            exec(`ollama create ${modelName} -f "${modelfilePath}"`, (error, stdout, stderr) => {
                if (error) {
                    console.error(`[EXPERT] Error creating ${modelName}:`, error.message);
                    reject(error);
                    return;
                }
                console.log(`[EXPERT] Successfully created ${modelName}`);
                resolve({ success: true, model: modelName, output: stdout });
            });
        });
    }

    /**
     * Liste tous les modèles experts disponibles
     */
    async listExpertModels() {
        const results = [];
        
        for (const [modelName, config] of Object.entries(this.expertModels)) {
            const exists = await this.checkModelExists(modelName);
            results.push({
                name: modelName,
                displayName: config.name,
                description: config.description,
                expertise: config.expertise,
                installed: exists
            });
        }
        
        return results;
    }

    /**
     * Charge les données de training pour un modèle
     */
    loadTrainingData(modelName) {
        const config = this.expertModels[modelName];
        if (!config) return null;

        const dataPath = path.join(this.trainingDataDir, config.trainingData);
        
        try {
            const data = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
            return data;
        } catch (error) {
            console.error(`[EXPERT] Cannot load training data for ${modelName}:`, error.message);
            return null;
        }
    }

    /**
     * Initialise tous les modèles experts manquants
     */
    async initializeAllModels() {
        const results = [];
        
        for (const modelName of Object.keys(this.expertModels)) {
            const exists = await this.checkModelExists(modelName);
            
            if (!exists) {
                try {
                    await this.createExpertModel(modelName);
                    results.push({ model: modelName, status: 'created' });
                } catch (error) {
                    results.push({ model: modelName, status: 'failed', error: error.message });
                }
            } else {
                results.push({ model: modelName, status: 'exists' });
            }
        }
        
        return results;
    }

    /**
     * Obtient le prompt système pour un modèle expert
     */
    getExpertSystemPrompt(modelName) {
        const prompts = {
            'ddos-expert-33': `Tu es DDOS-EXPERT-33, expert en cybersécurité spécialisé dans les attaques DDoS.
EXPERTISE: Attaques volumétriques (UDP/SYN Flood), Layer 7 (HTTP Flood, Slowloris), 
Botnets (Mirai, architecture C2), Défense (WAF, CDN, rate limiting).
CONTEXTE: HTTP/2 Rapid Reset (CVE-2023-44487) - Record 398M req/s. Tendance 2026: IA dans botnets.
RÈGLES: Éducation défensive uniquement. Toujours proposer des contre-mesures.`,

            'osint-shodan-33': `Tu es OSINT-SHODAN-33, expert en reconnaissance passive d'infrastructure.
EXPERTISE: Shodan queries, analyse de surface d'attaque, scoring de risques.
PORTS CRITIQUES: 21(FTP), 23(Telnet), 445(SMB), 3389(RDP), 27017(MongoDB).
RÈGLES: Reconnaissance PASSIVE uniquement. Éthique OSINT. Proposer remédiations.`
        };

        return prompts[modelName] || '';
    }
}

module.exports = ExpertModelService;
