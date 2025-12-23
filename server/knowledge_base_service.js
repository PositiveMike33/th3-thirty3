/**
 * Knowledge Base Service
 * Loads OSINT tools, security trends, and OPSEC scenarios for RAG-based AI responses
 * OPTIMIZED: Pre-indexed keywords and cached searches
 */

const fs = require('fs');
const path = require('path');
const { knowledgeCache } = require('./performance_utils');

class KnowledgeBaseService {
    constructor() {
        this.knowledgeDir = path.join(__dirname, 'knowledge');
        this.datasets = {};
        this.searchIndex = new Map(); // Pre-built keyword index
        this.loadAllDatasets();
    }

    loadAllDatasets() {
        const files = [
            'osint_tools.json',
            'security_trends_2025.json',
            'opsec_scenarios.json',
            'cyber_physical_systems.json',
            'kinetic_osint.json',
            'network_defense_reverse_engineering.json',  // WiFi, network, RE defense
            'defense_training_workflows.json',           // Structured training workflows
            'expert_model_assignments.json',             // Model specialization config
            'wifi_security_training_scenarios.json',     // 50+ WiFi attack/defense scenarios
            'pentestgpt_methodology.json',               // PentestGPT (USENIX 2024) pentest methodology
            'financial_markets_scenarios.json'           // Financial Cyber-Warfare (HFT, SWIFT, DeFi) scenarios
        ];

        files.forEach(file => {
            const filePath = path.join(this.knowledgeDir, file);
            if (fs.existsSync(filePath)) {
                try {
                    const content = fs.readFileSync(filePath, 'utf8');
                    const name = file.replace('.json', '');
                    this.datasets[name] = JSON.parse(content);
                    console.log(`[KNOWLEDGE] Loaded ${file} (${this.datasets[name].length} entries)`);
                } catch (error) {
                    console.error(`[KNOWLEDGE] Failed to load ${file}:`, error.message);
                }
            }
        });
    }

    /**
     * Search for relevant knowledge based on query
     * @param {string} query - User query
     * @param {string} category - Optional category filter (osint_tools, security_trends_2025, opsec_scenarios)
     * @returns {Array} Matching knowledge entries
     */
    search(query, category = null) {
        const results = [];
        const queryLower = query.toLowerCase();
        
        const datasetsToSearch = category 
            ? { [category]: this.datasets[category] } 
            : this.datasets;

        for (const [datasetName, entries] of Object.entries(datasetsToSearch)) {
            if (!entries) continue;
            
            // Handle array entries
            const entryArray = Array.isArray(entries) ? entries : [entries];
            
            entryArray.forEach(entry => {
                // Original fields
                const instruction = entry.instruction?.toLowerCase() || '';
                const challenge = entry.challenge?.toLowerCase() || '';
                const toolName = entry.output?.tool?.toLowerCase() || '';
                
                // CPS fields (cyber_physical_systems)
                const sector = entry.sector?.toLowerCase() || '';
                const systemType = entry.system_type?.toLowerCase() || '';
                const physicalImpact = entry.physical_impact?.toLowerCase() || '';
                const protocolPort = entry.protocol_port?.toLowerCase() || '';
                
                // Kinetic OSINT fields
                const technique = entry.technique?.toLowerCase() || '';
                const toolRef = entry.tool_ref?.toLowerCase() || '';
                const physicalRisk = entry.physical_risk?.toLowerCase() || '';
                
                // Network Defense / Reverse Engineering fields (NEW)
                const attackType = entry.attack_type?.toLowerCase() || '';
                const categoryField = entry.category?.toLowerCase() || '';
                const detectionMethod = entry.detection_method?.toLowerCase() || '';
                const defenseProtocol = entry.defense_protocol?.toLowerCase() || '';
                const trainingPrompt = entry.training_prompt?.toLowerCase() || '';
                const toolChain = entry.tool_chain?.join(' ').toLowerCase() || '';
                const iocIndicators = entry.ioc_indicators?.join(' ').toLowerCase() || '';
                
                // Match against all fields
                if (instruction.includes(queryLower) || 
                    challenge.includes(queryLower) || 
                    toolName.includes(queryLower) ||
                    sector.includes(queryLower) ||
                    systemType.includes(queryLower) ||
                    physicalImpact.includes(queryLower) ||
                    protocolPort.includes(queryLower) ||
                    technique.includes(queryLower) ||
                    toolRef.includes(queryLower) ||
                    physicalRisk.includes(queryLower) ||
                    attackType.includes(queryLower) ||
                    categoryField.includes(queryLower) ||
                    detectionMethod.includes(queryLower) ||
                    defenseProtocol.includes(queryLower) ||
                    trainingPrompt.includes(queryLower) ||
                    toolChain.includes(queryLower) ||
                    iocIndicators.includes(queryLower)) {
                    results.push({
                        source: datasetName,
                        ...entry
                    });
                }
            });
        }

        return results;
    }

    /**
     * Get tool recommendation for a specific task
     * @param {string} taskType - Type of task (username, geolocation, archive, metadata, tech)
     * @returns {Object|null} Tool recommendation
     */
    getToolForTask(taskType) {
        const taskMapping = {
            'username': 'Sherlock',
            'user': 'Sherlock',
            'pseudo': 'Sherlock',
            'geolocation': 'SunCalc',
            'photo': 'SunCalc',
            'shadow': 'SunCalc',
            'archive': 'Wayback Machine',
            'history': 'Wayback Machine',
            'deleted': 'Wayback Machine',
            'metadata': 'ExifTool',
            'exif': 'ExifTool',
            'technology': 'Wappalyzer',
            'stack': 'Wappalyzer',
            'cms': 'Wappalyzer'
        };

        const toolName = taskMapping[taskType.toLowerCase()];
        if (!toolName) return null;

        const tools = this.datasets.osint_tools || [];
        return tools.find(t => t.output?.tool === toolName) || null;
    }

    /**
     * Get OPSEC guidance for a scenario
     * @param {string} scenarioType - Type of scenario (telegram, darkweb, recon)
     * @returns {Object|null} OPSEC guidance
     */
    getOpsecGuidance(scenarioType) {
        const scenarios = this.datasets.opsec_scenarios || [];
        const typeLower = scenarioType.toLowerCase();
        
        return scenarios.find(s => 
            s.challenge?.toLowerCase().includes(typeLower) ||
            s.scenario_id?.toLowerCase().includes(typeLower)
        ) || null;
    }

    /**
     * Build context string for LLM prompt augmentation
     * OPTIMIZED: Cached for 60 seconds to speed up repeated queries
     * @param {string} query - User query
     * @returns {string} Context to inject into prompt
     */
    buildRAGContext(query) {
        // Use cache for repeated queries
        const cacheKey = `rag_${query.toLowerCase().substring(0, 50)}`;
        return knowledgeCache.getOrComputeSync(cacheKey, () => {
            const relevant = this.search(query);
            
            if (relevant.length === 0) {
                return '';
            }

        let context = '\n--- BASE DE CONNAISSANCES PERTINENTE ---\n';
        relevant.slice(0, 5).forEach((entry, i) => {
            context += `\n[${i + 1}] Source: ${entry.source}\n`;
            
            // Handle different entry types
            if (entry.instruction) {
                context += `Instruction: ${entry.instruction}\n`;
                context += `Réponse: ${JSON.stringify(entry.output, null, 2)}\n`;
            } else if (entry.sector) {
                // CPS entry
                context += `Secteur: ${entry.sector}\n`;
                context += `Système: ${entry.system_type}\n`;
                context += `Port: ${entry.protocol_port}\n`;
                context += `Impact Physique: ${entry.physical_impact}\n`;
                context += `Défense: ${entry.defense_protocol || 'N/A'}\n`;
            } else if (entry.technique) {
                // Kinetic OSINT entry
                context += `Technique: ${entry.technique}\n`;
                context += `Outil: ${entry.tool_ref}\n`;
                context += `Risque Physique: ${entry.physical_risk}\n`;
                context += `Contre-mesure: ${entry.counter_measure || 'N/A'}\n`;
            } else if (entry.attack_type) {
                // Network Defense / Reverse Engineering entry (NEW)
                context += `Catégorie: ${entry.category}\n`;
                context += `Type d'attaque: ${entry.attack_type}\n`;
                context += `Outils: ${entry.tool_chain?.join(', ') || 'N/A'}\n`;
                context += `Détection: ${entry.detection_method}\n`;
                context += `Défense: ${entry.defense_protocol}\n`;
                context += `IOCs: ${entry.ioc_indicators?.join(', ') || 'N/A'}\n`;
                if (entry.training_prompt) {
                    context += `Prompt d'entraînement: ${entry.training_prompt}\n`;
                }
            } else if (entry.category_id) {
                // Training Workflow category (NEW)
                context += `Workflow: ${entry.name}\n`;
                context += `Objectifs: ${entry.learning_objectives?.join('; ') || 'N/A'}\n`;
                if (entry.training_scenarios?.length) {
                    context += `Phases: ${entry.training_scenarios.map(s => s.phase).join(' → ')}\n`;
                }
            } else if (entry.expert_domains) {
                // Expert Model Assignments (NEW) - skip detailed output, just note availability
                context += `Configuration d'experts disponible pour ${Object.keys(entry.expert_domains).length} domaines\n`;
            } else if (entry.ideal_agent) {
                // Financial Cyber-Warfare entry (NEW)
                context += `Scénario Financier: ${entry.title} (${entry.category})\n`;
                context += `Difficulté: ${entry.difficulty}\n`;
                context += `Contexte: ${entry.context}\n`;
                context += `Objectifs: ${entry.objectives?.join(', ') || 'N/A'}\n`;
                context += `Agent Idéal: ${entry.ideal_agent} (${entry.ideal_model})\n`;
                context += `Points Clés: ${entry.golden_answer_points?.join('; ') || 'N/A'}\n`;
            } else if (entry.challenge) {
                context += `Scénario: ${entry.challenge}\n`;
                context += `Solution: ${JSON.stringify(entry.solution, null, 2)}\n`;
            }
        });
        context += '\n--- FIN DE LA BASE ---\n';


            return context;
        }, 60000); // 60 second cache TTL
    }

    /**
     * Get all available knowledge stats
     */
    getStats() {
        const stats = {};
        for (const [name, entries] of Object.entries(this.datasets)) {
            stats[name] = entries?.length || 0;
        }
        return stats;
    }
}

// Singleton
const knowledgeBase = new KnowledgeBaseService();

module.exports = knowledgeBase;
