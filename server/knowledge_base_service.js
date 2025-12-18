/**
 * Knowledge Base Service
 * Loads OSINT tools, security trends, and OPSEC scenarios for RAG-based AI responses
 */

const fs = require('fs');
const path = require('path');

class KnowledgeBaseService {
    constructor() {
        this.knowledgeDir = path.join(__dirname, 'knowledge');
        this.datasets = {};
        this.loadAllDatasets();
    }

    loadAllDatasets() {
        const files = [
            'osint_tools.json',
            'security_trends_2025.json',
            'opsec_scenarios.json',
            'cyber_physical_systems.json',
            'kinetic_osint.json'
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
            
            entries.forEach(entry => {
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
                    physicalRisk.includes(queryLower)) {
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
     * @param {string} query - User query
     * @returns {string} Context to inject into prompt
     */
    buildRAGContext(query) {
        const relevant = this.search(query);
        
        if (relevant.length === 0) {
            return '';
        }

        let context = '\n--- BASE DE CONNAISSANCES PERTINENTE ---\n';
        relevant.slice(0, 3).forEach((entry, i) => {
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
            } else if (entry.challenge) {
                context += `Scénario: ${entry.challenge}\n`;
                context += `Solution: ${JSON.stringify(entry.solution, null, 2)}\n`;
            }
        });
        context += '\n--- FIN DE LA BASE ---\n';


        return context;
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
