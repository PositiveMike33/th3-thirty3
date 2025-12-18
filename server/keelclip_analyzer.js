const { VPO_KEELCLIP_EXPERT } = require('./config/prompts');

class KeelClipAnalyzer {
    constructor(llmService) {
        this.llmService = llmService;
        // Workspace AnythingLLM dédié au module VPO
        this.vpoWorkspace = 'expert-senior-en-excellence-operationnelle-standard-vpowcm-et-specialiste-technique-des-machines-keelclip';
        console.log('[KEELCLIP] Analyzer initialized');
        console.log(`[KEELCLIP] VPO Workspace: ${this.vpoWorkspace}`);
    }

    /**
     * Send request to VPO workspace
     * @param {string} prompt - The prompt to send
     * @returns {Promise<string>} Response from VPO workspace
     */
    async sendToVPOWorkspace(prompt) {
        const baseUrl = process.env.ANYTHING_LLM_URL;
        const apiKey = process.env.ANYTHING_LLM_KEY;

        if (!baseUrl || !apiKey) {
            throw new Error("AnythingLLM URL or Key missing.");
        }

        console.log(`[KEELCLIP] Sending to VPO workspace: ${this.vpoWorkspace}`);

        try {
            const chatRes = await fetch(`${baseUrl}/workspace/${this.vpoWorkspace}/chat`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    message: prompt,
                    mode: 'chat'
                })
            });

            if (!chatRes.ok) {
                const errText = await chatRes.text();
                throw new Error(`VPO Workspace failed: ${chatRes.status} - ${errText}`);
            }

            const chatData = await chatRes.json();
            return chatData.textResponse;

        } catch (error) {
            console.error(`[KEELCLIP] VPO Workspace error:`, error.message);
            throw error;
        }
    }

    /**
     * Generate complete 5-Why report from visual analysis
     * @param {Object} visionAnalysis - Output from VisionService.analyzeKeelClipIncident
     * @param {string} operatorDescription - Additional context from operator
     * @returns {Promise<string>} Complete 5-Why report in VPO format
     */
    async generate5Why(visionAnalysis, operatorDescription = '') {
        // Build context from vision analysis
        let context = `# ANALYSE VISUELLE DE L'INCIDENT\n\n`;
        
        if (visionAnalysis.parsed === false) {
            // Raw analysis
            context += visionAnalysis.raw_analysis;
        } else {
            // Structured analysis
            context += `## Composants Identifiés\n`;
            context += (visionAnalysis.composants_visibles || []).map(c => `- ${c}`).join('\n');
            
            context += `\n\n## Défaut Principal\n${visionAnalysis.defaut_principal || 'Non identifié'}`;
            context += `\n\n## Localisation\n${visionAnalysis.localisation || 'Non spécifiée'}`;
            
            if (visionAnalysis.indices_visuels && visionAnalysis.indices_visuels.length > 0) {
                context += `\n\n## Indices Visuels\n`;
                context += visionAnalysis.indices_visuels.map(i => `- ${i}`).join('\n');
            }
            
            if (visionAnalysis.risques_securite && visionAnalysis.risques_securite.length > 0) {
                context += `\n\n⚠️ RISQUES SÉCURITÉ IDENTIFIÉS :\n`;
                context += visionAnalysis.risques_securite.map(r => `- ${r}`).join('\n');
            }
            
            if (visionAnalysis.hypotheses_causes && visionAnalysis.hypotheses_causes.length > 0) {
                context += `\n\n## Hypothèses de Causes (Vision)\n`;
                context += visionAnalysis.hypotheses_causes.map((h, i) => `${i + 1}. ${h}`).join('\n');
            }
        }

        if (operatorDescription) {
            context += `\n\n# DESCRIPTION DE L'OPÉRATEUR\n\n${operatorDescription}`;
        }

        // Build the 5-Why generation prompt
        const prompt = `${VPO_KEELCLIP_EXPERT}

${context}

---

**MISSION :** Génère un rapport 5-Why COMPLET et PRÊT POUR AUDIT VPO.

**INSTRUCTIONS :**
1. Utilise l'analyse visuelle ET la description de l'opérateur pour construire le rapport
2. Applique STRICTEMENT le format de sortie obligatoire (tableaux QQOQCCP, 5 Pourquoi, Plan d'Action)
3. Utilise le vocabulaire technique exact des machines KeelClip
4. La cause racine (P5) DOIT être une faille systémique (Standard, CIL, OPL, Formation, Centerline)
5. JAMAIS de conclusion "erreur humaine"

Génère maintenant le rapport 5-Why complet.`;

        try {
            // Use dedicated VPO workspace in AnythingLLM
            const report = await this.sendToVPOWorkspace(prompt);
            return report;

        } catch (error) {
            console.error('[KEELCLIP] 5-Why generation failed:', error.message);
            throw error;
        }
    }


    /**
     * Generate quick incident summary (for chat context)
     * @param {Object} visionAnalysis - Output from VisionService
     * @returns {string} Brief summary
     */
    generateQuickSummary(visionAnalysis) {
        if (visionAnalysis.parsed === false) {
            return `📸 **Analyse Visuelle :**\n${visionAnalysis.raw_analysis.substring(0, 500)}...`;
        }

        let summary = `📸 **Incident Détecté**\n\n`;
        summary += `**Défaut :** ${visionAnalysis.defaut_principal || 'Non identifié'}\n`;
        summary += `**Localisation :** ${visionAnalysis.localisation || 'Non spécifiée'}\n`;
        
        if (visionAnalysis.risques_securite && visionAnalysis.risques_securite.length > 0) {
            summary += `\n⚠️ **Sécurité :** ${visionAnalysis.risques_securite.join(', ')}\n`;
        }
        
        if (visionAnalysis.hypotheses_causes && visionAnalysis.hypotheses_causes.length > 0) {
            summary += `\n**Causes Probables :**\n`;
            summary += visionAnalysis.hypotheses_causes.slice(0, 3).map((h, i) => `${i + 1}. ${h}`).join('\n');
        }

        return summary;
    }

    /**
     * Validate 5-Why report quality
     * @param {string} report - Generated report
     * @returns {Object} Validation result with score and issues
     */
    validate5WhyReport(report) {
        const issues = [];
        let score = 100;

        // Check for required sections
        const requiredSections = [
            { pattern: /DÉFINITION DU PROBLÈME|QQOQCCP/i, name: 'QQOQCCP', points: 20 },
            { pattern: /ANALYSE DES 5 POURQUOI|Pourquoi 1|P1/i, name: '5 Pourquoi', points: 30 },
            { pattern: /PLAN D'ACTION|Action.*Corrective/i, name: 'Plan d\'Action', points: 20 }
        ];

        requiredSections.forEach(section => {
            if (!section.pattern.test(report)) {
                issues.push(`Section manquante : ${section.name}`);
                score -= section.points;
            }
        });

        // Check for forbidden patterns
        const forbiddenPatterns = [
            { pattern: /erreur humaine|faute.*opérateur|opérateur.*responsable/i, name: 'Erreur Humaine', points: 30 },
            { pattern: /inattention|négligence|oubli/i, name: 'Blâme Opérateur', points: 20 }
        ];

        forbiddenPatterns.forEach(forbidden => {
            if (forbidden.pattern.test(report)) {
                issues.push(`⛔ INTERDIT : ${forbidden.name} détecté`);
                score -= forbidden.points;
            }
        });

        // Check for technical vocabulary
        const technicalTerms = [
            'Discharge Selector', 'Star Wheel', 'Lug Chain', 'Hot Melt',
            'PLC', 'HMI', 'Centerline', 'VFD', 'Servo', 'Encoder',
            'CIL', 'OPL', 'Standard', 'Maintenance'
        ];

        const hasTerms = technicalTerms.some(term => 
            report.toLowerCase().includes(term.toLowerCase())
        );

        if (!hasTerms) {
            issues.push('Manque de vocabulaire technique KeelClip');
            score -= 10;
        }

        // Check for cause racine systémique
        const systemicCauses = [
            'Standard', 'CIL', 'OPL', 'Formation', 'Centerline',
            'Procédure', 'Documentation', 'Maintenance préventive'
        ];

        const hasSystemicCause = systemicCauses.some(cause =>
            report.toLowerCase().includes(cause.toLowerCase())
        );

        if (!hasSystemicCause) {
            issues.push('Cause racine non systémique (doit être Standard/CIL/OPL/Formation)');
            score -= 20;
        }

        return {
            valid: score >= 70,
            score: Math.max(0, score),
            issues: issues,
            recommendation: score >= 90 ? 'Excellent - Prêt pour audit' :
                           score >= 70 ? 'Bon - Révision mineure recommandée' :
                           'Insuffisant - Révision majeure requise'
        };
    }
}

module.exports = KeelClipAnalyzer;
