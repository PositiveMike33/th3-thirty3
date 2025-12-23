/**
 * Service d'Extraction et Apprentissage 5-Why avec Llama 3.2
 * Retient les patterns, apprend les tags, génère les 5P formatés
 */

const fs = require('fs');
const path = require('path');

class ReportExtractionService {
    constructor() {
        this.dataPath = path.join(__dirname, 'data');
        this.learningFile = path.join(this.dataPath, 'learned_patterns.json');
        this.tagsFile = path.join(this.dataPath, 'tags_database.json');
        
        this.ollamaUrl = process.env.OLLAMA_URL || 'http://localhost:11434';
        // Utiliser dolphin-mistral:7b par défaut (plus léger, 1.4GB)
        // Ou llama3.2-vision:11b si assez de RAM (11.7GB requis)
        this.model = process.env.OLLAMA_MODEL || 'dolphin-mistral:7b';
        
        this.ensureDataFolder();
        this.loadLearning();
        
        console.log('[EXTRACTION] Service initialisé avec Llama 3.2');
    }

    ensureDataFolder() {
        if (!fs.existsSync(this.dataPath)) {
            fs.mkdirSync(this.dataPath, { recursive: true });
        }
    }

    loadLearning() {
        // Charger les patterns appris
        if (fs.existsSync(this.learningFile)) {
            this.learnedPatterns = JSON.parse(fs.readFileSync(this.learningFile, 'utf8'));
        } else {
            this.learnedPatterns = {
                components: {},  // Composants et leurs problèmes fréquents
                rootCauses: {},  // Causes racines récurrentes
                solutions: {},   // Solutions déjà appliquées
                tags: []         // Tags identifiés
            };
            this.saveLearning();
        }

        // Charger la base de tags
        if (fs.existsSync(this.tagsFile)) {
            this.tagsDatabase = JSON.parse(fs.readFileSync(this.tagsFile, 'utf8'));
        } else {
            this.tagsDatabase = {
                components: [
                    'Star Wheel', 'Lug Chain', 'Hot Melt Glue Gun', 'Discharge Selector',
                    'Infeed Conveyor', 'Outfeed Conveyor', 'Clip Magazine', 'Applicator Head',
                    'Encoder', 'Proximity Sensor', 'PLC', 'HMI', 'VFD', 'Servo Motor'
                ],
                defects: [
                    'Bourrage', 'Désalignement', 'Usure', 'Surchauffe', 'Vibration',
                    'Bruit anormal', 'Fuite', 'Blocage', 'Défaut capteur', 'Erreur programme'
                ],
                systemicCauses: [
                    'CIL incomplet', 'OPL manquante', 'Centerline non défini',
                    'Formation insuffisante', 'Standard absent', 'PM non planifiée',
                    'Pièce non standard', 'Procédure obsolète'
                ],
                priorities: ['critical', 'high', 'medium', 'low']
            };
            this.saveTags();
        }
    }

    saveLearning() {
        fs.writeFileSync(this.learningFile, JSON.stringify(this.learnedPatterns, null, 2));
    }

    saveTags() {
        fs.writeFileSync(this.tagsFile, JSON.stringify(this.tagsDatabase, null, 2));
    }

    /**
     * Envoyer une requête à Llama 3.2 via Ollama
     */
    async queryLlama(prompt, systemPrompt = null) {
        // Construire le prompt complet
        let fullPrompt = '';
        if (systemPrompt) {
            fullPrompt = `${systemPrompt}\n\n${prompt}`;
        } else {
            fullPrompt = prompt;
        }

        try {
            // Utiliser l'endpoint /api/generate pour llama3.2-vision
            const response = await fetch(`${this.ollamaUrl}/api/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: this.model,
                    prompt: fullPrompt,
                    stream: false,
                    options: {
                        temperature: 0.3,
                        num_predict: 2000
                    }
                })
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error('[EXTRACTION] Ollama response:', errorText);
                throw new Error(`Ollama error: ${response.status} - ${errorText}`);
            }

            const data = await response.json();
            return data.response;

        } catch (error) {
            console.error('[EXTRACTION] Erreur Llama:', error.message);
            throw error;
        }
    }

    /**
     * Extraire les informations d'une description d'incident
     */
    async extractIncidentInfo(description, imageBase64 = null) {
        console.log('[EXTRACTION] Analyse de l\'incident...');

        const systemPrompt = `Tu es un expert VPO KeelClip. Extrait les informations de l'incident en JSON.

TAGS CONNUS:
Composants: ${this.tagsDatabase.components.join(', ')}
Défauts: ${this.tagsDatabase.defects.join(', ')}
Causes Systémiques: ${this.tagsDatabase.systemicCauses.join(', ')}

PATTERNS APPRIS (incidents similaires passés):
${JSON.stringify(this.learnedPatterns.components, null, 2)}

RÉPONDS UNIQUEMENT EN JSON VALIDE:
{
  "component": "composant identifié",
  "defect": "type de défaut",
  "tags": ["tag1", "tag2"],
  "priority": "critical|high|medium|low",
  "estimatedRootCause": "hypothèse cause racine basée sur patterns",
  "similarPastIncidents": ["INC-xxx si similaire"]
}`;

        const prompt = `Analyse cet incident KeelClip:

"${description}"

Extrait les informations structurées.`;

        const result = await this.queryLlama(prompt, systemPrompt);
        
        try {
            // Parser le JSON de la réponse
            const jsonMatch = result.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                return JSON.parse(jsonMatch[0]);
            }
        } catch (e) {
            console.error('[EXTRACTION] Erreur parsing JSON:', e.message);
        }
        
        return { raw: result };
    }

    /**
     * Générer le rapport 5-Pourquoi formaté
     */
    async generate5WhyReport(incidentInfo, description) {
        console.log('[EXTRACTION] Génération du rapport 5P...');

        const systemPrompt = `Tu es un auditeur VPO senior expert KeelClip. Génère un rapport 5-Pourquoi.

RÈGLES ABSOLUES:
1. JAMAIS "erreur humaine" ou "inattention" comme cause
2. Chaque P doit être la cause DIRECTE du précédent
3. P5 DOIT être une faille systémique (CIL, OPL, Centerline, Formation, Standard)
4. Vocabulaire technique exact KeelClip
5. Format VPO prêt pour SAP/DMS

PATTERNS APPRIS:
${JSON.stringify(this.learnedPatterns.rootCauses, null, 2)}`;

        const prompt = `Génère le rapport 5-Pourquoi pour:

INCIDENT: ${description}
COMPOSANT: ${incidentInfo.component || 'Non identifié'}
DÉFAUT: ${incidentInfo.defect || 'Non identifié'}
PRIORITÉ: ${incidentInfo.priority || 'medium'}

FORMAT DE SORTIE EXACT:

═══════════════════════════════════════════════════════════════
                    RAPPORT 5 POURQUOI - VPO COMPLIANT
═══════════════════════════════════════════════════════════════

📋 IDENTIFICATION
├── ID: [À assigner]
├── Date: ${new Date().toLocaleDateString('fr-CA')}
├── Ligne: [À spécifier]
├── Composant: ${incidentInfo.component || '[À identifier]'}
├── Priorité: ${incidentInfo.priority?.toUpperCase() || 'MEDIUM'}
└── Tags: ${incidentInfo.tags?.join(', ') || '[Tags]'}

───────────────────────────────────────────────────────────────
📌 DÉFINITION DU PROBLÈME (QQOQCCP)
───────────────────────────────────────────────────────────────
│ QUOI     │ [Description technique du défaut]
│ OÙ       │ [Composant précis de la machine]
│ QUAND    │ [Moment du cycle ou condition]
│ COMMENT  │ [Comment le problème s'est manifesté]
│ COMBIEN  │ [Fréquence, durée, impact quantifié]
│ POURQUOI │ [Pourquoi c'est un problème - impact]
│ QUI      │ [Qui a détecté, qui est impacté]
───────────────────────────────────────────────────────────────

───────────────────────────────────────────────────────────────
🔍 ANALYSE DES 5 POURQUOI
───────────────────────────────────────────────────────────────

P1 │ POURQUOI [le problème s'est produit]?
   │ ➜ [Cause directe observable]
   │
P2 │ POURQUOI [P1]?
   │ ➜ [Cause technique derrière P1]
   │
P3 │ POURQUOI [P2]?
   │ ➜ [Dérive, usure, ou défaillance]
   │
P4 │ POURQUOI [P3]?
   │ ➜ [Absence de détection/prévention]
   │
P5 │ POURQUOI [P4]?
   │ ➜ ⚠️ CAUSE RACINE SYSTÉMIQUE ⚠️
   │    [CIL incomplet | OPL manquante | Centerline non défini |
   │     Formation insuffisante | Standard absent]
   │
───────────────────────────────────────────────────────────────

───────────────────────────────────────────────────────────────
🛠️ PLAN D'ACTION
───────────────────────────────────────────────────────────────

CORRECTIVE (IMMÉDIAT):
┌──────────────────────────────────────────────────────────────┐
│ Action    │ [Ce qu'il faut faire pour réparer]              │
│ Qui       │ [Responsable]                                    │
│ Quand     │ [Délai - ex: Immédiat]                          │
│ Statut    │ ⏳ En attente                                    │
└──────────────────────────────────────────────────────────────┘

PRÉVENTIVE (SYSTÉMIQUE):
┌──────────────────────────────────────────────────────────────┐
│ Action    │ [Modification CIL/Centerline/OPL/Formation]     │
│ Qui       │ [Responsable]                                    │
│ Quand     │ [Délai planifié]                                │
│ Statut    │ ⏳ À planifier                                   │
└──────────────────────────────────────────────────────────────┘

───────────────────────────────────────────────────────────────
✅ VALIDATION
───────────────────────────────────────────────────────────────
│ Rédigé par    │ [Nom]                │ Date: ${new Date().toLocaleDateString('fr-CA')} │
│ Vérifié par   │ ________________     │ Date: __________ │
│ Approuvé par  │ ________________     │ Date: __________ │
───────────────────────────────────────────────────────────────

═══════════════════════════════════════════════════════════════
                    FIN DU RAPPORT - VPO COMPLIANT
═══════════════════════════════════════════════════════════════

Génère ce rapport complet avec les vraies informations de l'incident.`;

        const report = await this.queryLlama(prompt, systemPrompt);
        return report;
    }

    /**
     * Apprendre d'un incident résolu
     */
    learnFromResolution(incident, resolution) {
        console.log('[EXTRACTION] Apprentissage du pattern...');

        const component = incident.component;
        const defect = incident.defect;
        const rootCause = resolution.rootCause;
        const solution = resolution.preventiveAction;

        // Apprendre le pattern composant -> défaut
        if (!this.learnedPatterns.components[component]) {
            this.learnedPatterns.components[component] = {
                defects: {},
                totalIncidents: 0
            };
        }
        this.learnedPatterns.components[component].totalIncidents++;
        
        if (!this.learnedPatterns.components[component].defects[defect]) {
            this.learnedPatterns.components[component].defects[defect] = {
                count: 0,
                rootCauses: [],
                solutions: []
            };
        }
        this.learnedPatterns.components[component].defects[defect].count++;

        // Apprendre la cause racine
        if (rootCause && !this.learnedPatterns.components[component].defects[defect].rootCauses.includes(rootCause)) {
            this.learnedPatterns.components[component].defects[defect].rootCauses.push(rootCause);
        }

        // Apprendre la solution
        if (solution && !this.learnedPatterns.components[component].defects[defect].solutions.includes(solution)) {
            this.learnedPatterns.components[component].defects[defect].solutions.push(solution);
        }

        // Mettre à jour la base de causes racines
        if (rootCause) {
            if (!this.learnedPatterns.rootCauses[rootCause]) {
                this.learnedPatterns.rootCauses[rootCause] = { count: 0, components: [] };
            }
            this.learnedPatterns.rootCauses[rootCause].count++;
            if (!this.learnedPatterns.rootCauses[rootCause].components.includes(component)) {
                this.learnedPatterns.rootCauses[rootCause].components.push(component);
            }
        }

        // Ajouter nouveaux tags si découverts
        if (incident.tags) {
            incident.tags.forEach(tag => {
                if (!this.learnedPatterns.tags.includes(tag)) {
                    this.learnedPatterns.tags.push(tag);
                }
            });
        }

        this.saveLearning();
        console.log(`[EXTRACTION] Pattern appris: ${component} -> ${defect} -> ${rootCause}`);
    }

    /**
     * Obtenir des suggestions basées sur l'apprentissage
     */
    getSuggestions(component, defect = null) {
        const suggestions = {
            possibleDefects: [],
            likelyRootCauses: [],
            recommendedSolutions: [],
            similarIncidents: 0
        };

        if (this.learnedPatterns.components[component]) {
            const compData = this.learnedPatterns.components[component];
            suggestions.similarIncidents = compData.totalIncidents;

            if (defect && compData.defects[defect]) {
                const defData = compData.defects[defect];
                suggestions.likelyRootCauses = defData.rootCauses;
                suggestions.recommendedSolutions = defData.solutions;
            } else {
                suggestions.possibleDefects = Object.keys(compData.defects);
            }
        }

        return suggestions;
    }

    /**
     * Ajouter un nouveau tag à la base
     */
    addTag(category, tag) {
        if (this.tagsDatabase[category] && !this.tagsDatabase[category].includes(tag)) {
            this.tagsDatabase[category].push(tag);
            this.saveTags();
            console.log(`[EXTRACTION] Nouveau tag ajouté: ${category}/${tag}`);
            return true;
        }
        return false;
    }

    /**
     * Obtenir les statistiques d'apprentissage
     */
    getLearningStats() {
        return {
            componentsTracked: Object.keys(this.learnedPatterns.components).length,
            rootCausesIdentified: Object.keys(this.learnedPatterns.rootCauses).length,
            tagsLearned: this.learnedPatterns.tags.length,
            topComponents: Object.entries(this.learnedPatterns.components)
                .sort((a, b) => b[1].totalIncidents - a[1].totalIncidents)
                .slice(0, 5)
                .map(([comp, data]) => ({ component: comp, incidents: data.totalIncidents })),
            topRootCauses: Object.entries(this.learnedPatterns.rootCauses)
                .sort((a, b) => b[1].count - a[1].count)
                .slice(0, 5)
                .map(([cause, data]) => ({ cause, count: data.count }))
        };
    }

    /**
     * Workflow complet: Extraction → 5P → Apprentissage
     */
    async processIncident(description, imageBase64 = null) {
        console.log('[EXTRACTION] ═══ TRAITEMENT INCIDENT ═══');

        // 1. Extraire les informations
        const extracted = await this.extractIncidentInfo(description, imageBase64);
        console.log('[EXTRACTION] Infos extraites:', JSON.stringify(extracted, null, 2));

        // 2. Obtenir suggestions basées sur apprentissage
        const suggestions = this.getSuggestions(extracted.component, extracted.defect);
        console.log('[EXTRACTION] Suggestions basées sur historique:', suggestions.similarIncidents, 'incidents similaires');

        // 3. Générer le rapport 5P
        const report = await this.generate5WhyReport(extracted, description);

        return {
            extracted,
            suggestions,
            report,
            timestamp: new Date().toISOString()
        };
    }
}

module.exports = ReportExtractionService;
