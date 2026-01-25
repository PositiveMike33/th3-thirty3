/**
 * Elite Hacker Scenarios Service
 * 
 * 33 scénarios de hackers élite 0.1% pour entraînement et tests
 * Intégré avec les patterns Fabric
 */

const fs = require('fs');
const path = require('path');

class EliteHackerScenariosService {
    constructor() {
        this.dataPath = path.join(__dirname, 'data', 'elite_hacker_scenarios_2026.json');
        this.scenarios = [];
        this.categoriesIndex = {};
        this.toolsIndex = {};

        this.loadScenarios();
        console.log(`[ELITE-SCENARIOS] ✅ Loaded ${this.scenarios.length} elite hacker scenarios`);
    }

    loadScenarios() {
        try {
            if (fs.existsSync(this.dataPath)) {
                const data = JSON.parse(fs.readFileSync(this.dataPath, 'utf8'));
                this.scenarios = data.scenarios || [];
                this.metadata = {
                    name: data.name,
                    version: data.version,
                    region: data.region,
                    year: data.year
                };

                this.buildIndexes();
            }
        } catch (error) {
            console.error('[ELITE-SCENARIOS] Failed to load:', error.message);
            this.scenarios = [];
        }
    }

    buildIndexes() {
        // Index par catégorie
        this.categoriesIndex = {};
        for (const scenario of this.scenarios) {
            const cat = scenario.category;
            if (!this.categoriesIndex[cat]) {
                this.categoriesIndex[cat] = [];
            }
            this.categoriesIndex[cat].push(scenario);
        }

        // Index par outil
        this.toolsIndex = {};
        for (const scenario of this.scenarios) {
            for (const tool of scenario.tools || []) {
                if (!this.toolsIndex[tool]) {
                    this.toolsIndex[tool] = [];
                }
                this.toolsIndex[tool].push(scenario);
            }
        }
    }

    /**
     * Obtenir tous les scénarios
     */
    getAllScenarios() {
        return this.scenarios;
    }

    /**
     * Obtenir un scénario par ID
     */
    getScenarioById(id) {
        return this.scenarios.find(s => s.id === parseInt(id));
    }

    /**
     * Obtenir les scénarios par catégorie
     */
    getByCategory(category) {
        return this.categoriesIndex[category] || [];
    }

    /**
     * Obtenir les catégories disponibles
     */
    getCategories() {
        return Object.keys(this.categoriesIndex).map(cat => ({
            name: cat,
            count: this.categoriesIndex[cat].length
        }));
    }

    /**
     * Obtenir les scénarios utilisant un outil spécifique
     */
    getByTool(toolId) {
        return this.toolsIndex[toolId] || [];
    }

    /**
     * Obtenir un scénario aléatoire par difficulté
     */
    getRandomByDifficulty(difficulty) {
        const filtered = this.scenarios.filter(s =>
            s.difficulty.toLowerCase() === difficulty.toLowerCase()
        );
        if (filtered.length === 0) return null;
        return filtered[Math.floor(Math.random() * filtered.length)];
    }

    /**
     * Recherche par mots-clés dans questions et titres
     */
    searchScenarios(query) {
        const q = query.toLowerCase();
        return this.scenarios.filter(s =>
            s.title.toLowerCase().includes(q) ||
            s.question.toLowerCase().includes(q) ||
            s.category.toLowerCase().includes(q)
        );
    }

    /**
     * Générer un prompt d'entraînement complet pour un scénario
     */
    generateTrainingPrompt(scenarioId) {
        const scenario = this.getScenarioById(scenarioId);
        if (!scenario) return null;

        return `# 🔥 SCÉNARIO D'ENTRAÎNEMENT ÉLITE - ${scenario.title}

## 📋 Catégorie: ${scenario.category}
## ⚡ Difficulté: ${scenario.difficulty}

---

## 🎯 QUESTION
${scenario.question}

---

## 🛠️ OUTILS RECOMMANDÉS
${scenario.tools.map(t => `• ${t}`).join('\n')}

---

## ⛓️ CHAÎNE D'ATTAQUE
${scenario.attack_chain.map((step, i) => step).join('\n')}

---

## ✅ RÉSULTAT ATTENDU
${scenario.expected_result}

---

## 🛡️ PERSPECTIVE DÉFENSIVE (Blue Team)
${scenario.defense_perspective}

---

**Région:** Québec, Canada
**Contexte:** 2026
**Avertissement:** À des fins éducatives uniquement. Tests autorisés seulement.`;
    }

    /**
     * Obtenir les statistiques des scénarios
     */
    getStats() {
        const difficulties = {};
        const toolsUsage = {};

        for (const scenario of this.scenarios) {
            // Count by difficulty
            difficulties[scenario.difficulty] = (difficulties[scenario.difficulty] || 0) + 1;

            // Count tool usage
            for (const tool of scenario.tools || []) {
                toolsUsage[tool] = (toolsUsage[tool] || 0) + 1;
            }
        }

        return {
            totalScenarios: this.scenarios.length,
            totalCategories: Object.keys(this.categoriesIndex).length,
            difficulties,
            topTools: Object.entries(toolsUsage)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
                .map(([tool, count]) => ({ tool, count })),
            metadata: this.metadata
        };
    }

    /**
     * Obtenir les scénarios recommandés basés sur un contexte
     */
    getRecommendedScenarios(context) {
        const keywords = context.toLowerCase().split(/\s+/);

        const scored = this.scenarios.map(scenario => {
            let score = 0;
            const text = `${scenario.title} ${scenario.question} ${scenario.category}`.toLowerCase();

            for (const keyword of keywords) {
                if (text.includes(keyword)) score += 1;
            }

            return { scenario, score };
        });

        return scored
            .filter(s => s.score > 0)
            .sort((a, b) => b.score - a.score)
            .slice(0, 5)
            .map(s => s.scenario);
    }
}

module.exports = EliteHackerScenariosService;
