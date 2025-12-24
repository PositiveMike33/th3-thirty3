/**
 * init_anythingllm_agents.js
 * Initialise les métriques pour les agents AnythingLLM spécialisés
 * 
 * Agents:
 * - OSINT: Spécialisé en recherche de renseignements
 * - Cybersécurité: Expert en sécurité informatique
 * - Agent-Thirty3: Agent principal polyvalent
 */

const fs = require('fs');
const path = require('path');

const METRICS_PATH = path.join(__dirname, 'data', 'model_metrics.json');

const AGENTS_TO_ADD = [
    {
        name: '[ANYTHINGLLM] osint',
        displayName: 'OSINT Agent',
        specialization: 'intelligence',
        expertise: {
            coding: { score: 45, samples: 0, lastUpdated: null },
            intelligence: { score: 85, samples: 1, lastUpdated: new Date().toISOString() },
            logic: { score: 70, samples: 0, lastUpdated: null },
            creativity: { score: 55, samples: 0, lastUpdated: null },
            chat: { score: 60, samples: 0, lastUpdated: null },
            humanizer: { score: 50, samples: 0, lastUpdated: null },
            analysis: { score: 90, samples: 1, lastUpdated: new Date().toISOString() },
            writing: { score: 65, samples: 0, lastUpdated: null }
        },
        description: 'Agent spécialisé en Open Source Intelligence (OSINT)'
    },
    {
        name: '[ANYTHINGLLM] cybersecurite',
        displayName: 'Cybersécurité Agent',
        specialization: 'analysis',
        expertise: {
            coding: { score: 80, samples: 1, lastUpdated: new Date().toISOString() },
            intelligence: { score: 75, samples: 0, lastUpdated: null },
            logic: { score: 85, samples: 1, lastUpdated: new Date().toISOString() },
            creativity: { score: 45, samples: 0, lastUpdated: null },
            chat: { score: 55, samples: 0, lastUpdated: null },
            humanizer: { score: 40, samples: 0, lastUpdated: null },
            analysis: { score: 95, samples: 1, lastUpdated: new Date().toISOString() },
            writing: { score: 60, samples: 0, lastUpdated: null }
        },
        description: 'Agent expert en cybersécurité et analyse de vulnérabilités'
    },
    {
        name: '[ANYTHINGLLM] agent-thirty3',
        displayName: 'Agent Thirty3',
        specialization: 'chat',
        expertise: {
            coding: { score: 70, samples: 1, lastUpdated: new Date().toISOString() },
            intelligence: { score: 75, samples: 0, lastUpdated: null },
            logic: { score: 72, samples: 0, lastUpdated: null },
            creativity: { score: 78, samples: 1, lastUpdated: new Date().toISOString() },
            chat: { score: 88, samples: 1, lastUpdated: new Date().toISOString() },
            humanizer: { score: 82, samples: 1, lastUpdated: new Date().toISOString() },
            analysis: { score: 70, samples: 0, lastUpdated: null },
            writing: { score: 75, samples: 0, lastUpdated: null }
        },
        description: 'Agent principal Th3 Thirty3 - polyvalent et adaptatif'
    }
];

function calculateCognitiveScore(expertise) {
    const categories = Object.keys(expertise);
    const sum = categories.reduce((acc, cat) => acc + expertise[cat].score, 0);
    return Math.round(sum / categories.length);
}

function identifyStrengthsWeaknesses(expertise) {
    const labels = {
        coding: '💻 Codage',
        intelligence: '🧠 Intelligence',
        logic: '📐 Logique',
        creativity: '🎨 Créativité',
        chat: '💬 Chat',
        humanizer: '🤝 Humanisation',
        analysis: '🔍 Analyse',
        writing: '✍️ Rédaction'
    };
    
    const sorted = Object.entries(expertise)
        .map(([cat, data]) => ({ category: cat, score: data.score, label: labels[cat] }))
        .sort((a, b) => b.score - a.score);
    
    return {
        strengths: sorted.slice(0, 3).filter(e => e.score > 60),
        weaknesses: sorted.slice(-3).filter(e => e.score < 65)
    };
}

async function initializeAgents() {
    console.log('\n╔════════════════════════════════════════════════════════════╗');
    console.log('║   🤖 INITIALISATION DES AGENTS ANYTHINGLLM                 ║');
    console.log('╚════════════════════════════════════════════════════════════╝\n');

    // Charger les métriques existantes
    let metrics = {};
    if (fs.existsSync(METRICS_PATH)) {
        metrics = JSON.parse(fs.readFileSync(METRICS_PATH, 'utf8'));
        console.log(`📂 Métriques existantes chargées: ${Object.keys(metrics).length} modèles`);
    }

    let addedCount = 0;
    let updatedCount = 0;

    for (const agent of AGENTS_TO_ADD) {
        const exists = !!metrics[agent.name];
        
        if (exists) {
            console.log(`   ⚡ ${agent.displayName} existe déjà, mise à jour des profils...`);
            // Update expertise if it's all at default 50
            const currentExpertise = metrics[agent.name].expertise;
            const allDefault = Object.values(currentExpertise).every(e => e.score === 50);
            if (allDefault) {
                metrics[agent.name].expertise = agent.expertise;
                const sw = identifyStrengthsWeaknesses(agent.expertise);
                metrics[agent.name].strengths = sw.strengths;
                metrics[agent.name].weaknesses = sw.weaknesses;
                metrics[agent.name].cognitive.overallScore = calculateCognitiveScore(agent.expertise);
                updatedCount++;
            }
        } else {
            console.log(`   ✅ Ajout de ${agent.displayName}...`);
            
            const cognitiveScore = calculateCognitiveScore(agent.expertise);
            const sw = identifyStrengthsWeaknesses(agent.expertise);
            
            metrics[agent.name] = {
                modelName: agent.name,
                displayName: agent.displayName,
                description: agent.description,
                specialization: agent.specialization,
                createdAt: new Date().toISOString(),
                performance: {
                    totalQueries: 0,
                    successfulQueries: 0,
                    failedQueries: 0,
                    avgResponseTime: 0,
                    minResponseTime: null,
                    maxResponseTime: 0,
                    tokensPerSecond: 0,
                    totalTokensGenerated: 0
                },
                expertise: agent.expertise,
                cognitive: {
                    overallScore: cognitiveScore,
                    learningRate: 0,
                    consistency: 0,
                    adaptability: 0
                },
                learning: {
                    sessionsCompleted: 0,
                    improvementTrend: 0,
                    lastSessionScore: cognitiveScore,
                    averageSessionScore: cognitiveScore,
                    peakScore: cognitiveScore,
                    growthPercentage: Math.round(((cognitiveScore - 50) / 50) * 100)
                },
                strengths: sw.strengths,
                weaknesses: sw.weaknesses,
                history: [{
                    date: new Date().toISOString(),
                    cognitiveScore: cognitiveScore,
                    expertise: Object.fromEntries(
                        Object.entries(agent.expertise).map(([k, v]) => [k, v.score])
                    )
                }],
                benchmarks: [],
                lastBenchmark: null,
                lastUpdated: new Date().toISOString()
            };
            addedCount++;
        }
    }

    // Sauvegarder
    fs.writeFileSync(METRICS_PATH, JSON.stringify(metrics, null, 2));

    console.log(`\n📊 Résultat:`);
    console.log(`   ✅ Agents ajoutés: ${addedCount}`);
    console.log(`   ⚡ Agents mis à jour: ${updatedCount}`);
    console.log(`   📁 Total modèles: ${Object.keys(metrics).length}`);
    console.log(`\n✅ Métriques sauvegardées dans data/model_metrics.json\n`);

    // Afficher les profils
    console.log('📊 Profils des agents:');
    for (const agent of AGENTS_TO_ADD) {
        const m = metrics[agent.name];
        console.log(`\n   🤖 ${m.displayName || m.modelName}`);
        console.log(`      Score Cognitif: ${m.cognitive.overallScore}/100`);
        console.log(`      Spécialisation: ${m.specialization}`);
        if (m.strengths.length > 0) {
            console.log(`      Forces: ${m.strengths.map(s => s.label).join(', ')}`);
        }
    }
}

initializeAgents().catch(console.error);
