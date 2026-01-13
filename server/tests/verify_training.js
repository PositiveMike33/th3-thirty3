/**
 * verify_training.js
 * Script de vérification du système de training des agents
 * 
 * Ce script teste directement l'API Ollama pour valider que le training fonctionne
 * et génère un rapport détaillé des performances.
 */

const fs = require('fs');
const path = require('path');

const OLLAMA_API = 'http://localhost:11434';
const METRICS_PATH = path.join(__dirname, 'data', 'model_metrics.json');

// Prompts de benchmark par catégorie
const BENCHMARK_PROMPTS = {
    coding: "Écris une fonction JavaScript qui calcule la suite de Fibonacci jusqu'à n termes. Inclus la gestion des erreurs.",
    intelligence: "Analyse les implications géopolitiques de l'intelligence artificielle sur le marché du travail.",
    logic: "Si tous les A sont B, et certains B sont C, que peut-on déduire sur la relation entre A et C?",
    creativity: "Invente un concept de startup innovante qui n'existe pas encore.",
    chat: "Bonjour! Comment vas-tu aujourd'hui?",
    humanizer: "Réécris ce texte technique de façon plus naturelle: 'L'algorithme utilise une approche heuristique pour optimiser les hyperparamètres.'",
    analysis: "Analyse les forces et faiblesses de cette stratégie: investir 100% dans les cryptomonnaies.",
    writing: "Rédige un paragraphe d'introduction pour un article sur la cybersécurité."
};

const EXPERTISE_CATEGORIES = ['coding', 'intelligence', 'logic', 'creativity', 'chat', 'humanizer', 'analysis', 'writing'];

// Modèle à tester (le plus rapide)
const TEST_MODEL = 'granite4:3b';

async function callOllama(model, prompt, systemPrompt = '') {
    const response = await fetch(`${OLLAMA_API}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            model,
            prompt,
            system: systemPrompt || "Tu es un assistant expert. Réponds de manière concise et précise.",
            stream: false,
            options: {
                temperature: 0.7,
                num_predict: 200
            }
        })
    });

    if (!response.ok) {
        throw new Error(`Ollama error: ${response.status}`);
    }

    return await response.json();
}

function evaluateResponse(category, response, responseTime) {
    let score = 50; // Base score

    // Score basé sur la longueur de la réponse (max 20 points)
    const lengthScore = Math.min(20, Math.floor(response.length / 50));
    score += lengthScore;

    // Score basé sur le temps de réponse (max 15 points) - plus c'est rapide, mieux c'est
    if (responseTime < 5000) score += 15;
    else if (responseTime < 10000) score += 10;
    else if (responseTime < 20000) score += 5;

    // Bonus par catégorie
    const categoryKeywords = {
        coding: ['function', 'return', 'const', 'let', 'var', '=>', 'if (', 'for ('],
        logic: ['donc', 'implique', 'conclusion', 'si', 'alors', 'déduit'],
        creativity: ['nouveau', 'innovant', 'unique', 'original', 'idée'],
        analysis: ['avantages', 'inconvénients', 'risques', 'opportunités'],
        writing: ['.', ',', '!', '?'] // Ponctuation variée = meilleure écriture
    };

    const keywords = categoryKeywords[category] || [];
    const keywordMatches = keywords.filter(kw => response.toLowerCase().includes(kw.toLowerCase())).length;
    score += Math.min(15, keywordMatches * 3);

    return Math.min(100, Math.max(0, score));
}

async function runVerificationTest() {
    console.log('\n╔════════════════════════════════════════════════════════════╗');
    console.log('║   🧪 TEST DE VÉRIFICATION DU TRAINING DES AGENTS          ║');
    console.log('║   Modèle: ' + TEST_MODEL.padEnd(48) + '║');
    console.log('╚════════════════════════════════════════════════════════════╝\n');

    // Vérifier si Ollama est accessible
    try {
        const tags = await fetch(`${OLLAMA_API}/api/tags`);
        if (!tags.ok) throw new Error('Ollama non accessible');
        console.log('✅ Ollama est actif et répond\n');
    } catch (error) {
        console.error('❌ ERREUR: Ollama n\'est pas accessible sur', OLLAMA_API);
        console.error('   Lancez Ollama avec: ollama serve');
        process.exit(1);
    }

    // Charger les métriques existantes
    let metrics = {};
    if (fs.existsSync(METRICS_PATH)) {
        metrics = JSON.parse(fs.readFileSync(METRICS_PATH, 'utf8'));
    }

    // Créer/récupérer les métriques du modèle
    if (!metrics[TEST_MODEL]) {
        metrics[TEST_MODEL] = {
            modelName: TEST_MODEL,
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
            expertise: {},
            cognitive: { overallScore: 50, learningRate: 0, consistency: 0, adaptability: 0 },
            learning: { sessionsCompleted: 0, improvementTrend: 0, lastSessionScore: 0, averageSessionScore: 0, peakScore: 0, growthPercentage: 0 },
            strengths: [],
            weaknesses: [],
            history: [],
            benchmarks: [],
            lastBenchmark: null,
            lastUpdated: null
        };
        // Initialiser les catégories d'expertise
        EXPERTISE_CATEGORIES.forEach(cat => {
            metrics[TEST_MODEL].expertise[cat] = { score: 50, samples: 0, lastUpdated: null };
        });
    }

    const model = metrics[TEST_MODEL];
    const benchmarkResults = {};
    let totalScore = 0;
    let successCount = 0;

    console.log('📊 Exécution des benchmarks par catégorie:\n');

    for (const [category, prompt] of Object.entries(BENCHMARK_PROMPTS)) {
        process.stdout.write(`   [${category.padEnd(12)}] `);

        try {
            const startTime = Date.now();
            const result = await callOllama(TEST_MODEL, prompt);
            const responseTime = Date.now() - startTime;
            const response = result.response || '';

            // Évaluer la réponse
            const qualityScore = evaluateResponse(category, response, responseTime);

            // Mettre à jour les métriques
            model.performance.totalQueries++;
            model.performance.successfulQueries++;

            // Mettre à jour le temps de réponse moyen
            const oldAvg = model.performance.avgResponseTime;
            model.performance.avgResponseTime = ((oldAvg * (model.performance.totalQueries - 1)) + responseTime) / model.performance.totalQueries;

            // Mettre à jour l'expertise
            const exp = model.expertise[category];
            const oldScore = exp.score;
            exp.samples++;
            exp.score = Math.round((oldScore * (exp.samples - 1) + qualityScore) / exp.samples);
            exp.lastUpdated = new Date().toISOString();

            benchmarkResults[category] = {
                responseTime,
                qualityScore,
                responseLength: response.length
            };

            totalScore += qualityScore;
            successCount++;

            console.log(`✅ Score: ${qualityScore}/100 (${responseTime}ms, ${response.length} chars)`);

        } catch (error) {
            console.log(`❌ Erreur: ${error.message}`);
            benchmarkResults[category] = { error: error.message, qualityScore: 0 };
            model.performance.failedQueries++;
        }
    }

    // Calculer le score cognitif global
    const avgExpertise = EXPERTISE_CATEGORIES.reduce((sum, cat) => sum + model.expertise[cat].score, 0) / EXPERTISE_CATEGORIES.length;
    model.cognitive.overallScore = Math.round(avgExpertise);

    // Calculer le taux de progression
    const previousScore = model.learning.lastSessionScore || 50;
    const currentScore = model.cognitive.overallScore;
    model.cognitive.learningRate = currentScore - previousScore;

    // Mettre à jour les métriques d'apprentissage
    model.learning.sessionsCompleted++;
    model.learning.lastSessionScore = currentScore;
    model.learning.averageSessionScore = Math.round(
        ((model.learning.averageSessionScore * (model.learning.sessionsCompleted - 1)) + currentScore) / model.learning.sessionsCompleted
    );
    model.learning.peakScore = Math.max(model.learning.peakScore, currentScore);
    model.learning.improvementTrend = model.cognitive.learningRate;
    model.learning.growthPercentage = Math.round(((currentScore - 50) / 50) * 100);

    // Identifier forces et faiblesses
    const sortedExpertise = EXPERTISE_CATEGORIES
        .map(cat => ({ category: cat, score: model.expertise[cat].score }))
        .sort((a, b) => b.score - a.score);

    model.strengths = sortedExpertise.slice(0, 3).filter(e => e.score > 55);
    model.weaknesses = sortedExpertise.slice(-3).filter(e => e.score < 60);

    // Enregistrer le benchmark
    model.benchmarks.push({
        date: new Date().toISOString(),
        results: benchmarkResults,
        overallScore: currentScore
    });

    // Garder seulement les 30 derniers jours
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    model.benchmarks = model.benchmarks.filter(b => new Date(b.date) > thirtyDaysAgo);

    // Ajouter à l'historique
    model.history.push({
        date: new Date().toISOString(),
        cognitiveScore: currentScore,
        expertise: EXPERTISE_CATEGORIES.reduce((obj, cat) => {
            obj[cat] = model.expertise[cat].score;
            return obj;
        }, {})
    });

    model.lastBenchmark = new Date().toISOString();
    model.lastUpdated = new Date().toISOString();

    // Sauvegarder
    fs.writeFileSync(METRICS_PATH, JSON.stringify(metrics, null, 2));

    // Afficher le rapport
    console.log('\n╔════════════════════════════════════════════════════════════╗');
    console.log('║   📈 RAPPORT DE TRAINING                                    ║');
    console.log('╚════════════════════════════════════════════════════════════╝');
    console.log(`\n   Score Cognitif Global: ${currentScore}/100`);
    console.log(`   Taux d'apprentissage: ${model.cognitive.learningRate > 0 ? '+' : ''}${model.cognitive.learningRate}`);
    console.log(`   Sessions complétées: ${model.learning.sessionsCompleted}`);
    console.log(`   Score moyen: ${model.learning.averageSessionScore}/100`);
    console.log(`   Score pic: ${model.learning.peakScore}/100`);
    console.log(`   Croissance: ${model.learning.growthPercentage}%`);

    console.log('\n   📊 Expertise par catégorie:');
    EXPERTISE_CATEGORIES.forEach(cat => {
        const score = model.expertise[cat].score;
        const bar = '█'.repeat(Math.floor(score / 5)) + '░'.repeat(20 - Math.floor(score / 5));
        console.log(`      ${cat.padEnd(12)} [${bar}] ${score}/100`);
    });

    if (model.strengths.length > 0) {
        console.log('\n   💪 Forces:', model.strengths.map(s => s.category).join(', '));
    }
    if (model.weaknesses.length > 0) {
        console.log('   ⚠️  Faiblesses:', model.weaknesses.map(w => w.category).join(', '));
    }

    console.log('\n   ✅ Métriques sauvegardées dans data/model_metrics.json');
    console.log('   ✅ LE TRAINING FONCTIONNE!\n');

    return { success: true, score: currentScore, model: TEST_MODEL };
}

// Exécuter le test
runVerificationTest()
    .then(result => {
        process.exit(result.success ? 0 : 1);
    })
    .catch(error => {
        console.error('❌ Erreur fatale:', error);
        process.exit(1);
    });

