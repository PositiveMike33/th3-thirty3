/**
 * Model Evolution Test
 * Tests all trained models to compare their WiFi security expertise
 */

const TEST_SCENARIO = {
    scenario: "Un client se déconnecte de façon répétée du réseau WiFi corporate toutes les 10 secondes. L'administrateur observe dans les logs de l'AP des messages 'deauthentication reason code 7'. Le signal est bon (-50 dBm) et d'autres clients sur le même AP fonctionnent normalement.",
    question: `En tant qu'expert sécurité WiFi, analyse cette situation:

1. Quelle est la cause la plus probable de ce comportement?
2. Comment confirmer ton diagnostic avec des outils spécifiques?
3. Quelles commandes exactes utiliserais-tu pour détecter l'attaque?
4. Quelles contre-mesures immédiates recommandes-tu?
5. Quelle configuration long-terme empêcherait cette attaque?

Réponds de manière technique et détaillée avec des commandes concrètes.`,
    expected_keywords: ['deauth', 'attack', 'aireplay', 'aircrack', 'wireshark', 'pmf', '802.11w', 'kismet', 'wids'],
    min_score: 70
};

async function testModel(modelName) {
    const startTime = Date.now();
    
    try {
        const response = await fetch('http://localhost:3000/api/wifi-training/train', {
            method: 'POST',
            headers: {
                'Authorization': 'Bearer admin',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: modelName,
                type: 'attack'
            })
        });
        
        const result = await response.json();
        const responseTime = Date.now() - startTime;
        
        return {
            model: modelName,
            success: result.success,
            score: result.score || 0,
            responseTime,
            feedback: result.feedback || [],
            preview: result.response ? result.response.substring(0, 300) : 'No response'
        };
    } catch (error) {
        return {
            model: modelName,
            success: false,
            error: error.message,
            responseTime: Date.now() - startTime
        };
    }
}

async function runComparison() {
    console.log('\n========================================');
    console.log('   MODEL EVOLUTION TEST - WiFi Security');
    console.log('========================================\n');
    
    const models = [
        'granite3.1-moe:1b',
        'mistral:7b-instruct',
        'qwen2.5-coder:7b'
    ];
    
    console.log('Testing scenario:', TEST_SCENARIO.scenario.substring(0, 100) + '...\n');
    
    const results = [];
    
    for (const model of models) {
        console.log(`Testing ${model}...`);
        const result = await testModel(model);
        results.push(result);
        
        if (result.success) {
            console.log(`  ✓ Score: ${result.score}/100 (${result.responseTime}ms)`);
            if (result.feedback && result.feedback.length > 0) {
                result.feedback.forEach(f => console.log(`    - ${f}`));
            }
        } else {
            console.log(`  ✗ Error: ${result.error}`);
        }
        console.log('');
    }
    
    // Ranking
    console.log('\n========================================');
    console.log('   RANKING');
    console.log('========================================\n');
    
    const sorted = results.filter(r => r.success).sort((a, b) => b.score - a.score);
    sorted.forEach((r, i) => {
        console.log(`${i + 1}. ${r.model}: ${r.score}/100 (${(r.responseTime/1000).toFixed(1)}s)`);
    });
    
    // Get global stats
    try {
        const statsResponse = await fetch('http://localhost:3000/api/wifi-training/stats', {
            headers: { 'Authorization': 'Bearer admin' }
        });
        const stats = await statsResponse.json();
        
        console.log('\n========================================');
        console.log('   GLOBAL TRAINING STATS');
        console.log('========================================\n');
        console.log(`Expertise Score: ${stats.expertiseScore}/100`);
        console.log(`Total Sessions: ${stats.sessionsCompleted}`);
        console.log(`Total Iterations: ${stats.totalIterations}`);
    } catch (e) {
        console.log('Could not fetch stats:', e.message);
    }
    
    return results;
}

runComparison();
