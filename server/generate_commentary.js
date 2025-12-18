/**
 * 🎯 ELITE Training Commentary Generator
 * Real-time agent performance monitoring with alerts & historization
 * 
 * Features:
 * - Performance analysis for all tracked agents
 * - Critical threshold alerts (latency > 20s)
 * - Daily report historization
 * - Audit trail generation
 */

const fs = require('fs');
const path = require('path');

// Configuration
const LATENCY_THRESHOLD_MS = 20000; // 20 seconds = critical
const THROUGHPUT_MIN = 15; // tokens/s minimum acceptable

const metricsPath = path.join(__dirname, 'data', 'model_metrics.json');
const reportsDir = path.join(__dirname, 'data', 'training_reports');

// Ensure reports directory exists
if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir, { recursive: true });
}

const metrics = JSON.parse(fs.readFileSync(metricsPath, 'utf8'));

// Target agents to analyze
const targetAgents = {
    'OSINT': '[ANYTHINGLLM] team-agents-o-dot-s-dot-i-dot-n-dot-t',
    'Cybersécurité': '[ANYTHINGLLM] team-cybersecurite',
    'ChatGPT-4o': '[OPENAI] chatgpt-4o-latest',
    'GPT-4o': '[OPENAI] gpt-4o',
    'GPT-4o-Mini': '[OPENAI] gpt-4o-mini',
    'Sonar-Pro': '[PERPLEXITY] sonar-pro',
    'Sonar-Reasoning': '[PERPLEXITY] sonar-reasoning'
};

// Alert system
const alerts = [];

function addAlert(level, agent, message) {
    alerts.push({
        timestamp: new Date().toISOString(),
        level,
        agent,
        message
    });
}

function generateCommentary(displayName, data) {
    if (!data) return { text: "❌ Agent non trouvé dans les métriques.", status: 'missing' };
    
    const perf = data.performance || {};
    const queries = perf.totalQueries || 0;
    const success = perf.successfulQueries || 0;
    const avgTime = perf.avgResponseTime || 0;
    const tokensPerSec = perf.tokensPerSecond || 0;
    const history = data.history?.length || 0;
    const benchmarks = data.benchmarks?.length || 0;
    
    let lines = [];
    let status = 'ok';
    
    // Header
    lines.push(`📊 RAPPORT D'ENTRAÎNEMENT: ${displayName}`);
    lines.push(`   Dernière mise à jour: ${data.lastUpdated || 'Jamais'}`);
    lines.push('');
    
    // Performance Stats
    lines.push('📈 PERFORMANCE:');
    if (queries === 0) {
        lines.push('   ⚠️ Aucune requête traitée - Agent en veille');
        lines.push('   → Action: Initier des sessions de calibration');
        status = 'inactive';
    } else {
        const successRate = ((success / queries) * 100).toFixed(1);
        lines.push(`   • Requêtes traitées: ${queries}`);
        lines.push(`   • Taux de succès: ${successRate}%`);
        lines.push(`   • Temps moyen: ${(avgTime/1000).toFixed(2)}s`);
        
        // CRITICAL ALERT: Latency threshold
        if (avgTime > LATENCY_THRESHOLD_MS) {
            lines.push(`   🚨 ALERTE CRITIQUE: Latence ${(avgTime/1000).toFixed(1)}s > seuil ${LATENCY_THRESHOLD_MS/1000}s`);
            addAlert('CRITICAL', displayName, `Latence critique: ${(avgTime/1000).toFixed(1)}s`);
            status = 'critical';
        } else if (avgTime < 8000) {
            lines.push('   ✅ Réactivité excellente');
        } else if (avgTime < 15000) {
            lines.push('   ⚡ Réactivité acceptable');
        } else {
            lines.push('   ⚠️ Latence élevée - Surveillance recommandée');
            addAlert('WARNING', displayName, `Latence élevée: ${(avgTime/1000).toFixed(1)}s`);
            status = 'warning';
        }
    }
    lines.push('');
    
    // Throughput
    if (tokensPerSec > 0) {
        lines.push('🚀 DÉBIT:');
        lines.push(`   • ${tokensPerSec.toFixed(1)} tokens/seconde`);
        if (tokensPerSec > 50) {
            lines.push('   ✅ Débit exceptionnel - Mode turbo actif');
        } else if (tokensPerSec > 30) {
            lines.push('   ⚡ Débit élevé - Performance optimale');
        } else if (tokensPerSec > THROUGHPUT_MIN) {
            lines.push('   📊 Débit standard');
        } else {
            lines.push('   ⚠️ Débit faible - Vérifier la charge');
            addAlert('WARNING', displayName, `Débit faible: ${tokensPerSec.toFixed(1)} tok/s`);
        }
        lines.push('');
    }
    
    // Training Progress
    lines.push('🎓 PROGRESSION TRAINING:');
    if (history === 0) {
        lines.push('   • Sessions: 0 (Initialization requise)');
    } else {
        lines.push(`   • Sessions enregistrées: ${history}`);
        if (history >= 5) {
            lines.push('   ✅ Apprentissage continu actif');
        } else {
            lines.push('   🌱 Phase de démarrage du training');
        }
    }
    
    if (benchmarks > 0) {
        lines.push(`   • Benchmarks effectués: ${benchmarks}`);
    }
    lines.push('');
    
    return { 
        text: lines.join('\n'), 
        status,
        metrics: { queries, success, avgTime, tokensPerSec, history, benchmarks }
    };
}

// Generate ranking
function generateRanking(results) {
    const ranking = Object.entries(results)
        .filter(([_, r]) => r.metrics && r.metrics.tokensPerSec > 0)
        .sort((a, b) => b[1].metrics.tokensPerSec - a[1].metrics.tokensPerSec);
    
    let lines = ['\n🏆 CLASSEMENT PAR PERFORMANCE:'];
    const medals = ['🥇', '🥈', '🥉'];
    
    ranking.forEach(([name, r], i) => {
        const medal = medals[i] || `${i+1}.`;
        const latencyIcon = r.metrics.avgTime < 10000 ? '✅' : r.metrics.avgTime < 20000 ? '⚡' : '🐢';
        lines.push(`   ${medal} ${name}: ${r.metrics.tokensPerSec.toFixed(1)} tok/s | ${(r.metrics.avgTime/1000).toFixed(1)}s ${latencyIcon}`);
    });
    
    return lines.join('\n');
}

// Main execution
const timestamp = new Date();
const report = [];

report.push('');
report.push('═'.repeat(70));
report.push('   📊 COMPTE-RENDU TEMPS RÉEL - TRAINING DES AGENTS');
report.push('   Date: ' + timestamp.toLocaleString('fr-CA'));
report.push('   Seuil latence critique: ' + (LATENCY_THRESHOLD_MS/1000) + 's');
report.push('═'.repeat(70));

const results = {};

Object.entries(targetAgents).forEach(([displayName, modelKey]) => {
    const data = metrics[modelKey];
    report.push('');
    report.push('─'.repeat(60));
    const result = generateCommentary(displayName, data);
    results[displayName] = result;
    report.push(result.text);
});

// Add ranking
report.push(generateRanking(results));

// Add alerts section
if (alerts.length > 0) {
    report.push('');
    report.push('═'.repeat(70));
    report.push('   🚨 ALERTES ACTIVES');
    report.push('═'.repeat(70));
    alerts.forEach(a => {
        const icon = a.level === 'CRITICAL' ? '🔴' : '🟡';
        report.push(`${icon} [${a.level}] ${a.agent}: ${a.message}`);
    });
}

// Recommendations
report.push('');
report.push('═'.repeat(70));
report.push('   🎯 RECOMMANDATIONS GLOBALES');
report.push('═'.repeat(70));
report.push('');
report.push('1. 🔍 OSINT: Activer avec des requêtes de reconnaissance ciblées');
report.push('2. 🛡️ Cybersécurité: Continuer le training - surveiller latence');
report.push('3. 🌐 Sonar-Pro: Leader débit+réactivité - Assigner tâches complexes');
report.push('4. 💭 Sonar-Reasoning: Turbo mode - Exploiter pour analyses profondes');
report.push('5. 🤖 ChatGPT-4o: Augmenter sessions pour calibration complète');
report.push('');
report.push('═'.repeat(70));

const reportText = report.join('\n');

// Output to console
console.log(reportText);

// HISTORIZATION: Save daily report
const dateStr = timestamp.toISOString().split('T')[0];
const reportFile = path.join(reportsDir, `daily_report_${dateStr}.txt`);
fs.writeFileSync(reportFile, reportText + '\n\n--- Generated: ' + timestamp.toISOString() + ' ---\n');
console.log(`\n📁 Rapport sauvegardé: ${reportFile}`);

// Summary
console.log('\n' + '═'.repeat(70));
console.log('   📋 RÉSUMÉ EXÉCUTIF');
console.log('═'.repeat(70));
console.log(`   • Agents analysés: ${Object.keys(results).length}`);
console.log(`   • Alertes actives: ${alerts.length}`);
console.log(`   • Rapport archivé: training_reports/daily_report_${dateStr}.txt`);

if (alerts.length > 0) {
    console.log('\n   ⚠️ ATTENTION: ' + alerts.length + ' alerte(s) nécessitent votre attention!');
}

// Identify best performer for next task
const activeAgents = Object.entries(results)
    .filter(([_, r]) => r.metrics && r.metrics.queries > 0)
    .sort((a, b) => {
        // Score = throughput / normalized_latency
        const scoreA = a[1].metrics.tokensPerSec / (a[1].metrics.avgTime / 10000);
        const scoreB = b[1].metrics.tokensPerSec / (b[1].metrics.avgTime / 10000);
        return scoreB - scoreA;
    });

if (activeAgents.length > 0) {
    console.log(`\n   🎯 MEILLEUR AGENT POUR TÂCHE COMPLEXE: ${activeAgents[0][0]}`);
}

console.log('');
