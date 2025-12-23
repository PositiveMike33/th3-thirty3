#!/usr/bin/env node
/**
 * Auto-Continue Training Script
 * Entraînement continu automatique des modèles locaux sur données aléatoires
 * Utilise le système Golden Ratio (φ=1.618) pour croissance exponentielle
 * 
 * Usage: node auto_train.js [model] [interval_minutes]
 */

const API_BASE = 'http://localhost:3000/api/wifi-training';
const AUTH_HEADER = { 'Authorization': 'Bearer admin', 'Content-Type': 'application/json' };

// Configuration
const CONFIG = {
    models: ['uandinotai/dolphin-uncensored:latest', 'mistral:7b-instruct', 'qwen2.5-coder:7b'],
    iterationsPerSession: 5,
    pauseBetweenSessions: 60000, // 1 minute
    pauseBetweenModels: 30000,   // 30 seconds
    maxContinuousSessions: 100,
    targetExpertise: 95
};

// Statistics
let stats = {
    totalSessions: 0,
    totalIterations: 0,
    startTime: new Date(),
    modelStats: {}
};

async function fetchWithTimeout(url, options, timeout = 120000) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    try {
        const response = await fetch(url, { ...options, signal: controller.signal });
        clearTimeout(id);
        return response;
    } catch (error) {
        clearTimeout(id);
        throw error;
    }
}

async function getStats() {
    try {
        const response = await fetchWithTimeout(`${API_BASE}/stats`, { headers: AUTH_HEADER });
        return await response.json();
    } catch (error) {
        console.error('[ERROR] Failed to get stats:', error.message);
        return null;
    }
}

async function runTrainingSession(model, iterations = 5) {
    console.log(`\n[TRAINING] ${model} - ${iterations} iterations`);
    
    try {
        const response = await fetchWithTimeout(
            `${API_BASE}/session`,
            {
                method: 'POST',
                headers: AUTH_HEADER,
                body: JSON.stringify({ model, iterations })
            },
            600000 // 10 minute timeout for full session
        );
        
        const result = await response.json();
        
        if (result.averageScore) {
            console.log(`[SUCCESS] ${model}: Avg ${result.averageScore.toFixed(1)}/100 | Expertise: ${result.expertiseScore}`);
            
            // Update stats
            if (!stats.modelStats[model]) {
                stats.modelStats[model] = { sessions: 0, totalScore: 0, bestScore: 0 };
            }
            stats.modelStats[model].sessions++;
            stats.modelStats[model].totalScore += result.averageScore;
            if (result.averageScore > stats.modelStats[model].bestScore) {
                stats.modelStats[model].bestScore = result.averageScore;
            }
            
            return result;
        } else {
            console.log(`[WARN] ${model}: Training completed but no score returned`);
            return null;
        }
    } catch (error) {
        console.error(`[ERROR] ${model}: ${error.message}`);
        return null;
    }
}

async function getModelOptimization(model) {
    try {
        const response = await fetchWithTimeout(
            `${API_BASE}/optimization/${encodeURIComponent(model)}`,
            { headers: AUTH_HEADER }
        );
        return await response.json();
    } catch (error) {
        return null;
    }
}

async function getModelEliteStatus(model) {
    try {
        const response = await fetchWithTimeout(
            `${API_BASE}/elite/${encodeURIComponent(model)}`,
            { headers: AUTH_HEADER }
        );
        return await response.json();
    } catch (error) {
        return null;
    }
}

function printBanner() {
    console.log(`
╔═══════════════════════════════════════════════════════════════╗
║     TH3 THIRTY3 - AUTO CONTINUOUS TRAINING                   ║
║     Golden Ratio Memory System (φ = 1.618)                   ║
║     Elite Cybernetic Knowledge Development                   ║
╚═══════════════════════════════════════════════════════════════╝
    `);
}

function printStats() {
    const runtime = Math.round((new Date() - stats.startTime) / 60000);
    
    console.log(`
╔═══════════════════════════════════════════════════════════════╗
║  SESSION STATS                                                ║
╠═══════════════════════════════════════════════════════════════╣
║  Total Sessions: ${String(stats.totalSessions).padEnd(44)}║
║  Total Iterations: ${String(stats.totalIterations).padEnd(42)}║
║  Runtime: ${String(runtime + ' minutes').padEnd(51)}║
╠═══════════════════════════════════════════════════════════════╣`);
    
    for (const [model, data] of Object.entries(stats.modelStats)) {
        const avgScore = data.sessions > 0 ? (data.totalScore / data.sessions).toFixed(1) : 0;
        console.log(`║  ${model.padEnd(25)} Avg: ${avgScore}/100  Best: ${data.bestScore.toFixed(1)}/100 ║`);
    }
    
    console.log(`╚═══════════════════════════════════════════════════════════════╝`);
}

async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function runContinuousTraining() {
    printBanner();
    
    console.log('[INFO] Starting continuous training...');
    console.log(`[CONFIG] Models: ${CONFIG.models.join(', ')}`);
    console.log(`[CONFIG] Iterations per session: ${CONFIG.iterationsPerSession}`);
    console.log(`[CONFIG] Target expertise: ${CONFIG.targetExpertise}`);
    console.log('');
    
    let sessionCount = 0;
    let expertiseReached = false;
    
    while (sessionCount < CONFIG.maxContinuousSessions && !expertiseReached) {
        sessionCount++;
        
        console.log(`\n${'='.repeat(60)}`);
        console.log(`SESSION ${sessionCount}/${CONFIG.maxContinuousSessions}`);
        console.log(`${'='.repeat(60)}`);
        
        // Train each model
        for (const model of CONFIG.models) {
            const result = await runTrainingSession(model, CONFIG.iterationsPerSession);
            
            if (result) {
                stats.totalSessions++;
                stats.totalIterations += CONFIG.iterationsPerSession;
                
                // Check optimization status
                const opt = await getModelOptimization(model);
                if (opt && opt.optimization) {
                    console.log(`    [OPT] ${opt.optimization.vram.efficiencyTier.icon} ${opt.optimization.optimizationLevel} - VRAM: ${opt.optimization.vram.requiredVRAM}GB (saved ${opt.optimization.vram.savingsPercent}%)`);
                }
                
                // Check elite status
                const elite = await getModelEliteStatus(model);
                if (elite && elite.eliteStatus) {
                    console.log(`    [ELITE] Level ${elite.eliteStatus.level.level}: ${elite.eliteStatus.level.name} | Power: ${elite.eliteStatus.cyberneticPower}`);
                }
            }
            
            // Pause between models
            if (model !== CONFIG.models[CONFIG.models.length - 1]) {
                await sleep(CONFIG.pauseBetweenModels);
            }
        }
        
        // Check overall expertise
        const globalStats = await getStats();
        if (globalStats && globalStats.expertiseScore >= CONFIG.targetExpertise) {
            console.log(`\n[SUCCESS] Target expertise ${CONFIG.targetExpertise} reached! Current: ${globalStats.expertiseScore}`);
            expertiseReached = true;
        }
        
        // Print stats every 5 sessions
        if (sessionCount % 5 === 0) {
            printStats();
        }
        
        // Pause between sessions
        if (!expertiseReached && sessionCount < CONFIG.maxContinuousSessions) {
            console.log(`\n[PAUSE] Next session in ${CONFIG.pauseBetweenSessions / 1000}s...`);
            await sleep(CONFIG.pauseBetweenSessions);
        }
    }
    
    // Final stats
    console.log('\n');
    console.log('═'.repeat(60));
    console.log('TRAINING COMPLETE');
    console.log('═'.repeat(60));
    printStats();
    
    // Get final global stats
    const finalStats = await getStats();
    if (finalStats) {
        console.log(`\nFinal Expertise Score: ${finalStats.expertiseScore}/100`);
        console.log(`Total Tracked Sessions: ${finalStats.sessionsCompleted}`);
        console.log(`Total Tracked Iterations: ${finalStats.totalIterations}`);
    }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
    console.log('\n\n[INTERRUPT] Training interrupted by user');
    printStats();
    process.exit(0);
});

// Run
runContinuousTraining().catch(error => {
    console.error('[FATAL]', error);
    process.exit(1);
});
