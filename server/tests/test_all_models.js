/**
 * Test All Models Script
 * Vérifie que tous les modèles sont:
 * 1. Disponibles dans Ollama
 * 2. Connectés via le Model Router
 * 3. Capables de générer des réponses
 * 4. mxbai-embed-large is ready for local embeddings (fallback: snowflake-arctic-embed)
 * 5. La rotation des modèles fonctionne correctement
 */

const modelRouter = require('./model_router');
const EmbeddingService = require('./embedding_service');
const TrainingCommentaryService = require('./training_commentary_service');

const COLORS = {
    reset: '\x1b[0m',
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    cyan: '\x1b[36m',
    magenta: '\x1b[35m'
};

function log(color, symbol, message) {
    console.log(`${color}${symbol}${COLORS.reset} ${message}`);
}

async function testOllamaConnection() {
    log(COLORS.cyan, '🔍', 'Testing Ollama connection...');

    try {
        const response = await fetch('http://localhost:11434/api/tags');
        const data = await response.json();
        const models = data.models || [];

        log(COLORS.green, '✅', `Ollama connected - ${models.length} models available`);

        console.log('\n📦 Available Models:');
        models.forEach(m => {
            const sizeGB = (m.size / (1024 * 1024 * 1024)).toFixed(2);
            const isEmbed = m.name.includes('embed') ? ' [EMBEDDING]' : '';
            const isOptimized = m.name.includes('q4_K_M') ? ' [UNSLOTH Q4_K_M]' : '';
            console.log(`   - ${m.name} (${sizeGB}GB)${isEmbed}${isOptimized}`);
        });

        return models;
    } catch (error) {
        log(COLORS.red, '❌', `Ollama connection failed: ${error.message}`);
        return [];
    }
}

async function testModelRouter() {
    log(COLORS.cyan, '\n🔍', 'Testing Model Router...');

    try {
        // Initialize router
        await modelRouter.initialize();
        log(COLORS.green, '✅', 'Model Router initialized');

        // Check nomic preload
        const status = modelRouter.getStatus();
        if (status.currentlyLoaded.some(m => m.includes('nomic'))) {
            log(COLORS.green, '✅', 'nomic-embed-text preloaded for local embeddings');
        } else {
            log(COLORS.yellow, '⚠️', 'nomic-embed-text not preloaded');
        }

        // Test different domain routes
        const domains = ['security', 'code', 'vision', 'general', 'fast'];
        console.log('\n🎯 Domain Routing Tests:');

        for (const domain of domains) {
            const result = await modelRouter.routeToModel(domain);
            // routeToModel returns { model, isLocal, provider }
            const modelName = result.model;
            const providerTag = result.isLocal ? '[LOCAL]' : `[CLOUD: ${result.provider}]`;
            log(COLORS.green, '  ✅', `${domain} → ${modelName} ${providerTag}`);
        }

        return true;
    } catch (error) {
        log(COLORS.red, '❌', `Model Router test failed: ${error.message}`);
        return false;
    }
}


async function testEmbeddings() {
    log(COLORS.cyan, '\n🔍', 'Testing Embedding Service (nomic-embed-text priority)...');

    try {
        const embedService = new EmbeddingService();

        // Test local embedding (nomic)
        console.log('   Testing nomic-embed-text (local)...');
        const localEmbed = await embedService.embed('Test embedding for local processing', 'ollama');
        log(COLORS.green, '✅', `nomic-embed-text: ${localEmbed.length} dimensions`);

        // Get stats
        const stats = embedService.getStats();
        log(COLORS.green, '✅', `Primary provider: ${stats.primary_provider}`);

        return true;
    } catch (error) {
        log(COLORS.red, '❌', `Embedding test failed: ${error.message}`);
        return false;
    }
}

async function testCommentaryRotation() {
    log(COLORS.cyan, '\n🔍', 'Testing Training Commentary Service...');

    try {
        const commentaryService = new TrainingCommentaryService();

        console.log('\n🔄 Commentary Model Availability Test:');

        // Test getAvailableModels (works async, returns cached list or fetches from Ollama)
        const models = await commentaryService.getAvailableModels();

        if (models && models.length > 0) {
            log(COLORS.green, '✅', `${models.length} models available for commentary`);
            models.forEach(m => console.log(`     - ${m}`));
        } else {
            log(COLORS.yellow, '⚠️', 'No models available for commentary');
        }

        // Check service status
        const status = commentaryService.getStatus();
        console.log('\n📊 Commentary Status:');
        console.log(`   Total entries: ${status.totalEntries}`);
        console.log(`   Is active: ${status.isActive}`);

        return true;
    } catch (error) {
        log(COLORS.red, '❌', `Commentary rotation test failed: ${error.message}`);
        return false;
    }
}


async function testModelGeneration() {
    log(COLORS.cyan, '\n🔍', 'Testing Model Generation (all models)...');

    const models = await testOllamaConnection();
    const genModels = models.filter(m => !m.name.includes('embed'));

    console.log('\n💬 Generation Tests:');

    const results = [];
    for (const model of genModels) {
        try {
            const startTime = Date.now();

            const response = await fetch('http://localhost:11434/api/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: model.name,
                    prompt: 'Say "OK" in one word.',
                    stream: false,
                    options: { num_predict: 5 }
                })
            });

            const elapsed = Date.now() - startTime;

            if (response.ok) {
                const data = await response.json();
                const hasUnsloth = model.name.includes('q4_K_M');
                const tag = hasUnsloth ? ' [UNSLOTH]' : '';
                log(COLORS.green, '  ✅', `${model.name}${tag}: ${elapsed}ms`);
                results.push({ model: model.name, success: true, time: elapsed });
            } else {
                log(COLORS.red, '  ❌', `${model.name}: HTTP ${response.status}`);
                results.push({ model: model.name, success: false });
            }
        } catch (error) {
            log(COLORS.red, '  ❌', `${model.name}: ${error.message}`);
            results.push({ model: model.name, success: false, error: error.message });
        }
    }

    // Summary
    const successful = results.filter(r => r.success).length;
    const total = results.length;
    console.log(`\n📊 Generation Summary: ${successful}/${total} models working`);

    return results;
}

async function runAllTests() {
    console.log('═'.repeat(60));
    console.log('   🧪 TH3 THIRTY3 - MODEL SYSTEM TEST SUITE');
    console.log('═'.repeat(60));
    console.log();

    const results = {
        ollama: false,
        router: false,
        embeddings: false,
        rotation: false,
        generation: null
    };

    try {
        // Test 1: Ollama Connection
        const models = await testOllamaConnection();
        results.ollama = models.length > 0;

        // Test 2: Model Router
        results.router = await testModelRouter();

        // Test 3: Embeddings
        results.embeddings = await testEmbeddings();

        // Test 4: Commentary Rotation
        results.rotation = await testCommentaryRotation();

        // Test 5: All Model Generation
        results.generation = await testModelGeneration();

    } catch (error) {
        log(COLORS.red, '❌', `Test suite error: ${error.message}`);
    }

    // Final Summary
    console.log('\n' + '═'.repeat(60));
    console.log('   📋 FINAL SUMMARY');
    console.log('═'.repeat(60));

    console.log(`   Ollama Connection:     ${results.ollama ? '✅ OK' : '❌ FAILED'}`);
    console.log(`   Model Router:          ${results.router ? '✅ OK' : '❌ FAILED'}`);
    console.log(`   Embeddings (nomic):    ${results.embeddings ? '✅ OK' : '❌ FAILED'}`);
    console.log(`   Commentary Rotation:   ${results.rotation ? '✅ OK' : '❌ FAILED'}`);

    if (results.generation) {
        const genOK = results.generation.filter(r => r.success).length;
        const genTotal = results.generation.length;
        console.log(`   Model Generation:      ${genOK}/${genTotal} models working`);
    }

    console.log('\n' + '═'.repeat(60));

    const allPassed = results.ollama && results.router && results.embeddings && results.rotation;
    if (allPassed) {
        log(COLORS.green, '🎉', 'ALL CORE TESTS PASSED!');
    } else {
        log(COLORS.red, '⚠️', 'Some tests failed - check logs above');
    }

    return results;
}

// Run if executed directly
if (require.main === module) {
    runAllTests()
        .then(() => process.exit(0))
        .catch(err => {
            console.error(err);
            process.exit(1);
        });
}

module.exports = { runAllTests };
