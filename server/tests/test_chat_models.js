/**
 * TEST CHAT MODELS - Vérification complète de la connectivité des modèles Cloud
 * Ce script teste tous les modèles de chat disponibles dans llm_service.js
 */

require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });

const COLORS = {
    reset: '\x1b[0m',
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    cyan: '\x1b[36m',
    magenta: '\x1b[35m',
    blue: '\x1b[34m'
};

function log(color, symbol, message) {
    console.log(`${color}${symbol}${COLORS.reset} ${message}`);
}

// Test de connexion simple à chaque provider
async function testGeminiConnection() {
    const key = process.env.GEMINI_API_KEY;
    if (!key) {
        log(COLORS.yellow, '⚠️', 'GEMINI_API_KEY non configurée - SKIP');
        return { connected: false, reason: 'NO_KEY' };
    }

    try {
        const { GoogleGenerativeAI } = require('@google/generative-ai');
        const genAI = new GoogleGenerativeAI(key);
        const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });

        const startTime = Date.now();
        const result = await model.generateContent('Say "OK" in one word');
        const response = result.response.text();
        const latency = Date.now() - startTime;

        log(COLORS.green, '✅', `Gemini Connected - Response: "${response.substring(0, 50)}" (${latency}ms)`);
        return { connected: true, latency, response: response.substring(0, 100) };
    } catch (error) {
        log(COLORS.red, '❌', `Gemini Error: ${error.message}`);
        return { connected: false, error: error.message };
    }
}

async function testOpenAIConnection() {
    const key = process.env.OPENAI_API_KEY;
    if (!key) {
        log(COLORS.yellow, '⚠️', 'OPENAI_API_KEY non configurée - SKIP');
        return { connected: false, reason: 'NO_KEY' };
    }

    try {
        const OpenAI = require('openai');
        const client = new OpenAI({ apiKey: key });

        const startTime = Date.now();
        const completion = await client.chat.completions.create({
            model: 'gpt-4o-mini',
            messages: [{ role: 'user', content: 'Say "OK" in one word' }],
            max_tokens: 10
        });
        const latency = Date.now() - startTime;
        const response = completion.choices[0].message.content;

        log(COLORS.green, '✅', `OpenAI Connected - Response: "${response}" (${latency}ms)`);
        return { connected: true, latency, response };
    } catch (error) {
        log(COLORS.red, '❌', `OpenAI Error: ${error.message}`);
        return { connected: false, error: error.message };
    }
}

async function testClaudeConnection() {
    const key = process.env.ANTHROPIC_API_KEY;
    if (!key) {
        log(COLORS.yellow, '⚠️', 'ANTHROPIC_API_KEY non configurée - SKIP');
        return { connected: false, reason: 'NO_KEY' };
    }

    try {
        const Anthropic = require('@anthropic-ai/sdk');
        const anthropic = new Anthropic({ apiKey: key });

        const startTime = Date.now();
        const msg = await anthropic.messages.create({
            model: 'claude-3-5-sonnet-20241022',
            max_tokens: 10,
            messages: [{ role: 'user', content: 'Say "OK" in one word' }]
        });
        const latency = Date.now() - startTime;
        const response = msg.content[0].text;

        log(COLORS.green, '✅', `Claude Connected - Response: "${response}" (${latency}ms)`);
        return { connected: true, latency, response };
    } catch (error) {
        log(COLORS.red, '❌', `Claude Error: ${error.message}`);
        return { connected: false, error: error.message };
    }
}

async function testGroqConnection() {
    const key = process.env.GROQ_API_KEY;
    if (!key) {
        log(COLORS.yellow, '⚠️', 'GROQ_API_KEY non configurée - SKIP');
        return { connected: false, reason: 'NO_KEY' };
    }

    try {
        const OpenAI = require('openai');
        const client = new OpenAI({
            apiKey: key,
            baseURL: 'https://api.groq.com/openai/v1'
        });

        const startTime = Date.now();
        const completion = await client.chat.completions.create({
            model: 'llama-3.1-8b-instant',
            messages: [{ role: 'user', content: 'Say "OK" in one word' }],
            max_tokens: 10
        });
        const latency = Date.now() - startTime;
        const response = completion.choices[0].message.content;

        log(COLORS.green, '✅', `Groq Connected - Response: "${response}" (${latency}ms)`);
        return { connected: true, latency, response };
    } catch (error) {
        log(COLORS.red, '❌', `Groq Error: ${error.message}`);
        return { connected: false, error: error.message };
    }
}

async function testPerplexityConnection() {
    const key = process.env.PERPLEXITY_API_KEY;
    if (!key) {
        log(COLORS.yellow, '⚠️', 'PERPLEXITY_API_KEY non configurée - SKIP');
        return { connected: false, reason: 'NO_KEY' };
    }

    try {
        const OpenAI = require('openai');
        const client = new OpenAI({
            apiKey: key,
            baseURL: 'https://api.perplexity.ai'
        });

        const startTime = Date.now();
        const completion = await client.chat.completions.create({
            model: 'sonar',
            messages: [{ role: 'user', content: 'Say "OK" in one word' }],
            max_tokens: 10
        });
        const latency = Date.now() - startTime;
        const response = completion.choices[0].message.content;

        log(COLORS.green, '✅', `Perplexity Connected - Response: "${response.substring(0, 50)}" (${latency}ms)`);
        return { connected: true, latency, response: response.substring(0, 100) };
    } catch (error) {
        log(COLORS.red, '❌', `Perplexity Error: ${error.message}`);
        return { connected: false, error: error.message };
    }
}

async function testAnythingLLMConnection() {
    const url = process.env.ANYTHING_LLM_URL;
    const key = process.env.ANYTHING_LLM_KEY;
    if (!url || !key) {
        log(COLORS.yellow, '⚠️', 'ANYTHING_LLM_URL ou ANYTHING_LLM_KEY non configurée - SKIP');
        return { connected: false, reason: 'NO_KEY' };
    }

    try {
        const startTime = Date.now();
        const response = await fetch(`${url}/openai/models`, {
            headers: { 'Authorization': `Bearer ${key}` },
            signal: AbortSignal.timeout(5000)
        });
        const latency = Date.now() - startTime;

        if (response.ok) {
            const data = await response.json();
            const workspaces = data?.data?.length || 0;
            log(COLORS.green, '✅', `AnythingLLM Connected - ${workspaces} workspaces disponibles (${latency}ms)`);
            return { connected: true, latency, workspaces };
        } else {
            throw new Error(`HTTP ${response.status}`);
        }
    } catch (error) {
        log(COLORS.red, '❌', `AnythingLLM Error: ${error.message}`);
        return { connected: false, error: error.message };
    }
}

async function runAllTests() {
    console.log('\n' + '═'.repeat(70));
    console.log('   🧪 TH3 THIRTY3 - TEST COMPLET DES MODÈLES CHAT CLOUD');
    console.log('═'.repeat(70) + '\n');

    console.log('📋 Variables d\'environnement détectées:');
    console.log(`   GEMINI_API_KEY:      ${process.env.GEMINI_API_KEY ? '✅ Configurée' : '❌ Manquante'}`);
    console.log(`   OPENAI_API_KEY:      ${process.env.OPENAI_API_KEY ? '✅ Configurée' : '❌ Manquante'}`);
    console.log(`   ANTHROPIC_API_KEY:   ${process.env.ANTHROPIC_API_KEY ? '✅ Configurée' : '❌ Manquante'}`);
    console.log(`   GROQ_API_KEY:        ${process.env.GROQ_API_KEY ? '✅ Configurée' : '❌ Manquante'}`);
    console.log(`   PERPLEXITY_API_KEY:  ${process.env.PERPLEXITY_API_KEY ? '✅ Configurée' : '❌ Manquante'}`);
    console.log(`   ANYTHING_LLM_URL:    ${process.env.ANYTHING_LLM_URL ? '✅ Configurée' : '❌ Manquante'}`);
    console.log(`   ANYTHING_LLM_KEY:    ${process.env.ANYTHING_LLM_KEY ? '✅ Configurée' : '❌ Manquante'}`);
    console.log('');

    const results = {
        gemini: null,
        openai: null,
        claude: null,
        groq: null,
        perplexity: null,
        anythingllm: null
    };

    console.log('🔌 Test de connexion aux providers:\n');

    // Test séquentiel de chaque provider
    log(COLORS.cyan, '🌐', 'Testing Google Gemini...');
    results.gemini = await testGeminiConnection();

    log(COLORS.cyan, '🌐', 'Testing OpenAI...');
    results.openai = await testOpenAIConnection();

    log(COLORS.cyan, '🌐', 'Testing Anthropic Claude...');
    results.claude = await testClaudeConnection();

    log(COLORS.cyan, '🌐', 'Testing Groq...');
    results.groq = await testGroqConnection();

    log(COLORS.cyan, '🌐', 'Testing Perplexity...');
    results.perplexity = await testPerplexityConnection();

    log(COLORS.cyan, '🌐', 'Testing AnythingLLM...');
    results.anythingllm = await testAnythingLLMConnection();

    // Résumé final
    console.log('\n' + '═'.repeat(70));
    console.log('   📊 RÉSUMÉ DES CONNEXIONS');
    console.log('═'.repeat(70) + '\n');

    const providers = [
        { name: 'Google Gemini', key: 'gemini', emoji: '🔥' },
        { name: 'OpenAI', key: 'openai', emoji: '🟢' },
        { name: 'Anthropic Claude', key: 'claude', emoji: '🟣' },
        { name: 'Groq', key: 'groq', emoji: '⚡' },
        { name: 'Perplexity', key: 'perplexity', emoji: '🔍' },
        { name: 'AnythingLLM', key: 'anythingllm', emoji: '🤖' }
    ];

    let connected = 0;
    let total = 0;

    providers.forEach(p => {
        const result = results[p.key];
        if (result.reason === 'NO_KEY') {
            console.log(`   ${p.emoji} ${p.name.padEnd(20)} [ ⏭️  SKIP - Clé non configurée ]`);
        } else if (result.connected) {
            console.log(`   ${p.emoji} ${p.name.padEnd(20)} [ ✅ CONNECTÉ - ${result.latency}ms ]`);
            connected++;
            total++;
        } else {
            console.log(`   ${p.emoji} ${p.name.padEnd(20)} [ ❌ ERREUR - ${result.error?.substring(0, 40)}... ]`);
            total++;
        }
    });

    console.log('\n' + '─'.repeat(70));

    const configuredProviders = Object.values(results).filter(r => r.reason !== 'NO_KEY').length;

    if (connected === configuredProviders && configuredProviders > 0) {
        log(COLORS.green, '🎉', `SUCCÈS: ${connected}/${configuredProviders} providers configurés sont CONNECTÉS!`);
    } else if (connected > 0) {
        log(COLORS.yellow, '⚠️', `PARTIEL: ${connected}/${configuredProviders} providers configurés sont connectés.`);
    } else {
        log(COLORS.red, '❌', `ÉCHEC: Aucun provider connecté sur ${configuredProviders} configurés.`);
    }

    console.log('═'.repeat(70) + '\n');

    return {
        results,
        summary: {
            connected,
            total: configuredProviders,
            success: connected === configuredProviders && configuredProviders > 0
        }
    };
}

// Exécuter les tests
if (require.main === module) {
    runAllTests()
        .then((data) => {
            process.exit(data.summary.success ? 0 : 1);
        })
        .catch(err => {
            console.error('Test suite crashed:', err);
            process.exit(1);
        });
}

module.exports = { runAllTests };
