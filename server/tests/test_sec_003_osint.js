/**
 * TEST-SEC-003: OSINT Expert Agent Analysis
 * Test des agents OSINT spécialisés avec analyse LLM
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

// Mock OSINT data for testing
const MOCK_SHERLOCK_RESULT = {
    username: "target_user123",
    found_on: ["GitHub", "Twitter", "LinkedIn", "Reddit", "Instagram"],
    not_found: ["Facebook", "TikTok"],
    profiles: {
        GitHub: "https://github.com/target_user123",
        Twitter: "https://twitter.com/target_user123",
        LinkedIn: "https://linkedin.com/in/target_user123"
    }
};

const MOCK_WHOIS_RESULT = {
    domain: "example-target.com",
    registrar: "GoDaddy",
    created: "2019-03-15",
    expires: "2025-03-15",
    nameservers: ["ns1.cloudflare.com", "ns2.cloudflare.com"],
    privacy_protected: true,
    registrant_country: "US"
};

async function runTest() {
    console.log('\n=== TEST-SEC-003: OSINT Expert Agent Analysis ===\n');
    
    const results = { steps: [], success: false };
    
    // STEP 1: Test LLM Sherlock Analysis Persona
    console.log('[STEP 1] Analyse Sherlock avec persona Ghost...');
    try {
        const LLMService = require('../llm_service');
        const llmService = new LLMService();
        
        const models = await llmService.listModels('local');
        if (!models.local || models.local.length === 0 || models.local[0].includes('Offline')) {
            throw new Error('No local models available');
        }
        
        const analysis = await llmService.analyzeOsintResult(
            'sherlock',
            JSON.stringify(MOCK_SHERLOCK_RESULT, null, 2)
        );
        
        console.log('  [OK] Analyse Sherlock complétée');
        console.log('  [PREVIEW]', (analysis || '').substring(0, 200) + '...');
        results.steps.push({ step: 1, success: true, response_length: analysis?.length || 0 });
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 1, success: false, error: error.message });
    }

    // STEP 2: Test LLM WHOIS Analysis Persona
    console.log('\n[STEP 2] Analyse WHOIS avec persona Architect...');
    try {
        const LLMService = require('../llm_service');
        const llmService = new LLMService();
        
        const analysis = await llmService.analyzeOsintResult(
            'whois',
            JSON.stringify(MOCK_WHOIS_RESULT, null, 2)
        );
        
        console.log('  [OK] Analyse WHOIS complétée');
        console.log('  [PREVIEW]', (analysis || '').substring(0, 200) + '...');
        results.steps.push({ step: 2, success: true, response_length: analysis?.length || 0 });
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 2, success: false, error: error.message });
    }

    // STEP 3: Test Custom Quebec Cyber Expert Persona
    console.log('\n[STEP 3] Analyse personnalisée Quebec Cyber Expert...');
    try {
        const LLMService = require('../llm_service');
        const llmService = new LLMService();
        
        const customPersona = `Tu es un expert québécois en OSINT. Tu analyses les données de reconnaissance.
Tu parles en français québécois avec des expressions locales. Tu es direct et efficace.`;
        
        const combinedData = {
            sherlock: MOCK_SHERLOCK_RESULT,
            whois: MOCK_WHOIS_RESULT,
            summary: "Cible identifiée sur multiples plateformes avec infrastructure protégée par Cloudflare"
        };
        
        const prompt = `Analyse cette cible OSINT complète:

${JSON.stringify(combinedData, null, 2)}

Fournis:
1. Résumé de la présence numérique
2. Points d'intérêt pour investigation
3. Recommandations pour approfondir`;

        const response = await llmService.generateResponse(
            prompt,
            null,
            'local',
            null, // auto-select model
            customPersona
        );
        
        console.log('  [OK] Analyse personnalisée complétée');
        console.log('  [PREVIEW]', (response || '').substring(0, 300) + '...');
        results.steps.push({ step: 3, success: true, response_length: response?.length || 0 });
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 3, success: false, error: error.message });
    }

    // STEP 4: Test OSINT Service Tools List
    console.log('\n[STEP 4] Liste des outils OSINT disponibles...');
    try {
        const OsintService = require('../osint_service');
        const osintService = new OsintService();
        
        const tools = osintService.getTools();
        console.log('  [OK] Outils OSINT chargés:', tools.length);
        tools.slice(0, 5).forEach(t => {
            console.log(`    - ${t.id}: ${t.name}`);
        });
        
        results.steps.push({ step: 4, success: true, tools_count: tools.length });
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 4, success: false, error: error.message });
    }

    // Summary
    const successCount = results.steps.filter(s => s.success).length;
    results.success = successCount >= 3;
    
    console.log('\n=== RÉSUMÉ ===');
    results.steps.forEach(s => {
        console.log(`Step ${s.step}: ${s.success ? 'PASS' : 'FAIL'}`);
    });
    console.log(`\nRésultat global: ${results.success ? 'PASS' : 'FAIL'} (${successCount}/4 steps)`);
    console.log('==============\n');

    return results;
}

runTest()
    .then(async r => {
        await new Promise(resolve => setTimeout(resolve, 500));
        process.exit(r.success ? 0 : 1);
    })
    .catch(async e => {
        console.error('Test failed:', e);
        await new Promise(resolve => setTimeout(resolve, 500));
        process.exit(1);
    });
