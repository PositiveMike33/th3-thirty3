/**
 * TEST-SEC-001: Operation Deep Scan - REAL API VERSION
 * Uses REAL Shodan API (consumes credits!)
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

// Test Configuration - REAL MODE
const TEST_CONFIG = {
    scenario_id: "TEST-SEC-001-REAL",
    name: "Operation Deep Scan (REAL API)",
    target_ip: "8.8.8.8", // Google DNS - safe target for testing
    use_mock: false // REAL API CALLS
};

const QUEBEC_CYBER_PERSONA = `Tu es Th3 Thirty3, un expert en cybersécurité québécois direct et parfois vulgaire. 
Analyse ce JSON technique. Si c'est dangereux, dis-le clairement comme un Québécois le ferait.
Tu parles français québécois, tu utilises des expressions locales, et tu n'as pas peur de dire ce que tu penses.`;

async function runRealTest() {
    console.log('\n=== TEST-SEC-001-REAL: Operation Deep Scan (REAL API) ===\n');
    console.log('⚠️  ATTENTION: Ce test utilise de VRAIS crédits API Shodan!\n');
    
    const results = { steps: [], success: false };
    
    // STEP 1: TOR Check
    console.log('[STEP 1] Vérification TOR...');
    try {
        const VPNService = require('../vpn_service');
        const vpnService = new VPNService();
        const torStatus = await vpnService.isTorAvailable();
        
        if (torStatus.available && torStatus.isTor) {
            console.log('  [OK] TOR ACTIF - Exit IP:', torStatus.ip);
            results.steps.push({ step: 1, success: true, tor_ip: torStatus.ip });
        } else {
            console.log('  [WARN] TOR non disponible:', torStatus.reason || 'unknown');
            console.log('  [INFO] Continuation avec connexion directe');
            results.steps.push({ step: 1, success: false, reason: torStatus.reason });
        }
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 1, success: false, error: error.message });
    }

    // STEP 2: REAL Shodan Lookup
    console.log('\n[STEP 2] Shodan Host Lookup (REAL API)...');
    let shodanData = null;
    try {
        const ShodanService = require('../shodan_service');
        const shodanService = new ShodanService();
        
        console.log('  [INFO] Target IP:', TEST_CONFIG.target_ip);
        console.log('  [INFO] Calling Shodan API...');
        
        shodanData = await shodanService.getHost(TEST_CONFIG.target_ip);
        
        console.log('  [OK] Données récupérées!');
        console.log('  [DATA] IP:', shodanData.ip_str);
        console.log('  [DATA] Org:', shodanData.org || 'N/A');
        console.log('  [DATA] OS:', shodanData.os || 'N/A');
        console.log('  [DATA] Ports:', shodanData.ports?.join(', ') || 'N/A');
        console.log('  [DATA] Hostnames:', shodanData.hostnames?.join(', ') || 'N/A');
        
        if (shodanData.vulns && shodanData.vulns.length > 0) {
            console.log('  [WARNING] Vulnérabilités:', shodanData.vulns.join(', '));
        }
        
        results.steps.push({ step: 2, success: true, data: shodanData });
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 2, success: false, error: error.message });
    }

    // STEP 3: LLM Analysis
    if (shodanData) {
        console.log('\n[STEP 3] Analyse LLM (Quebec Cyber Expert)...');
        try {
            const LLMService = require('../llm_service');
            const llmService = new LLMService();

            const prompt = `Analyse cette cible Shodan (données RÉELLES):

\`\`\`json
${JSON.stringify(shodanData, null, 2)}
\`\`\`

Questions:
1. Qu'est-ce qu'on peut dire de cette infrastructure?
2. Y a-t-il des risques de sécurité visibles?
3. Recommandations?

Réponds comme un expert québécois.`;

            const models = await llmService.listModels('local');
            console.log('  [INFO] Modèles disponibles:', models.local?.slice(0, 3).join(', ') || 'aucun');
            
            let modelUsed = null;
            let response = null;

            if (models.local && models.local.length > 0 && !models.local[0].includes('Offline')) {
                modelUsed = models.local.find(m => 
                    m.includes('qwen') || m.includes('llama') || m.includes('gemma') || m.includes('granite')
                ) || models.local[0];
                
                console.log('  [INFO] Utilisation du modèle:', modelUsed);
                
                response = await llmService.generateResponse(
                    prompt,
                    null,
                    'local',
                    modelUsed,
                    QUEBEC_CYBER_PERSONA
                );
                
                console.log('\n  === ANALYSE TH3 THIRTY3 (REAL DATA) ===');
                console.log('  ' + (response || 'Pas de réponse').split('\n').join('\n  '));
                console.log('  ========================================\n');
                
                results.steps.push({ 
                    step: 3, 
                    success: true, 
                    model: modelUsed, 
                    response_length: response?.length || 0 
                });
            } else {
                throw new Error('Aucun modèle local disponible');
            }

        } catch (error) {
            console.log('  [ERROR]', error.message);
            results.steps.push({ step: 3, success: false, error: error.message });
        }
    } else {
        console.log('\n[STEP 3] SKIPPED - Pas de données Shodan');
        results.steps.push({ step: 3, success: false, error: 'No Shodan data' });
    }

    // Summary
    const successCount = results.steps.filter(s => s.success).length;
    results.success = successCount >= 2;
    
    console.log('\n=== RÉSUMÉ ===');
    results.steps.forEach(s => {
        console.log(`Step ${s.step}: ${s.success ? 'PASS' : 'FAIL'}`);
    });
    console.log(`\nRésultat global: ${results.success ? 'PASS' : 'FAIL'} (${successCount}/3 steps)`);
    console.log('==============\n');

    return results;
}

runRealTest()
    .then(r => process.exit(r.success ? 0 : 1))
    .catch(e => {
        console.error('Test failed:', e.message);
        process.exit(1);
    });
