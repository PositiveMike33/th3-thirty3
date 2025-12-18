/**
 * TEST-SEC-001: Operation Deep Scan - Simple Version
 * Quick test without fancy formatting
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

// Mock Data
const MOCK_SHODAN_RESPONSE = {
    ip_str: "198.51.100.45",
    org: "Insecure Corp Ltd.",
    os: "Windows Server 2008 R2",
    ports: [80, 443, 3389],
    vulns: ["CVE-2019-0708"],
    data: [
        {
            port: 3389,
            transport: "tcp",
            product: "Microsoft Terminal Services",
            info: "BlueKeep Vulnerable"
        }
    ]
};

const QUEBEC_CYBER_PERSONA = `Tu es Th3 Thirty3, un expert en cybersécurité québécois direct. 
Analyse ce JSON technique. Si c'est dangereux, dis-le clairement.
Tu parles français québécois et tu n'as pas peur de dire ce que tu penses.`;

async function runTest() {
    console.log('\n=== TEST-SEC-001: Operation Deep Scan ===\n');
    
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
            console.log('  [INFO] Continuation sans TOR pour le test');
            results.steps.push({ step: 1, success: false, reason: torStatus.reason });
        }
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 1, success: false, error: error.message });
    }

    // STEP 2: Shodan Mock Data
    console.log('\n[STEP 2] Shodan Host Lookup (MOCK DATA)...');
    console.log('  [INFO] Utilisation de mock data pour économiser les crédits API');
    console.log('  [DATA] Target:', MOCK_SHODAN_RESPONSE.ip_str);
    console.log('  [DATA] Org:', MOCK_SHODAN_RESPONSE.org);
    console.log('  [DATA] OS:', MOCK_SHODAN_RESPONSE.os);
    console.log('  [DATA] Ports:', MOCK_SHODAN_RESPONSE.ports.join(', '));
    console.log('  [WARNING] Vulnérabilités:', MOCK_SHODAN_RESPONSE.vulns.join(', '));
    results.steps.push({ step: 2, success: true, data: MOCK_SHODAN_RESPONSE });

    // STEP 3: LLM Analysis
    console.log('\n[STEP 3] Analyse LLM (Quebec Cyber Expert)...');
    try {
        const LLMService = require('../llm_service');
        const llmService = new LLMService();

        const prompt = `Analyse cette cible Shodan:

\`\`\`json
${JSON.stringify(MOCK_SHODAN_RESPONSE, null, 2)}
\`\`\`

Questions rapides:
1. C'est-tu une passoire cette machine?
2. CVE-2019-0708 (BlueKeep) - les risques?
3. Recommandations?

Réponds comme un expert québécois.`;

        // Get available models
        const models = await llmService.listModels('local');
        console.log('  [INFO] Modèles disponibles:', models.local?.slice(0, 5).join(', ') || 'aucun local');
        
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
            
            console.log('\n  === ANALYSE TH3 THIRTY3 ===');
            console.log('  ' + (response || 'Pas de réponse').split('\n').join('\n  '));
            console.log('  ===========================\n');
            
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

runTest()
    .then(async r => {
        await new Promise(resolve => setTimeout(resolve, 500));
        process.exit(r.success ? 0 : 1);
    })
    .catch(async e => {
        console.error('Test failed:', e.message);
        await new Promise(resolve => setTimeout(resolve, 500));
        process.exit(1);
    });
