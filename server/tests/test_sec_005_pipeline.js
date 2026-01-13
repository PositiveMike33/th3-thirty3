/**
 * TEST-SEC-005: Full Security Pipeline
 * Test complet du pipeline de sécurité: Auth → TOR → Shodan → LLM → Report
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

// Test target (mock data)
const MOCK_TARGET = {
    ip: "192.0.2.1", // TEST-NET IP (safe for testing)
    shodan_data: {
        ip_str: "192.0.2.1",
        org: "Test Corporation",
        os: "Linux Ubuntu 22.04",
        ports: [22, 80, 443, 8080],
        hostnames: ["test.example.com"],
        vulns: [],
        data: [
            { port: 22, product: "OpenSSH", version: "8.4p1" },
            { port: 80, product: "nginx", version: "1.18.0" },
            { port: 443, product: "nginx", version: "1.18.0" },
            { port: 8080, product: "Apache Tomcat", version: "9.0" }
        ]
    }
};

async function runTest() {
    console.log('\n=== TEST-SEC-005: Full Security Pipeline ===\n');
    console.log('Pipeline: Privacy Check → Target Recon → LLM Analysis → Report\n');
    
    const results = { 
        steps: [], 
        success: false,
        report: null,
        execution_time: 0
    };
    
    const startTime = Date.now();
    
    // STEP 1: Privacy Layer Check
    console.log('[STEP 1] Vérification couche de confidentialité...');
    try {
        const VPNService = require('../vpn_service');
        const vpnService = new VPNService();
        
        const originalIP = await vpnService.getCurrentIP();
        console.log('  [INFO] IP actuelle:', originalIP);
        
        const torStatus = await vpnService.isTorAvailable();
        if (torStatus.available && torStatus.isTor) {
            console.log('  [OK] TOR ACTIF - Anonymisation confirmée');
            console.log('  [INFO] Exit Node IP:', torStatus.ip);
            results.steps.push({ step: 1, success: true, privacy: 'TOR', original_ip: originalIP, tor_ip: torStatus.ip });
        } else {
            console.log('  [WARN] TOR non disponible - utilisation connexion directe');
            console.log('  [OPSEC] Attention: Les requêtes Shodan seront liées à votre IP');
            results.steps.push({ step: 1, success: true, privacy: 'DIRECT', warning: true, original_ip: originalIP });
        }
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 1, success: false, error: error.message });
    }

    // STEP 2: Target Reconnaissance (Mock)
    console.log('\n[STEP 2] Reconnaissance de la cible (Mock Data)...');
    try {
        console.log('  [INFO] Target IP:', MOCK_TARGET.ip);
        console.log('  [INFO] Org:', MOCK_TARGET.shodan_data.org);
        console.log('  [INFO] OS:', MOCK_TARGET.shodan_data.os);
        console.log('  [INFO] Ports:', MOCK_TARGET.shodan_data.ports.join(', '));
        console.log('  [INFO] Services:');
        MOCK_TARGET.shodan_data.data.forEach(s => {
            console.log(`    - Port ${s.port}: ${s.product} ${s.version}`);
        });
        
        results.steps.push({ step: 2, success: true, target: MOCK_TARGET });
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 2, success: false, error: error.message });
    }

    // STEP 3: LLM Security Analysis
    console.log('\n[STEP 3] Analyse de sécurité par LLM...');
    try {
        const LLMService = require('../llm_service');
        const llmService = new LLMService();
        
        const securityPrompt = `Tu es un expert en sécurité informatique québécois. Analyse cette infrastructure:

\`\`\`json
${JSON.stringify(MOCK_TARGET.shodan_data, null, 2)}
\`\`\`

Fournis un rapport de sécurité structuré:
1. **Résumé Exécutif** (2-3 phrases)
2. **Services Identifiés** (liste avec risques)
3. **Vulnérabilités Potentielles** (basé sur versions)
4. **Score de Risque** (1-10)
5. **Recommandations Prioritaires** (top 3)

Réponds en français québécois professionnel.`;

        const models = await llmService.listModels('local');
        const modelUsed = models.local?.find(m => 
            m.includes('qwen') || m.includes('llama') || m.includes('gemma') || m.includes('granite')
        ) || models.local?.[0];
        
        if (!modelUsed || modelUsed.includes('Offline')) {
            throw new Error('No local model available');
        }
        
        console.log('  [INFO] Modèle utilisé:', modelUsed);
        
        const analysis = await llmService.generateResponse(
            securityPrompt,
            null,
            'local',
            modelUsed,
            'Tu es un analyste de sécurité senior avec 15 ans d\'expérience.'
        );
        
        console.log('  [OK] Analyse complétée');
        results.steps.push({ step: 3, success: true, model: modelUsed, analysis_length: analysis?.length || 0 });
        results.report = analysis;
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 3, success: false, error: error.message });
    }

    // STEP 4: Report Generation
    console.log('\n[STEP 4] Génération du rapport final...');
    try {
        if (!results.report) {
            throw new Error('No analysis available for report');
        }
        
        console.log('\n╔════════════════════════════════════════════════════════════════╗');
        console.log('║           RAPPORT DE SÉCURITÉ - TH3 THIRTY3                    ║');
        console.log('╠════════════════════════════════════════════════════════════════╣');
        console.log('║ Target:', MOCK_TARGET.ip.padEnd(54) + '║');
        console.log('║ Date:', new Date().toISOString().padEnd(56) + '║');
        console.log('╠════════════════════════════════════════════════════════════════╣');
        console.log('');
        console.log(results.report);
        console.log('');
        console.log('╚════════════════════════════════════════════════════════════════╝');
        
        results.steps.push({ step: 4, success: true, report_generated: true });
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 4, success: false, error: error.message });
    }

    // Calculate results
    results.execution_time = Date.now() - startTime;
    const successCount = results.steps.filter(s => s.success).length;
    results.success = successCount >= 3;
    
    console.log('\n=== RÉSUMÉ PIPELINE ===');
    console.log(`Temps d'exécution: ${results.execution_time}ms`);
    results.steps.forEach(s => {
        console.log(`Step ${s.step}: ${s.success ? 'PASS' : 'FAIL'}`);
    });
    console.log(`\nRésultat global: ${results.success ? 'PASS' : 'FAIL'} (${successCount}/4 steps)`);
    console.log('=======================\n');

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
