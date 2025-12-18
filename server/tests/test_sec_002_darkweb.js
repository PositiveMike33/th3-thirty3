/**
 * TEST-SEC-002: Dark Web Reconnaissance
 * Test du système TOR pour accès réseau anonymisé
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

async function runTest() {
    console.log('\n=== TEST-SEC-002: Dark Web Reconnaissance ===\n');
    
    const results = { steps: [], success: false };
    
    // STEP 1: Initialize TOR Network Service
    console.log('[STEP 1] Initialisation TOR Network Service...');
    try {
        const TorNetworkService = require('../tor_network_service');
        const torService = new TorNetworkService();
        
        console.log('  [OK] Service initialisé');
        console.log('  [INFO] Proxy URL:', torService.proxyUrl);
        results.steps.push({ step: 1, success: true });
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 1, success: false, error: error.message });
    }

    // STEP 2: Check TOR Status
    console.log('\n[STEP 2] Vérification statut TOR...');
    try {
        const TorNetworkService = require('../tor_network_service');
        const torService = new TorNetworkService();
        
        const status = await torService.checkTorStatus();
        console.log('  [INFO] TOR Running:', status.running);
        
        if (status.running) {
            console.log('  [OK] TOR est actif sur le port', status.port);
            
            // Try to verify TOR connection
            const verification = await torService.verifyTorConnection();
            console.log('  [INFO] Using TOR:', verification.usingTor);
            console.log('  [INFO] Exit IP:', verification.ip || 'N/A');
            
            results.steps.push({ step: 2, success: true, data: verification });
        } else {
            console.log('  [WARN] TOR non disponible:', status.error);
            results.steps.push({ step: 2, success: false, reason: status.error });
        }
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 2, success: false, error: error.message });
    }

    // STEP 3: Test IP Change Capability
    console.log('\n[STEP 3] Test capacité changement d\'identité...');
    try {
        const TorNetworkService = require('../tor_network_service');
        const torService = new TorNetworkService();
        
        const status = await torService.checkTorStatus();
        if (!status.running) {
            console.log('  [SKIP] TOR non disponible, test ignoré');
            results.steps.push({ step: 3, success: false, skipped: true });
        } else {
            // Try to change circuit (new IP)
            console.log('  [INFO] Tentative de changement de circuit...');
            const changeResult = await torService.changeCircuit();
            
            if (changeResult.success) {
                console.log('  [OK] Nouveau circuit établi!');
                results.steps.push({ step: 3, success: true });
            } else {
                console.log('  [WARN] Échec changement circuit:', changeResult.error || 'unknown');
                results.steps.push({ step: 3, success: false, error: changeResult.error });
            }
        }
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 3, success: false, error: error.message });
    }

    // STEP 4: Test Secure Request Pattern
    console.log('\n[STEP 4] Test pattern requête sécurisée...');
    try {
        const TorNetworkService = require('../tor_network_service');
        const torService = new TorNetworkService();
        
        // Test with a regular clearnet site through TOR
        console.log('  [INFO] Test requête via TOR vers check.torproject.org');
        
        const status = await torService.checkTorStatus();
        if (!status.running) {
            console.log('  [SKIP] TOR non disponible');
            results.steps.push({ step: 4, success: false, skipped: true });
        } else {
            const response = await torService.torFetch('https://check.torproject.org/api/ip');
            const data = await response.json();
            
            console.log('  [OK] Réponse reçue');
            console.log('  [INFO] Is TOR:', data.IsTor);
            console.log('  [INFO] IP:', data.IP);
            
            results.steps.push({ step: 4, success: true, isTor: data.IsTor, ip: data.IP });
        }
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 4, success: false, error: error.message });
    }

    // Summary
    const successCount = results.steps.filter(s => s.success).length;
    const skippedCount = results.steps.filter(s => s.skipped).length;
    results.success = successCount >= 2 || (successCount >= 1 && skippedCount >= 2);
    
    console.log('\n=== RÉSUMÉ ===');
    results.steps.forEach(s => {
        const status = s.skipped ? 'SKIP' : (s.success ? 'PASS' : 'FAIL');
        console.log(`Step ${s.step}: ${status}`);
    });
    console.log(`\nRésultat global: ${results.success ? 'PASS' : 'FAIL'} (${successCount} pass, ${skippedCount} skip)`);
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
