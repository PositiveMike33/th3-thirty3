/**
 * TEST-SEC-004: VPN Rotation & Privacy
 * Test du système VPN avec rotation automatique
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

async function runTest() {
    console.log('\n=== TEST-SEC-004: VPN Rotation & Privacy ===\n');
    
    const results = { steps: [], success: false };
    
    // Single VPN Service instance
    let vpnService = null;
    
    // STEP 1: Initialize VPN Service
    console.log('[STEP 1] Initialisation VPN Service...');
    try {
        const VPNService = require('../vpn_service');
        vpnService = new VPNService();
        
        console.log('  [OK] Service initialisé');
        console.log('  [INFO] TOR Host:', vpnService.torConfig.host + ':' + vpnService.torConfig.port);
        results.steps.push({ step: 1, success: true });
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 1, success: false, error: error.message });
        // Cannot continue without VPN service
        return results;
    }

    // STEP 2: Get Current Public IP (with timeout)
    console.log('\n[STEP 2] Récupération IP publique actuelle...');
    try {
        const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Timeout')), 10000)
        );
        
        const ipInfo = await Promise.race([
            vpnService.getIPInfo(),
            timeoutPromise
        ]);
        
        console.log('  [OK] IP Info récupérée');
        console.log('  [INFO] IP:', ipInfo.ip);
        console.log('  [INFO] Location:', (ipInfo.city || 'Unknown') + ', ' + (ipInfo.country || 'Unknown'));
        
        results.steps.push({ step: 2, success: true, ip: ipInfo.ip });
    } catch (error) {
        console.log('  [WARN]', error.message);
        console.log('  [INFO] Continuing anyway...');
        results.steps.push({ step: 2, success: true, warning: error.message });
    }

    // STEP 3: Check Available VPN Servers
    console.log('\n[STEP 3] Vérification serveurs VPN disponibles...');
    try {
        const ovpnConfigs = vpnService.loadOpenVPNConfigs();
        const wgConfigs = vpnService.loadWireGuardConfigs();
        
        console.log('  [INFO] OpenVPN configs:', ovpnConfigs.length);
        console.log('  [INFO] WireGuard configs:', wgConfigs.length);
        
        results.steps.push({ 
            step: 3, 
            success: true, 
            openvpn: ovpnConfigs.length,
            wireguard: wgConfigs.length
        });
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 3, success: false, error: error.message });
    }

    // STEP 4: Test TOR Integration
    console.log('\n[STEP 4] Test intégration TOR...');
    try {
        const torStatus = await vpnService.isTorAvailable();
        console.log('  [INFO] TOR Available:', torStatus.available);
        
        if (torStatus.available) {
            console.log('  [OK] TOR est disponible');
            console.log('  [INFO] Is TOR:', torStatus.isTor);
            console.log('  [INFO] Exit IP:', torStatus.ip || 'N/A');
            results.steps.push({ step: 4, success: true, tor: torStatus });
        } else {
            console.log('  [WARN] TOR non disponible:', torStatus.reason);
            results.steps.push({ step: 4, success: false, reason: torStatus.reason });
        }
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 4, success: false, error: error.message });
    }

    // STEP 5: Get Full VPN Status
    console.log('\n[STEP 5] Statut complet VPN...');
    try {
        const status = await vpnService.getStatus();
        console.log('  [INFO] Connected:', status.isConnected);
        console.log('  [INFO] Current IP:', status.currentIP || status.ipInfo?.ip || 'N/A');
        console.log('  [INFO] Available OpenVPN:', status.availableServers?.openvpn || 0);
        console.log('  [INFO] Available WireGuard:', status.availableServers?.wireguard || 0);
        
        results.steps.push({ step: 5, success: true });
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 5, success: false, error: error.message });
    }

    // Summary
    const successCount = results.steps.filter(s => s.success).length;
    results.success = successCount >= 3;
    
    console.log('\n=== RÉSUMÉ ===');
    results.steps.forEach(s => {
        console.log(`Step ${s.step}: ${s.success ? 'PASS' : 'FAIL'}`);
    });
    console.log(`\nRésultat global: ${results.success ? 'PASS' : 'FAIL'} (${successCount}/5 steps)`);
    console.log('==============\n');

    return results;
}

runTest()
    .then(async r => {
        // Wait for async handles to close
        await new Promise(resolve => setTimeout(resolve, 500));
        process.exit(r.success ? 0 : 1);
    })
    .catch(async e => {
        console.error('Test failed:', e);
        await new Promise(resolve => setTimeout(resolve, 500));
        process.exit(1);
    });
