/**
 * TEST-SEC-004: VPN Rotation & Privacy
 * Test du système VPN avec rotation automatique
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

async function runTest() {
    console.log('\n=== TEST-SEC-004: VPN Rotation & Privacy ===\n');
    
    const results = { steps: [], success: false };
    
    // STEP 1: Initialize VPN Service
    console.log('[STEP 1] Initialisation VPN Service...');
    try {
        const VPNService = require('../vpn_service');
        const vpnService = new VPNService();
        
        console.log('  [OK] Service initialisé');
        console.log('  [INFO] TOR Host:', vpnService.torConfig.host + ':' + vpnService.torConfig.port);
        results.steps.push({ step: 1, success: true });
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 1, success: false, error: error.message });
    }

    // STEP 2: Get Current Public IP
    console.log('\n[STEP 2] Récupération IP publique actuelle...');
    try {
        const VPNService = require('../vpn_service');
        const vpnService = new VPNService();
        
        const ipInfo = await vpnService.getIPInfo();
        console.log('  [OK] IP Info récupérée');
        console.log('  [INFO] IP:', ipInfo.ip);
        console.log('  [INFO] Location:', ipInfo.city + ', ' + ipInfo.country);
        console.log('  [INFO] Org:', ipInfo.org || 'N/A');
        
        results.steps.push({ step: 2, success: true, ip: ipInfo.ip });
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 2, success: false, error: error.message });
    }

    // STEP 3: Check Available VPN Servers
    console.log('\n[STEP 3] Vérification serveurs VPN disponibles...');
    try {
        const VPNService = require('../vpn_service');
        const vpnService = new VPNService();
        
        const servers = vpnService.getAllServers();
        const ovpnConfigs = vpnService.loadOpenVPNConfigs();
        const wgConfigs = vpnService.loadWireGuardConfigs();
        const hasProton = await vpnService.isProtonVPNInstalled();
        
        console.log('  [INFO] OpenVPN configs:', ovpnConfigs.length);
        console.log('  [INFO] WireGuard configs:', wgConfigs.length);
        console.log('  [INFO] ProtonVPN CLI:', hasProton ? 'Installed' : 'Not installed');
        console.log('  [INFO] Total servers:', servers.length);
        
        if (ovpnConfigs.length > 0) {
            console.log('  [INFO] Sample OpenVPN:', ovpnConfigs[0].name);
        }
        
        results.steps.push({ 
            step: 3, 
            success: true, 
            servers: {
                openvpn: ovpnConfigs.length,
                wireguard: wgConfigs.length,
                protonvpn: hasProton
            }
        });
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 3, success: false, error: error.message });
    }

    // STEP 4: Test TOR Integration
    console.log('\n[STEP 4] Test intégration TOR...');
    try {
        const VPNService = require('../vpn_service');
        const vpnService = new VPNService();
        
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
        const VPNService = require('../vpn_service');
        const vpnService = new VPNService();
        
        const status = await vpnService.getStatus();
        console.log('  [INFO] Connected:', status.isConnected);
        console.log('  [INFO] Current Server:', status.currentServer || 'None');
        console.log('  [INFO] Current IP:', status.currentIP || status.ipInfo?.ip);
        console.log('  [INFO] Protected:', status.isProtected);
        console.log('  [INFO] Available OpenVPN:', status.availableServers?.openvpn);
        console.log('  [INFO] Available WireGuard:', status.availableServers?.wireguard);
        
        results.steps.push({ step: 5, success: true, status });
    } catch (error) {
        console.log('  [ERROR]', error.message);
        results.steps.push({ step: 5, success: false, error: error.message });
    }

    // Summary
    const successCount = results.steps.filter(s => s.success).length;
    results.success = successCount >= 4;
    
    console.log('\n=== RÉSUMÉ ===');
    results.steps.forEach(s => {
        console.log(`Step ${s.step}: ${s.success ? 'PASS' : 'FAIL'}`);
    });
    console.log(`\nRésultat global: ${results.success ? 'PASS' : 'FAIL'} (${successCount}/5 steps)`);
    console.log('==============\n');

    return results;
}

runTest()
    .then(r => process.exit(r.success ? 0 : 1))
    .catch(e => {
        console.error('Test failed:', e);
        process.exit(1);
    });
