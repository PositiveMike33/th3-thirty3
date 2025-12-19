/**
 * Test du TorNetworkService Mis à Jour
 * Vérifie que toutes les connexions sont anonymes
 */

require('dotenv').config();
const TorNetworkService = require('../tor_network_service');

async function testTorService() {
    console.log('\n' + '='.repeat(60));
    console.log('  TEST DU SERVICE TOR MIS À JOUR');
    console.log('='.repeat(60) + '\n');
    
    const torService = new TorNetworkService();
    
    // Test 1: Vérifier le statut
    console.log('[TEST 1] Vérification du statut Tor...');
    const status = await torService.checkTorStatus();
    console.log(`  Port SOCKS: ${status.running ? 'ACTIF' : 'INACTIF'}`);
    
    if (!status.running) {
        console.log('\n❌ Tor n\'est pas en cours d\'exécution!');
        console.log('   Lancez: Start-Process "C:\\Tor\\tor\\tor.exe" -ArgumentList "-f", "C:\\Tor\\torrc"');
        process.exit(1);
    }
    
    // Test 2: Requête via torFetch (méthode mise à jour)
    console.log('\n[TEST 2] Test de torFetch (via SOCKS5)...');
    try {
        const response = await torService.torFetch('https://check.torproject.org/api/ip');
        const data = await response.json();
        
        console.log(`  IP de sortie Tor: ${data.IP}`);
        console.log(`  Vérifié par Tor: ${data.IsTor ? 'OUI ✅' : 'NON ❌'}`);
        console.log(`  Via SOCKS5: ${response._viaSocks ? 'OUI ✅' : 'NON'}`);
        
        if (data.IsTor) {
            console.log('\n  ✅ CONNEXION ANONYME CONFIRMÉE!');
        } else {
            console.log('\n  ⚠️ Connexion non anonyme');
        }
    } catch (error) {
        console.log(`  ❌ Erreur: ${error.message}`);
    }
    
    // Test 3: Test sur plusieurs services
    console.log('\n[TEST 3] Vérification multi-services...');
    
    const services = [
        { name: 'IPify', url: 'https://api.ipify.org?format=json' },
        { name: 'HTTPBin', url: 'https://httpbin.org/ip' }
    ];
    
    for (const svc of services) {
        try {
            const response = await torService.torFetch(svc.url);
            const data = await response.json();
            const ip = data.ip || data.origin;
            console.log(`  ${svc.name}: ${ip}`);
        } catch (error) {
            console.log(`  ${svc.name}: Erreur - ${error.message}`);
        }
    }
    
    // Test 4: Vérification de la connexion Tor
    console.log('\n[TEST 4] Vérification complète de la connexion...');
    const verification = await torService.verifyTorConnection();
    console.log(`  Utilise Tor: ${verification.usingTor ? 'OUI ✅' : 'NON ❌'}`);
    console.log(`  IP: ${verification.ip}`);
    console.log(`  Message: ${verification.message}`);
    
    // Test 5: Statistiques
    console.log('\n[TEST 5] Statistiques du service...');
    const stats = torService.getStats();
    console.log(`  Requêtes effectuées: ${stats.requestsMade}`);
    console.log(`  Changements d'IP: ${stats.ipChanges}`);
    console.log(`  Erreurs: ${stats.errors}`);
    
    // Résumé
    console.log('\n' + '='.repeat(60));
    console.log('  RÉSUMÉ');
    console.log('='.repeat(60));
    
    if (verification.usingTor) {
        console.log('\n  🎉 SERVICE TOR OPÉRATIONNEL ET ANONYME');
        console.log('  - Toutes les requêtes via torFetch sont routées par Tor');
        console.log('  - Votre vraie IP est masquée');
        console.log('  - Le backend est prêt pour les opérations OSINT\n');
        process.exit(0);
    } else {
        console.log('\n  ⚠️ PROBLÈME DÉTECTÉ');
        console.log('  Vérifiez la configuration Tor\n');
        process.exit(1);
    }
}

testTorService().catch(error => {
    console.error('Erreur du test:', error.message);
    process.exit(1);
});
