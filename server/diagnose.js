/**
 * Script de diagnostic rapide pour le serveur Th3 Thirty3
 */

const API_KEY = 'sk-ADMIN-TH3-THIRTY3-MASTER-KEY';
const HEADERS = {
    'Content-Type': 'application/json',
    'x-api-key': API_KEY
};

async function diagnose() {
    console.log('\n=== DIAGNOSTIC TH3 THIRTY3 ===\n');
    
    // Test 1: Basic Server Health
    try {
        console.log('1. Test serveur basique (models)...');
        const res = await fetch('http://localhost:3000/models', { headers: HEADERS });
        console.log('   Status:', res.status);
        if (!res.ok) {
            const text = await res.text();
            console.log('   Error:', text);
        } else {
            const data = await res.json();
            console.log('   OK - Modèles locaux:', data.local?.slice(0, 3).join(', ') || 'none');
        }
    } catch (e) {
        console.log('   FAIL:', e.message);
    }

    // Test 2: Director Status
    try {
        console.log('\n2. Test Director Status...');
        const res = await fetch('http://localhost:3000/api/director/status', { headers: HEADERS });
        console.log('   Status:', res.status);
        if (!res.ok) {
            const text = await res.text();
            console.log('   Error:', text);
        } else {
            const data = await res.json();
            console.log('   Success:', data.success);
            console.log('   Director:', data.director?.name || 'N/A');
            console.log('   Agents count:', data.agents?.length || 0);
            if (data.agents) {
                console.log('   Agents:', data.agents.map(a => a.name).join(', '));
            }
        }
    } catch (e) {
        console.log('   FAIL:', e.message);
    }

    // Test 3: Cloud Optimizer Status
    try {
        console.log('\n3. Test Cloud Optimizer...');
        const res = await fetch('http://localhost:3000/api/cloud-optimizer/status', { headers: HEADERS });
        console.log('   Status:', res.status);
        if (!res.ok) {
            const text = await res.text();
            console.log('   Error:', text);
        } else {
            const data = await res.json();
            console.log('   Success:', data.success);
            console.log('   Running:', data.isRunning);
        }
    } catch (e) {
        console.log('   FAIL:', e.message);
    }

    // Test 4: Shodan Status (from our scenario)
    try {
        console.log('\n4. Test Shodan Status...');
        const res = await fetch('http://localhost:3000/api/shodan/status', { headers: HEADERS });
        console.log('   Status:', res.status);
        if (!res.ok) {
            const text = await res.text();
            console.log('   Error:', text);
        } else {
            const data = await res.json();
            console.log('   Status:', data.status);
            console.log('   Credits:', data.credits);
        }
    } catch (e) {
        console.log('   FAIL:', e.message);
    }

    // Test 5: VPN/TOR Status
    try {
        console.log('\n5. Test VPN/TOR Status...');
        const res = await fetch('http://localhost:3000/api/vpn/tor/status', { headers: HEADERS });
        console.log('   Status:', res.status);
        if (!res.ok) {
            const text = await res.text();
            console.log('   Error:', text);
        } else {
            const data = await res.json();
            console.log('   Available:', data.available);
            console.log('   Connected:', data.connected);
            console.log('   Is TOR:', data.isTor);
        }
    } catch (e) {
        console.log('   FAIL:', e.message);
    }

    console.log('\n=== FIN DIAGNOSTIC ===\n');
}

diagnose().then(() => process.exit(0)).catch(e => {
    console.error('Diagnostic failed:', e);
    process.exit(1);
});
