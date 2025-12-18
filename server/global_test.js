/**
 * Script de Test Global - Th3 Thirty3
 * Teste tous les systèmes: Director, Agents, Optimizer, Training
 */

async function runGlobalTest() {
    const results = {
        timestamp: new Date().toISOString(),
        tests: [],
        passed: 0,
        failed: 0
    };

    console.log('\n ===== TEST GLOBAL TH3 THIRTY3 =====\n');

    // Test 1: Director Status
    try {
        console.log('1 Test Director Status...');
        const res = await fetch('http://localhost:3000/api/director/status');
        const data = await res.json();
        if (data.success && data.agents.length >= 7) {
            console.log('    PASS - 7 agents configurés');
            console.log(`    Agents: ${data.agents.map(a => a.name).join(', ')}`);
            results.tests.push({ name: 'Director Status', status: 'PASS' });
            results.passed++;
        } else {
            throw new Error('Not enough agents');
        }
    } catch (e) {
        console.log(`    FAIL: ${e.message}`);
        results.tests.push({ name: 'Director Status', status: 'FAIL', error: e.message });
        results.failed++;
    }

    // Test 2: Cloud Optimizer
    try {
        console.log('\n2 Test Cloud Optimizer...');
        const res = await fetch('http://localhost:3000/api/cloud-optimizer/status');
        const data = await res.json();
        if (data.success && data.isRunning) {
            console.log('    PASS - Optimizer running');
            console.log(`    Providers: ${data.availableProviders.join(', ')}`);
            console.log(`    Domains: ${data.trainingDomains.map(d => d.name).join(', ')}`);
            results.tests.push({ name: 'Cloud Optimizer', status: 'PASS' });
            results.passed++;
        } else {
            throw new Error('Optimizer not running');
        }
    } catch (e) {
        console.log(`    FAIL: ${e.message}`);
        results.tests.push({ name: 'Cloud Optimizer', status: 'FAIL', error: e.message });
        results.failed++;
    }

    // Test 3: Training Commentary
    try {
        console.log('\n3 Test Training Commentary...');
        const res = await fetch('http://localhost:3000/api/real-training/commentary?limit=3');
        const data = await res.json();
        if (data.success) {
            console.log(`    PASS - ${data.count} commentaires trouvés`);
            results.tests.push({ name: 'Training Commentary', status: 'PASS' });
            results.passed++;
        } else {
            throw new Error('Commentary failed');
        }
    } catch (e) {
        console.log(`    FAIL: ${e.message}`);
        results.tests.push({ name: 'Training Commentary', status: 'FAIL', error: e.message });
        results.failed++;
    }

    // Test 4: Director Chat (Cybersecurity)
    try {
        console.log('\n4 Test Director Chat (Security)...');
        const res = await fetch('http://localhost:3000/api/director/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: 'Explique les bases du pentest' })
        });
        const data = await res.json();
        if (data.success && data.response) {
            console.log(`    PASS - Type: ${data.type}`);
            console.log(`    Réponse: ${data.response.substring(0, 100)}...`);
            results.tests.push({ name: 'Director Chat Security', status: 'PASS' });
            results.passed++;
        } else {
            throw new Error('No response');
        }
    } catch (e) {
        console.log(`    FAIL: ${e.message}`);
        results.tests.push({ name: 'Director Chat Security', status: 'FAIL', error: e.message });
        results.failed++;
    }

    // Test 5: Model Metrics
    try {
        console.log('\n5 Test Model Metrics...');
        const res = await fetch('http://localhost:3000/models/metrics');
        const data = await res.json();
        const modelCount = Object.keys(data).length;
        if (modelCount > 0) {
            console.log(`    PASS - ${modelCount} modèles trackés`);
            Object.entries(data).slice(0, 3).forEach(([name, metrics]) => {
                console.log(`    ${name}: Score ${metrics.cognitive?.overallScore || 'N/A'}`);
            });
            results.tests.push({ name: 'Model Metrics', status: 'PASS' });
            results.passed++;
        } else {
            throw new Error('No models');
        }
    } catch (e) {
        console.log(`    FAIL: ${e.message}`);
        results.tests.push({ name: 'Model Metrics', status: 'FAIL', error: e.message });
        results.failed++;
    }

    // Summary
    console.log('\n' + '='.repeat(50));
    console.log(` RÉSULTATS: ${results.passed} PASS / ${results.failed} FAIL`);
    console.log('='.repeat(50) + '\n');

    return results;
}

runGlobalTest().then(r => console.log('Test complet!')).catch(e => console.error(e));
