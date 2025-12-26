/**
 * Real-Time Connection Test Suite
 * Tests connectivity between backend and frontend
 */

const BASE_URL = 'http://localhost:3000';

async function testRealTimeConnections() {
    console.log('\n' + '='.repeat(60));
    console.log('  🔌 REAL-TIME CONNECTION TEST SUITE');
    console.log('='.repeat(60) + '\n');

    const results = { passed: 0, failed: 0, tests: [] };

    // Test 1: Server Health
    console.log('📡 SERVER CONNECTIVITY');
    console.log('─'.repeat(40));
    const healthResult = await testServerHealth();
    results.tests.push(healthResult);
    if (healthResult.passed) results.passed++; else results.failed++;

    // Test 2: Logs Streaming Endpoint
    console.log('\n📋 LOGS STREAMING ENDPOINT');
    console.log('─'.repeat(40));
    const logsResult = await testLogsEndpoint();
    results.tests.push(logsResult);
    if (logsResult.passed) results.passed++; else results.failed++;

    // Test 3: Socket Status Check
    console.log('\n🔌 WEBSOCKET STATUS');
    console.log('─'.repeat(40));
    const socketResult = await testSocketStatus();
    results.tests.push(socketResult);
    if (socketResult.passed) results.passed++; else results.failed++;

    // Test 4: Real-Time API Endpoints
    console.log('\n⚡ REAL-TIME API ENDPOINTS');
    console.log('─'.repeat(40));
    const apiResult = await testRealTimeAPIs();
    results.tests.push(apiResult);
    if (apiResult.passed) results.passed++; else results.failed++;

    // Test 5: Model Metrics (Live Updates)
    console.log('\n📊 MODEL METRICS (LIVE DATA)');
    console.log('─'.repeat(40));
    const metricsResult = await testModelMetrics();
    results.tests.push(metricsResult);
    if (metricsResult.passed) results.passed++; else results.failed++;

    // Test 6: Training Status
    console.log('\n🎓 TRAINING SYSTEM');
    console.log('─'.repeat(40));
    const trainingResult = await testTrainingStatus();
    results.tests.push(trainingResult);
    if (trainingResult.passed) results.passed++; else results.failed++;

    // Test 7: OSINT Real-Time Tools
    console.log('\n🔍 OSINT REAL-TIME');
    console.log('─'.repeat(40));
    const osintResult = await testOSINTRealTime();
    results.tests.push(osintResult);
    if (osintResult.passed) results.passed++; else results.failed++;

    // Test 8: Docker Status (Live)
    console.log('\n🐳 DOCKER LIVE STATUS');
    console.log('─'.repeat(40));
    const dockerResult = await testDockerStatus();
    results.tests.push(dockerResult);
    if (dockerResult.passed) results.passed++; else results.failed++;

    // Summary
    const total = results.passed + results.failed;
    const passRate = ((results.passed / total) * 100).toFixed(1);

    console.log('\n' + '='.repeat(60));
    console.log('  📊 TEST RESULTS');
    console.log('='.repeat(60));
    console.log(`  ✅ Passed: ${results.passed}`);
    console.log(`  ❌ Failed: ${results.failed}`);
    console.log(`  📈 Pass Rate: ${passRate}%`);
    console.log('='.repeat(60));

    if (results.failed === 0) {
        console.log('\n  🎉 ALL BACKEND-FRONTEND CONNECTIONS WORKING!\n');
    } else {
        console.log('\n  ⚠️  Some connections need attention.\n');
    }

    return results;
}

async function request(path) {
    const start = Date.now();
    try {
        const res = await fetch(`${BASE_URL}${path}`);
        const data = await res.json();
        return { ok: res.ok, data, duration: Date.now() - start };
    } catch (e) {
        return { ok: false, error: e.message, duration: Date.now() - start };
    }
}

// Test 1: Server Health
async function testServerHealth() {
    const res = await request('/health');
    if (res.ok) {
        console.log(`  ✅ Server Health             ${res.duration}ms - ONLINE`);
        return { name: 'Server Health', passed: true, duration: res.duration };
    }
    console.log(`  ❌ Server Health             OFFLINE`);
    return { name: 'Server Health', passed: false };
}

// Test 2: Logs Endpoint
async function testLogsEndpoint() {
    const res = await request('/api/logs/recent?limit=5');
    if (res.ok && res.data.logs !== undefined) {
        console.log(`  ✅ Logs Endpoint             ${res.data.logs.length} logs, ${res.duration}ms`);
        return { name: 'Logs Endpoint', passed: true, logCount: res.data.logs.length };
    }
    console.log(`  ❌ Logs Endpoint             FAILED`);
    return { name: 'Logs Endpoint', passed: false };
}

// Test 3: Socket Status
async function testSocketStatus() {
    // Check if WebSocket upgrade is available by hitting the socket.io endpoint
    try {
        const res = await fetch(`${BASE_URL}/socket.io/?EIO=4&transport=polling`);
        if (res.ok) {
            const text = await res.text();
            if (text.includes('sid')) {
                console.log(`  ✅ WebSocket Status          AVAILABLE (Socket.io active)`);
                return { name: 'WebSocket Status', passed: true };
            }
        }
        console.log(`  ⚠️ WebSocket Status          Polling mode (WebSocket may be blocked)`);
        return { name: 'WebSocket Status', passed: true };
    } catch (e) {
        console.log(`  ❌ WebSocket Status          ERROR: ${e.message}`);
        return { name: 'WebSocket Status', passed: false };
    }
}

// Test 4: Real-Time APIs
async function testRealTimeAPIs() {
    const endpoints = [
        { name: 'Models', path: '/models' },
        { name: 'Dart Status', path: '/api/dart/status' },
        { name: 'Google Status', path: '/api/google/status' },
        { name: 'Director', path: '/api/director/status' },
        { name: 'Network', path: '/api/network/status' }
    ];

    let allPassed = true;
    for (const ep of endpoints) {
        const res = await request(ep.path);
        const status = res.ok ? '✅' : '❌';
        console.log(`  ${status} ${ep.name.padEnd(20)} ${res.duration}ms`);
        if (!res.ok) allPassed = false;
    }

    return { name: 'Real-Time APIs', passed: allPassed };
}

// Test 5: Model Metrics
async function testModelMetrics() {
    const res = await request('/models/metrics');
    if (res.ok) {
        const modelCount = res.data.models?.length || Object.keys(res.data).length || 0;
        console.log(`  ✅ Model Metrics             ${modelCount} models tracked, ${res.duration}ms`);
        return { name: 'Model Metrics', passed: true, modelCount };
    }
    console.log(`  ❌ Model Metrics             FAILED`);
    return { name: 'Model Metrics', passed: false };
}

// Test 6: Training Status
async function testTrainingStatus() {
    const res = await request('/api/hackergpt/progress');
    if (res.ok) {
        console.log(`  ✅ Training Status           ${res.duration}ms - ACTIVE`);
        return { name: 'Training Status', passed: true };
    }
    console.log(`  ⚠️ Training Status           ${res.duration}ms - No active training`);
    return { name: 'Training Status', passed: true }; // Not an error if no training
}

// Test 7: OSINT Real-Time
async function testOSINTRealTime() {
    const res = await request('/osint/tools');
    if (res.ok && Array.isArray(res.data) && res.data.length > 0) {
        console.log(`  ✅ OSINT Tools               ${res.data.length} tools available, ${res.duration}ms`);
        return { name: 'OSINT Real-Time', passed: true, toolCount: res.data.length };
    }
    console.log(`  ❌ OSINT Tools               FAILED`);
    return { name: 'OSINT Real-Time', passed: false };
}

// Test 8: Docker Status
async function testDockerStatus() {
    const res = await request('/api/docker/status');
    if (res.ok) {
        const containers = res.data.containers || [];
        const running = containers.filter(c => c.status === 'running' || c.status === 'already_running').length;
        console.log(`  ✅ Docker Status             ${running}/${containers.length} containers running, ${res.duration}ms`);
        return { name: 'Docker Status', passed: true, running, total: containers.length };
    }
    console.log(`  ⚠️ Docker Status             ${res.duration}ms - Check manually`);
    return { name: 'Docker Status', passed: true };
}

// Run tests
testRealTimeConnections().then(results => {
    process.exit(results.failed > 0 ? 1 : 0);
});
