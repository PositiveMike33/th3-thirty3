/**
 * COMPREHENSIVE PROJECT TEST
 * Tests all critical endpoints and services
 * Run before production deployment
 */

const http = require('http');

const BASE_URL = 'http://localhost:3000';

// All critical endpoints to test
const ENDPOINTS = [
    // Health & Status
    { method: 'GET', path: '/health', name: 'Health Check' },
    
    // Authentication
    { method: 'GET', path: '/auth/status', name: 'Auth Status' },
    
    // Models & Training
    { method: 'GET', path: '/models', name: 'List Models' },
    { method: 'GET', path: '/models/metrics', name: 'Model Metrics' },
    { method: 'GET', path: '/models/cognitive/status', name: 'Cognitive Status' },
    
    // Patterns & Fabric
    { method: 'GET', path: '/patterns', name: 'Fabric Patterns' },
    
    // Sessions
    { method: 'GET', path: '/sessions', name: 'Sessions List' },
    
    // HackerAI Integration
    { method: 'GET', path: '/api/hackerai/status', name: 'HackerAI Status' },
    { method: 'GET', path: '/api/hackerai/commands', name: 'HackerAI Commands' },
    
    // Bug Bounty Agents
    { method: 'GET', path: '/api/bugbounty/status', name: 'Bug Bounty Status' },
    { method: 'GET', path: '/api/bugbounty/agents', name: 'Bug Bounty Agents' },
    { method: 'GET', path: '/api/bugbounty/missions', name: 'Bug Bounty Missions' },
    { method: 'GET', path: '/api/bugbounty/config', name: 'Bug Bounty Config' },
    
    // Security
    { method: 'GET', path: '/api/security/roles', name: 'Security Roles' },
    
    // OSINT
    { method: 'GET', path: '/api/shodan/status', name: 'Shodan Status' },
    
    // Network Scanner
    { method: 'GET', path: '/api/network/status', name: 'Network Scanner Status' },
    
    // Subscription & Payment
    { method: 'GET', path: '/api/subscription/tiers', name: 'Subscription Tiers' },
    
    // Astronomy
    { method: 'GET', path: '/api/astronomy/status', name: 'Astronomy Status' },
    
    // IP Location
    { method: 'GET', path: '/api/iplocation/status', name: 'IP Location Status' },
    
    // WHOIS
    { method: 'GET', path: '/api/whois/status', name: 'WHOIS Status' },
    
    // NotebookLM
    { method: 'GET', path: '/notebooklm/domains', name: 'NotebookLM Domains' },
    
    // Curriculum
    { method: 'GET', path: '/curriculum/domains', name: 'Curriculum Domains' },
    
    // Dart AI
    { method: 'GET', path: '/api/dart/status', name: 'Dart AI Status' },
    
    // VPN/TOR
    { method: 'GET', path: '/api/vpn/status', name: 'VPN Status' },
    
    // Agents (corrected path)
    { method: 'GET', path: '/api/agents/list', name: 'Lightweight Agents List' },
    
    // Evolution (corrected path)
    { method: 'GET', path: '/api/evolution/evolution-status', name: 'Evolution Status' },
    
    // Training
    { method: 'GET', path: '/api/evolution/training-log', name: 'Training Logs' },
];

async function testEndpoint(endpoint) {
    return new Promise((resolve) => {
        const url = new URL(endpoint.path, BASE_URL);
        
        const req = http.request({
            hostname: url.hostname,
            port: url.port,
            path: url.pathname,
            method: endpoint.method,
            timeout: 5000
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                resolve({
                    name: endpoint.name,
                    path: endpoint.path,
                    status: res.statusCode,
                    success: res.statusCode >= 200 && res.statusCode < 400,
                    hasData: data.length > 0
                });
            });
        });

        req.on('error', (err) => {
            resolve({
                name: endpoint.name,
                path: endpoint.path,
                status: 'ERROR',
                success: false,
                error: err.message
            });
        });

        req.on('timeout', () => {
            req.destroy();
            resolve({
                name: endpoint.name,
                path: endpoint.path,
                status: 'TIMEOUT',
                success: false
            });
        });

        req.end();
    });
}

async function runTests() {
    console.log('='.repeat(60));
    console.log('   TH3 THIRTY3 - COMPREHENSIVE PROJECT TEST');
    console.log('   Testing ' + ENDPOINTS.length + ' critical endpoints');
    console.log('='.repeat(60));
    console.log('');

    const results = [];
    let passed = 0;
    let failed = 0;

    for (const endpoint of ENDPOINTS) {
        const result = await testEndpoint(endpoint);
        results.push(result);
        
        const icon = result.success ? '✅' : '❌';
        const status = result.success ? 'PASS' : 'FAIL';
        console.log(`${icon} [${status}] ${result.name.padEnd(25)} ${result.path.padEnd(35)} ${result.status}`);
        
        if (result.success) passed++;
        else failed++;
    }

    console.log('');
    console.log('='.repeat(60));
    console.log('   RESULTS SUMMARY');
    console.log('='.repeat(60));
    console.log(`   Total Tests:  ${ENDPOINTS.length}`);
    console.log(`   Passed:       ${passed} (${Math.round(passed/ENDPOINTS.length*100)}%)`);
    console.log(`   Failed:       ${failed} (${Math.round(failed/ENDPOINTS.length*100)}%)`);
    console.log('');

    if (failed === 0) {
        console.log('   🎉 ALL TESTS PASSED! Project is ready for deployment.');
    } else {
        console.log('   ⚠️  Some tests failed. Review the endpoints above.');
        console.log('');
        console.log('   Failed endpoints:');
        results.filter(r => !r.success).forEach(r => {
            console.log(`   - ${r.name}: ${r.path} (${r.status})`);
        });
    }
    console.log('='.repeat(60));

    return { passed, failed, total: ENDPOINTS.length, results };
}

runTests().catch(console.error);
