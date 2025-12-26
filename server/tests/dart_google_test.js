/**
 * Dart & Google API Test Suite
 * Tests all Dart and Google endpoints for 100% functionality
 */

const BASE_URL = 'http://localhost:3000';

async function request(path, options = {}) {
    try {
        const url = `${BASE_URL}${path}`;
        const res = await fetch(url, {
            headers: { 'Content-Type': 'application/json' },
            ...options
        });
        const data = await res.json();
        return { ok: res.ok, status: res.status, data };
    } catch (error) {
        return { ok: false, error: error.message };
    }
}

async function runTests() {
    console.log('\n' + '='.repeat(60));
    console.log('  DART & GOOGLE API TEST SUITE');
    console.log('='.repeat(60) + '\n');

    const results = { passed: 0, failed: 0, tests: [] };

    const tests = [
        // DART API
        { name: 'Dart Status', method: 'GET', path: '/api/dart/status', validate: (d) => d.connected === true },
        { name: 'Dart List Tasks', method: 'GET', path: '/api/dart/tasks', validate: (d) => d.success === true },
        { 
            name: 'Dart Create Task', 
            method: 'POST', 
            path: '/api/dart/tasks/create', 
            body: { title: 'Test Task from API Test', description: 'Automated test' },
            validate: (d) => d.success === true 
        },
        { 
            name: 'Dart AI Breakdown', 
            method: 'POST', 
            path: '/api/dart/tasks/breakdown', 
            body: { taskDescription: 'Build a security audit system' },
            validate: (d) => d.success === true && d.breakdown 
        },
        
        // GOOGLE API
        { name: 'Google Status', method: 'GET', path: '/api/google/status', validate: (d) => d.connected >= 1 },
        { name: 'Google Help', method: 'GET', path: '/api/google/help', validate: (d) => d.endpoints && typeof d.endpoints === 'object' },
        { 
            name: 'Google Calendar Events', 
            method: 'GET', 
            path: '/api/google/calendar/mikegauthierguillet@gmail.com/events', 
            validate: (d) => Array.isArray(d.events) 
        },
        { 
            name: 'Google Drive Files', 
            method: 'GET', 
            path: '/api/google/drive/mikegauthierguillet@gmail.com/files', 
            validate: (d) => Array.isArray(d.files) 
        },
        { 
            name: 'Google Gmail Unread', 
            method: 'GET', 
            path: '/api/google/gmail/unread', 
            validate: (d) => d.accounts !== undefined 
        },
        { 
            name: 'Google YouTube Playlists', 
            method: 'GET', 
            path: '/api/google/youtube/th3thirty3@gmail.com/playlists', 
            validate: (d) => Array.isArray(d.playlists) || d.error === 'quotaExceeded'  // YouTube quota can be exceeded
        }
    ];

    console.log('📦 DART API');
    console.log('─'.repeat(40));
    
    for (const test of tests.filter(t => t.path.includes('/dart'))) {
        const result = await runTest(test);
        results.tests.push(result);
        if (result.passed) results.passed++;
        else results.failed++;
    }

    console.log('\n🔗 GOOGLE API');
    console.log('─'.repeat(40));
    
    for (const test of tests.filter(t => t.path.includes('/google'))) {
        const result = await runTest(test);
        results.tests.push(result);
        if (result.passed) results.passed++;
        else results.failed++;
    }

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
        console.log('\n  🎉 ALL TESTS PASSED! SYSTEM 100% OPERATIONAL!\n');
    } else {
        console.log('\n  ⚠️  Some tests failed. See details above.\n');
    }

    return results;
}

async function runTest(test) {
    const start = Date.now();
    try {
        const options = { method: test.method };
        if (test.body) options.body = JSON.stringify(test.body);
        
        const result = await request(test.path, options);
        const duration = Date.now() - start;
        
        const passed = result.ok && test.validate(result.data);
        const status = passed ? '✅' : '❌';
        const details = passed ? 'OK' : (result.data?.error || result.error || 'Validation failed');
        
        console.log(`  ${status} ${test.name.padEnd(25)} ${duration}ms  ${details}`);
        
        return { name: test.name, passed, duration, details };
    } catch (error) {
        console.log(`  ❌ ${test.name.padEnd(25)} ERROR  ${error.message}`);
        return { name: test.name, passed: false, error: error.message };
    }
}

// Run
runTests().then(results => {
    process.exit(results.failed > 0 ? 1 : 0);
});
