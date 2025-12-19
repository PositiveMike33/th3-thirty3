/**
 * SECURITY TEST SUITE RUNNER
 * Exécute tous les tests de sécurité et génère un rapport
 */

const { spawn } = require('child_process');
const path = require('path');

const TESTS = [
    { id: 'SEC-001', name: 'Deep Scan (Mock)', file: 'test_sec_001_simple.js' },
    { id: 'SEC-002', name: 'Dark Web Reconnaissance', file: 'test_sec_002_darkweb.js' },
    { id: 'SEC-003', name: 'OSINT Expert Analysis', file: 'test_sec_003_osint.js' },
    { id: 'SEC-004', name: 'VPN Rotation & Privacy', file: 'test_sec_004_vpn.js' },
    { id: 'SEC-005', name: 'Full Security Pipeline', file: 'test_sec_005_pipeline.js' }
];

async function runTest(testConfig) {
    return new Promise((resolve) => {
        const testPath = path.join(__dirname, testConfig.file);
        const startTime = Date.now();
        
        console.log(`\n${'='.repeat(60)}`);
        console.log(`Running ${testConfig.id}: ${testConfig.name}`);
        console.log('='.repeat(60));
        
        const child = spawn('node', [testPath], {
            cwd: __dirname,
            env: process.env,
            stdio: 'inherit'
        });
        
        child.on('close', (code) => {
            const duration = Date.now() - startTime;
            resolve({
                ...testConfig,
                exitCode: code,
                success: code === 0,
                duration
            });
        });
        
        child.on('error', (err) => {
            resolve({
                ...testConfig,
                exitCode: 1,
                success: false,
                error: err.message,
                duration: Date.now() - startTime
            });
        });
    });
}

async function runAllTests() {
    console.log('\n');
    console.log('╔════════════════════════════════════════════════════════════════╗');
    console.log('║         TH3 THIRTY3 - SECURITY TEST SUITE                      ║');
    console.log('║         Running all security scenario tests                    ║');
    console.log('╚════════════════════════════════════════════════════════════════╝');
    console.log(`\nStarted at: ${new Date().toISOString()}`);
    console.log(`Tests to run: ${TESTS.length}\n`);
    
    const results = [];
    const startTime = Date.now();
    
    for (const test of TESTS) {
        const result = await runTest(test);
        results.push(result);
    }
    
    const totalDuration = Date.now() - startTime;
    const passed = results.filter(r => r.success).length;
    const failed = results.filter(r => !r.success).length;
    
    // Final Report
    console.log('\n');
    console.log('╔════════════════════════════════════════════════════════════════╗');
    console.log('║                    TEST SUITE REPORT                           ║');
    console.log('╠════════════════════════════════════════════════════════════════╣');
    
    results.forEach(r => {
        const status = r.success ? '✓ PASS' : '✗ FAIL';
        const line = `║ ${r.id}: ${r.name.padEnd(35)} ${status.padEnd(10)} ${(r.duration + 'ms').padStart(8)} ║`;
        console.log(line);
    });
    
    console.log('╠════════════════════════════════════════════════════════════════╣');
    console.log(`║ Total: ${passed} PASSED, ${failed} FAILED                                      ║`.slice(0, 67) + '║');
    console.log(`║ Duration: ${totalDuration}ms                                              ║`.slice(0, 67) + '║');
    console.log(`║ Success Rate: ${Math.round((passed / TESTS.length) * 100)}%                                             ║`.slice(0, 67) + '║');
    console.log('╚════════════════════════════════════════════════════════════════╝');
    console.log('');
    
    return {
        total: TESTS.length,
        passed,
        failed,
        successRate: Math.round((passed / TESTS.length) * 100),
        duration: totalDuration,
        results
    };
}

// Run if executed directly
if (require.main === module) {
    runAllTests()
        .then(report => {
            process.exit(report.failed > 0 ? 1 : 0);
        })
        .catch(err => {
            console.error('Test suite failed:', err);
            process.exit(1);
        });
}

module.exports = { runAllTests, runTest, TESTS };
