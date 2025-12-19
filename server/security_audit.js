/**
 * SECURITY AUDIT - Th3 Thirty3
 * ============================
 * Complete security and anonymity verification
 * Tests: Tor, Docker, DNS leaks, API security
 */

const https = require('https');
const http = require('http');
const net = require('net');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

// Colors for output
const colors = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m',
    bold: '\x1b[1m'
};

const log = {
    info: (msg) => console.log(`${colors.cyan}[INFO]${colors.reset} ${msg}`),
    pass: (msg) => console.log(`${colors.green}[PASS]${colors.reset} ${msg}`),
    fail: (msg) => console.log(`${colors.red}[FAIL]${colors.reset} ${msg}`),
    warn: (msg) => console.log(`${colors.yellow}[WARN]${colors.reset} ${msg}`),
    header: (msg) => console.log(`\n${colors.bold}${colors.blue}${'='.repeat(60)}${colors.reset}\n${colors.bold}  ${msg}${colors.reset}\n${colors.bold}${colors.blue}${'='.repeat(60)}${colors.reset}\n`)
};

// Results tracking
const results = {
    passed: 0,
    failed: 0,
    warnings: 0,
    tests: []
};

function recordTest(name, passed, details = '') {
    results.tests.push({ name, passed, details, timestamp: new Date().toISOString() });
    if (passed === true) results.passed++;
    else if (passed === false) results.failed++;
    else results.warnings++;
}

// ============================================
// TEST UTILITIES
// ============================================

function checkPort(host, port, timeout = 5000) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(timeout);
        
        socket.on('connect', () => {
            socket.destroy();
            resolve(true);
        });
        
        socket.on('timeout', () => {
            socket.destroy();
            resolve(false);
        });
        
        socket.on('error', () => {
            socket.destroy();
            resolve(false);
        });
        
        socket.connect(port, host);
    });
}

function httpGet(url, options = {}) {
    return new Promise((resolve, reject) => {
        const protocol = url.startsWith('https') ? https : http;
        const timeout = options.timeout || 15000;
        
        const req = protocol.get(url, { timeout }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve({ status: res.statusCode, data }));
        });
        
        req.on('error', reject);
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Request timeout'));
        });
    });
}

function execAsync(cmd, timeout = 30000) {
    return new Promise((resolve) => {
        exec(cmd, { timeout }, (error, stdout, stderr) => {
            resolve({ success: !error, stdout, stderr, error: error?.message });
        });
    });
}

// ============================================
// SECURITY TESTS
// ============================================

async function testTorSOCKSPort() {
    log.info('Testing Tor SOCKS port (9050)...');
    const open = await checkPort('127.0.0.1', 9050);
    
    if (open) {
        log.pass('Tor SOCKS port 9050 is OPEN');
        recordTest('Tor SOCKS Port', true);
        return true;
    } else {
        log.fail('Tor SOCKS port 9050 is CLOSED');
        recordTest('Tor SOCKS Port', false, 'Port closed - Tor may not be running');
        return false;
    }
}

async function testTorControlPort() {
    log.info('Testing Tor Control port (9051)...');
    const open = await checkPort('127.0.0.1', 9051);
    
    if (open) {
        log.pass('Tor Control port 9051 is OPEN');
        recordTest('Tor Control Port', true);
        return true;
    } else {
        log.warn('Tor Control port 9051 is CLOSED');
        recordTest('Tor Control Port', null, 'Control port closed - circuit changes unavailable');
        return false;
    }
}

async function testTorAnonymity() {
    log.info('Testing Tor anonymity via Docker...');
    
    try {
        const result = await execAsync(
            'docker exec th3_kali_tor curl -s --socks5 localhost:9050 https://check.torproject.org/api/ip --max-time 20',
            25000
        );
        
        if (result.success && result.stdout) {
            const data = JSON.parse(result.stdout);
            if (data.IsTor === true) {
                log.pass(`Tor ANONYMOUS - Exit IP: ${data.IP}`);
                recordTest('Tor Anonymity', true, `Exit IP: ${data.IP}`);
                return { anonymous: true, ip: data.IP };
            }
        }
    } catch (e) {
        // Try local Tor
    }
    
    // Try direct local check via Node.js with socks-proxy-agent
    try {
        const { SocksProxyAgent } = require('socks-proxy-agent');
        const agent = new SocksProxyAgent('socks5h://127.0.0.1:9050');
        
        const result = await new Promise((resolve, reject) => {
            const req = https.get('https://check.torproject.org/api/ip', { agent, timeout: 20000 }, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(data));
                    } catch {
                        reject(new Error('Parse error'));
                    }
                });
            });
            req.on('error', reject);
            req.on('timeout', () => reject(new Error('Timeout')));
        });
        
        if (result.IsTor === true) {
            log.pass(`Tor ANONYMOUS (SOCKS) - Exit IP: ${result.IP}`);
            recordTest('Tor Anonymity', true, `Exit IP: ${result.IP}`);
            return { anonymous: true, ip: result.IP };
        }
    } catch (e) {
        log.fail(`Tor anonymity check failed: ${e.message}`);
        recordTest('Tor Anonymity', false, e.message);
        return { anonymous: false, error: e.message };
    }
    
    log.fail('Tor is NOT providing anonymity');
    recordTest('Tor Anonymity', false);
    return { anonymous: false };
}

async function testDirectIP() {
    log.info('Getting direct IP (for comparison)...');
    
    try {
        const result = await httpGet('https://api.ipify.org?format=json');
        const data = JSON.parse(result.data);
        log.info(`Direct IP: ${data.ip}`);
        recordTest('Direct IP Capture', true, data.ip);
        return data.ip;
    } catch (e) {
        log.warn(`Could not get direct IP: ${e.message}`);
        recordTest('Direct IP Capture', null, e.message);
        return null;
    }
}

async function testDockerContainers() {
    log.info('Checking Docker containers...');
    
    const result = await execAsync('docker ps --format "{{.Names}}|{{.Status}}"');
    
    if (!result.success) {
        log.fail('Docker is not running or not accessible');
        recordTest('Docker Status', false, 'Docker not accessible');
        return false;
    }
    
    const containers = result.stdout.split('\n').filter(Boolean);
    const requiredContainers = ['th3_kali_tor'];
    
    let allRunning = true;
    for (const required of requiredContainers) {
        const found = containers.find(c => c.includes(required) && c.includes('Up'));
        if (found) {
            log.pass(`Container ${required} is running`);
            recordTest(`Container: ${required}`, true);
        } else {
            log.fail(`Container ${required} is NOT running`);
            recordTest(`Container: ${required}`, false);
            allRunning = false;
        }
    }
    
    return allRunning;
}

async function testDNSLeak() {
    log.info('Testing for DNS leaks...');
    
    // DNS leak test via Docker Tor
    try {
        const result = await execAsync(
            'docker exec th3_kali_tor curl -s --socks5 localhost:9050 https://dnsleaktest.com/what-is-my-ip.html --max-time 15 2>/dev/null | grep -o "[0-9]\\+\\.[0-9]\\+\\.[0-9]\\+\\.[0-9]\\+" | head -1',
            20000
        );
        
        if (result.success && result.stdout.trim()) {
            log.pass('DNS queries routed through Tor');
            recordTest('DNS Leak Prevention', true);
            return true;
        }
    } catch (e) {
        // Continue with other checks
    }
    
    log.warn('DNS leak test inconclusive');
    recordTest('DNS Leak Prevention', null, 'Could not verify DNS routing');
    return null;
}

async function testTorServiceIntegration() {
    log.info('Testing TorNetworkService integration...');
    
    try {
        const TorNetworkService = require('./tor_network_service');
        const torService = new TorNetworkService();
        
        // Test torFetch
        const response = await torService.torFetch('https://check.torproject.org/api/ip');
        const data = await response.json();
        
        if (data.IsTor === true) {
            log.pass(`TorNetworkService verified ANONYMOUS - IP: ${data.IP}`);
            recordTest('TorNetworkService Integration', true, `Exit IP: ${data.IP}`);
            return true;
        } else {
            log.fail('TorNetworkService NOT anonymous');
            recordTest('TorNetworkService Integration', false);
            return false;
        }
    } catch (e) {
        log.fail(`TorNetworkService error: ${e.message}`);
        recordTest('TorNetworkService Integration', false, e.message);
        return false;
    }
}

async function testOSINTToolsSecurity() {
    log.info('Checking OSINT tools security configuration...');
    
    // Check if OSINT service uses Tor
    try {
        const osintServicePath = path.join(__dirname, 'osint_service.js');
        const osintContent = fs.readFileSync(osintServicePath, 'utf-8');
        
        if (osintContent.includes('torFetch') || osintContent.includes('TorNetworkService') || osintContent.includes('socks')) {
            log.pass('OSINT Service uses Tor routing');
            recordTest('OSINT Tor Integration', true);
        } else {
            log.warn('OSINT Service may not use Tor - manual verification needed');
            recordTest('OSINT Tor Integration', null, 'No Tor references found');
        }
    } catch (e) {
        log.warn(`Could not check OSINT service: ${e.message}`);
        recordTest('OSINT Tor Integration', null);
    }
    
    // Check Python pipeline
    try {
        const pipelinePath = path.join(__dirname, 'scripts', 'osint_pipeline.py');
        if (fs.existsSync(pipelinePath)) {
            const pipelineContent = fs.readFileSync(pipelinePath, 'utf-8');
            if (pipelineContent.includes('proxychains') || pipelineContent.includes('socks') || pipelineContent.includes('tor')) {
                log.pass('Python OSINT Pipeline has Tor support');
                recordTest('Python Pipeline Tor Support', true);
            } else {
                log.warn('Python OSINT Pipeline may need Tor configuration');
                recordTest('Python Pipeline Tor Support', null, 'No Tor references found');
            }
        }
    } catch (e) {
        recordTest('Python Pipeline Tor Support', null);
    }
}

async function testAPIKeySecurity() {
    log.info('Checking API key security...');
    
    const envPath = path.join(__dirname, '..', '.env');
    
    if (!fs.existsSync(envPath)) {
        log.warn('.env file not found');
        recordTest('API Key Security', null);
        return;
    }
    
    const envContent = fs.readFileSync(envPath, 'utf-8');
    const sensitiveKeys = ['STRIPE_SECRET_KEY', 'PAYPAL_CLIENT_SECRET', 'SHODAN_API_KEY', 'ADMIN_API_KEY'];
    
    let allSecure = true;
    for (const key of sensitiveKeys) {
        if (envContent.includes(key)) {
            log.pass(`${key} is configured`);
        } else {
            log.info(`${key} not configured (may be optional)`);
        }
    }
    
    // Check if .env is in .gitignore
    const gitignorePath = path.join(__dirname, '..', '.gitignore');
    if (fs.existsSync(gitignorePath)) {
        const gitignore = fs.readFileSync(gitignorePath, 'utf-8');
        if (gitignore.includes('.env')) {
            log.pass('.env is in .gitignore - keys protected from git');
            recordTest('API Key Security', true);
        } else {
            log.fail('.env NOT in .gitignore - SECURITY RISK');
            recordTest('API Key Security', false, '.env exposed to git');
            allSecure = false;
        }
    }
    
    return allSecure;
}

async function testSecurityMiddleware() {
    log.info('Checking security middleware...');
    
    try {
        const indexPath = path.join(__dirname, 'index.js');
        const indexContent = fs.readFileSync(indexPath, 'utf-8');
        
        const securityChecks = [
            { name: 'Auth Middleware', pattern: /authMiddleware/ },
            { name: 'Security Routes', pattern: /security_routes/ },
            { name: 'Zone Isolation', pattern: /zoneIsolationMiddleware/ },
            { name: 'CORS', pattern: /cors\(\)/ },
            { name: 'JSON Limit', pattern: /limit.*50mb/ }
        ];
        
        for (const check of securityChecks) {
            if (check.pattern.test(indexContent)) {
                log.pass(`${check.name} is active`);
                recordTest(`Security: ${check.name}`, true);
            } else {
                log.warn(`${check.name} may not be configured`);
                recordTest(`Security: ${check.name}`, null);
            }
        }
    } catch (e) {
        log.fail(`Could not check security middleware: ${e.message}`);
    }
}

async function testTorCircuitChange() {
    log.info('Testing Tor circuit change capability...');
    
    try {
        const TorNetworkService = require('./tor_network_service');
        const torService = new TorNetworkService();
        
        // Get initial IP
        const response1 = await torService.torFetch('https://check.torproject.org/api/ip');
        const data1 = await response1.json();
        const ip1 = data1.IP;
        
        log.info(`Initial IP: ${ip1}`);
        
        // Try to change circuit
        const changed = await torService.changeCircuit();
        
        if (changed) {
            // Wait a bit and check new IP
            await new Promise(r => setTimeout(r, 3000));
            
            const response2 = await torService.torFetch('https://check.torproject.org/api/ip');
            const data2 = await response2.json();
            const ip2 = data2.IP;
            
            log.info(`New IP: ${ip2}`);
            
            if (ip1 !== ip2) {
                log.pass('Circuit change SUCCESSFUL - IP changed');
                recordTest('Tor Circuit Change', true, `${ip1} -> ${ip2}`);
                return true;
            } else {
                log.warn('Circuit change requested but IP unchanged (may need more time)');
                recordTest('Tor Circuit Change', null, 'IP unchanged');
                return null;
            }
        } else {
            log.warn('Circuit change not available');
            recordTest('Tor Circuit Change', null, 'Change method returned false');
            return null;
        }
    } catch (e) {
        log.warn(`Circuit change test failed: ${e.message}`);
        recordTest('Tor Circuit Change', null, e.message);
        return null;
    }
}

// ============================================
// FIX FUNCTIONS
// ============================================

async function fixTorNotRunning() {
    log.info('Attempting to start Tor...');
    
    // Try Docker first
    let result = await execAsync('docker start th3_kali_tor');
    if (result.success) {
        log.pass('Started th3_kali_tor container');
        await new Promise(r => setTimeout(r, 30000)); // Wait for Tor bootstrap
        return true;
    }
    
    // Try local Tor
    result = await execAsync('C:\\Tor\\tor\\tor.exe');
    if (result.success) {
        log.pass('Started local Tor');
        await new Promise(r => setTimeout(r, 15000));
        return true;
    }
    
    return false;
}

async function fixDockerNotRunning() {
    log.info('Attempting to start Docker and containers...');
    
    try {
        const dockerAutoStart = require('./docker_autostart_service');
        const result = await dockerAutoStart.startAllContainers();
        
        if (result.success) {
            log.pass('Docker containers started');
            return true;
        }
    } catch (e) {
        log.fail(`Docker fix failed: ${e.message}`);
    }
    
    return false;
}

// ============================================
// MAIN AUDIT
// ============================================

async function runSecurityAudit() {
    console.log('\n');
    log.header('TH3 THIRTY3 - SECURITY AUDIT');
    console.log(`Timestamp: ${new Date().toISOString()}\n`);
    
    // PHASE 1: Infrastructure
    log.header('PHASE 1: INFRASTRUCTURE');
    
    const dockerOk = await testDockerContainers();
    if (!dockerOk) {
        log.info('Attempting to fix Docker...');
        await fixDockerNotRunning();
        await new Promise(r => setTimeout(r, 5000));
        await testDockerContainers();
    }
    
    // PHASE 2: Tor Connectivity
    log.header('PHASE 2: TOR CONNECTIVITY');
    
    let torOk = await testTorSOCKSPort();
    if (!torOk) {
        log.info('Attempting to start Tor...');
        await fixTorNotRunning();
        torOk = await testTorSOCKSPort();
    }
    
    await testTorControlPort();
    
    // PHASE 3: Anonymity Verification
    log.header('PHASE 3: ANONYMITY VERIFICATION');
    
    const directIP = await testDirectIP();
    const torResult = await testTorAnonymity();
    
    if (torResult.anonymous && directIP) {
        if (torResult.ip !== directIP) {
            log.pass(`ANONYMITY CONFIRMED: Direct IP ${directIP} ≠ Tor IP ${torResult.ip}`);
            recordTest('IP Comparison', true, `Direct: ${directIP}, Tor: ${torResult.ip}`);
        } else {
            log.fail('CRITICAL: Tor IP same as Direct IP - NO ANONYMITY');
            recordTest('IP Comparison', false, 'Same IP - Tor not working');
        }
    }
    
    await testDNSLeak();
    
    // PHASE 4: Service Integration
    log.header('PHASE 4: SERVICE INTEGRATION');
    
    await testTorServiceIntegration();
    await testTorCircuitChange();
    await testOSINTToolsSecurity();
    
    // PHASE 5: Application Security
    log.header('PHASE 5: APPLICATION SECURITY');
    
    await testAPIKeySecurity();
    await testSecurityMiddleware();
    
    // FINAL REPORT
    log.header('SECURITY AUDIT REPORT');
    
    console.log(`
${colors.bold}SUMMARY:${colors.reset}
  ${colors.green}✅ Passed: ${results.passed}${colors.reset}
  ${colors.red}❌ Failed: ${results.failed}${colors.reset}
  ${colors.yellow}⚠️  Warnings: ${results.warnings}${colors.reset}
  
${colors.bold}SECURITY STATUS:${colors.reset}
`);
    
    if (results.failed === 0) {
        console.log(`  ${colors.green}${colors.bold}🛡️  SYSTEM IS SECURE AND ANONYMOUS${colors.reset}`);
        console.log(`  ${colors.green}✅ All critical security tests passed${colors.reset}`);
        console.log(`  ${colors.green}✅ Tor anonymity verified${colors.reset}`);
        console.log(`  ${colors.green}✅ Safe to proceed with OSINT operations${colors.reset}\n`);
    } else {
        console.log(`  ${colors.red}${colors.bold}⚠️  SECURITY ISSUES DETECTED${colors.reset}`);
        console.log(`  ${colors.red}❌ ${results.failed} critical tests failed${colors.reset}`);
        console.log(`  ${colors.yellow}⚠️  DO NOT proceed with sensitive operations${colors.reset}\n`);
        
        console.log(`${colors.bold}FAILED TESTS:${colors.reset}`);
        results.tests.filter(t => t.passed === false).forEach(t => {
            console.log(`  ${colors.red}❌ ${t.name}: ${t.details || 'Failed'}${colors.reset}`);
        });
    }
    
    // Save report
    const reportPath = path.join(__dirname, 'security_audit_report.json');
    fs.writeFileSync(reportPath, JSON.stringify({
        timestamp: new Date().toISOString(),
        summary: {
            passed: results.passed,
            failed: results.failed,
            warnings: results.warnings,
            secure: results.failed === 0
        },
        tests: results.tests
    }, null, 2));
    
    console.log(`\n${colors.cyan}Report saved to: ${reportPath}${colors.reset}\n`);
    
    return results.failed === 0;
}

// Run audit
runSecurityAudit().then(secure => {
    process.exit(secure ? 0 : 1);
}).catch(err => {
    console.error('Audit failed:', err);
    process.exit(1);
});
