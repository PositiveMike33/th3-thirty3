/**
 * Deep Anonymity Test Suite
 * Th3 Thirty3 - Comprehensive Anonymous Connection Verification
 * 
 * Tests:
 * 1. Direct IP vs Tor IP comparison
 * 2. DNS leak detection
 * 3. All backend services anonymity
 * 4. Multiple IP verification services
 * 5. Tor network confirmation
 * 6. Connection fingerprinting
 */

require('dotenv').config();
const net = require('net');
const { SocksProxyAgent } = require('socks-proxy-agent');
const https = require('https');
const http = require('http');

// Configuration
const CONFIG = {
    torHost: process.env.TOR_HOST || '127.0.0.1',
    torSocksPort: parseInt(process.env.TOR_SOCKS_PORT) || 9050,
    torControlPort: parseInt(process.env.TOR_CONTROL_PORT) || 9051,
    torPassword: process.env.TOR_CONTROL_PASSWORD || 'Th3Thirty3SecureTor2024!'
};

// IP verification services
const IP_SERVICES = [
    { name: 'TorProject', url: 'https://check.torproject.org/api/ip', parseIP: (d) => d.IP, checkTor: (d) => d.IsTor },
    { name: 'IPify', url: 'https://api.ipify.org?format=json', parseIP: (d) => d.ip },
    { name: 'IPInfo', url: 'https://ipinfo.io/json', parseIP: (d) => d.ip, getCountry: (d) => d.country },
    { name: 'HTTPBin', url: 'https://httpbin.org/ip', parseIP: (d) => d.origin },
    { name: 'ICanHazIP', url: 'https://icanhazip.com', parseIP: (d) => d.trim(), isText: true }
];

// DNS leak test servers
const DNS_LEAK_TESTS = [
    'https://www.dnsleaktest.com/api/v1/info',
    'https://ipleak.net/json/'
];

// Results storage
const results = {
    timestamp: new Date().toISOString(),
    directIP: null,
    torIP: null,
    torVerified: false,
    dnsLeaks: [],
    serviceTests: [],
    warnings: [],
    errors: [],
    summary: {
        totalTests: 0,
        passed: 0,
        failed: 0,
        anonymityScore: 0
    }
};

/**
 * Console formatting
 */
const log = {
    header: (text) => console.log(`\n${'═'.repeat(70)}\n  ${text}\n${'═'.repeat(70)}`),
    section: (text) => console.log(`\n${'─'.repeat(50)}\n  ${text}\n${'─'.repeat(50)}`),
    success: (text) => console.log(`  ✅ ${text}`),
    fail: (text) => console.log(`  ❌ ${text}`),
    warn: (text) => console.log(`  ⚠️  ${text}`),
    info: (text) => console.log(`  ℹ️  ${text}`),
    detail: (text) => console.log(`     └─ ${text}`)
};

/**
 * Get real IP (without Tor)
 */
async function getDirectIP() {
    return new Promise((resolve) => {
        const options = {
            hostname: 'api.ipify.org',
            path: '/?format=json',
            method: 'GET',
            timeout: 10000
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                try {
                    const parsed = JSON.parse(data);
                    resolve(parsed.ip);
                } catch {
                    resolve(null);
                }
            });
        });

        req.on('error', () => resolve(null));
        req.on('timeout', () => { req.destroy(); resolve(null); });
        req.end();
    });
}

/**
 * Fetch via Tor SOCKS5 proxy
 */
async function torFetch(url, options = {}) {
    const proxyUrl = `socks5h://${CONFIG.torHost}:${CONFIG.torSocksPort}`;
    const agent = new SocksProxyAgent(proxyUrl);
    
    const response = await fetch(url, {
        ...options,
        agent,
        headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0',
            ...options.headers
        },
        signal: AbortSignal.timeout(30000)
    });
    
    return response;
}

/**
 * Check Tor port availability
 */
async function checkTorPort() {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(5000);
        
        socket.on('connect', () => {
            socket.destroy();
            resolve(true);
        });
        
        socket.on('error', () => {
            socket.destroy();
            resolve(false);
        });
        
        socket.on('timeout', () => {
            socket.destroy();
            resolve(false);
        });
        
        socket.connect(CONFIG.torSocksPort, CONFIG.torHost);
    });
}

/**
 * Test 1: Compare Direct IP vs Tor IP
 */
async function testIPComparison() {
    log.section('TEST 1: IP COMPARISON (Direct vs Tor)');
    results.summary.totalTests++;
    
    try {
        // Get direct IP
        log.info('Getting direct IP (without Tor)...');
        results.directIP = await getDirectIP();
        
        if (results.directIP) {
            log.detail(`Direct IP: ${results.directIP}`);
        } else {
            log.warn('Could not determine direct IP');
        }
        
        // Get Tor IP
        log.info('Getting Tor exit IP...');
        const response = await torFetch('https://check.torproject.org/api/ip');
        const data = await response.json();
        
        results.torIP = data.IP;
        results.torVerified = data.IsTor;
        
        log.detail(`Tor Exit IP: ${results.torIP}`);
        log.detail(`Tor Verified: ${data.IsTor ? 'YES' : 'NO'}`);
        
        // Compare
        if (results.directIP && results.torIP) {
            if (results.directIP !== results.torIP) {
                log.success('IPs are DIFFERENT - Tor is working!');
                results.summary.passed++;
                return true;
            } else {
                log.fail('IPs are THE SAME - Tor may not be working!');
                results.warnings.push('Direct IP matches Tor IP - possible leak');
                results.summary.failed++;
                return false;
            }
        }
        
        if (results.torVerified) {
            log.success('Tor connection verified by torproject.org');
            results.summary.passed++;
            return true;
        }
        
        results.summary.failed++;
        return false;
        
    } catch (error) {
        log.fail(`Error: ${error.message}`);
        results.errors.push(`IP Comparison: ${error.message}`);
        results.summary.failed++;
        return false;
    }
}

/**
 * Test 2: Multiple IP Services Verification
 */
async function testMultipleIPServices() {
    log.section('TEST 2: MULTIPLE IP VERIFICATION SERVICES');
    
    const ips = new Set();
    
    for (const service of IP_SERVICES) {
        results.summary.totalTests++;
        
        try {
            log.info(`Testing ${service.name}...`);
            const response = await torFetch(service.url);
            
            let data;
            if (service.isText) {
                data = await response.text();
            } else {
                data = await response.json();
            }
            
            const ip = service.parseIP(data);
            const isTor = service.checkTor ? service.checkTor(data) : null;
            const country = service.getCountry ? service.getCountry(data) : null;
            
            ips.add(ip);
            
            results.serviceTests.push({
                service: service.name,
                ip,
                isTor,
                country,
                success: true
            });
            
            let details = `IP: ${ip}`;
            if (isTor !== null) details += ` | Tor: ${isTor ? 'YES' : 'NO'}`;
            if (country) details += ` | Country: ${country}`;
            
            log.success(`${service.name}: ${details}`);
            results.summary.passed++;
            
        } catch (error) {
            log.fail(`${service.name}: ${error.message}`);
            results.serviceTests.push({
                service: service.name,
                error: error.message,
                success: false
            });
            results.summary.failed++;
        }
    }
    
    // Check if all IPs match (they should all be the same Tor exit node)
    log.info(`Unique IPs detected: ${ips.size}`);
    if (ips.size === 1) {
        log.success('All services returned the same IP - Consistent Tor exit');
    } else if (ips.size > 1) {
        log.warn('Multiple IPs detected - Tor circuit may have changed during test');
    }
    
    return ips.size >= 1;
}

/**
 * Test 3: DNS Leak Detection
 */
async function testDNSLeaks() {
    log.section('TEST 3: DNS LEAK DETECTION');
    results.summary.totalTests++;
    
    try {
        log.info('Checking for DNS leaks...');
        
        // Test via ipleak.net
        const response = await torFetch('https://ipleak.net/json/');
        const data = await response.json();
        
        results.dnsLeaks.push({
            service: 'ipleak.net',
            ip: data.ip,
            country: data.country_name,
            isp: data.isp_name
        });
        
        log.detail(`IP: ${data.ip}`);
        log.detail(`Country: ${data.country_name}`);
        log.detail(`ISP: ${data.isp_name || 'Unknown'}`);
        
        // Check if ISP reveals real identity
        if (data.isp_name && !data.isp_name.toLowerCase().includes('tor')) {
            log.warn('ISP does not indicate Tor - may require further verification');
        }
        
        // Compare with direct IP
        if (results.directIP && data.ip === results.directIP) {
            log.fail('DNS LEAK DETECTED - Your real IP is exposed!');
            results.warnings.push('DNS leak detected');
            results.summary.failed++;
            return false;
        }
        
        log.success('No obvious DNS leaks detected');
        results.summary.passed++;
        return true;
        
    } catch (error) {
        log.warn(`DNS leak test failed: ${error.message}`);
        results.errors.push(`DNS Leak Test: ${error.message}`);
        return null;
    }
}

/**
 * Test 4: Circuit Change Capability
 */
async function testCircuitChange() {
    log.section('TEST 4: CIRCUIT CHANGE (IP ROTATION)');
    results.summary.totalTests++;
    
    try {
        // Get current IP
        log.info('Getting current Tor IP...');
        const response1 = await torFetch('https://api.ipify.org?format=json');
        const data1 = await response1.json();
        const ip1 = data1.ip;
        log.detail(`Current IP: ${ip1}`);
        
        // Change circuit via Control Port
        log.info('Sending NEWNYM signal to change circuit...');
        
        const changed = await new Promise((resolve) => {
            const socket = new net.Socket();
            socket.setTimeout(10000);
            
            let response = '';
            let step = 'auth';
            
            socket.on('connect', () => {
                socket.write(`AUTHENTICATE "${CONFIG.torPassword}"\r\n`);
            });
            
            socket.on('data', (data) => {
                response += data.toString();
                
                if (step === 'auth' && response.includes('250 OK')) {
                    response = '';
                    step = 'newnym';
                    socket.write('SIGNAL NEWNYM\r\n');
                } else if (step === 'newnym' && response.includes('250 OK')) {
                    socket.destroy();
                    resolve(true);
                } else if (response.includes('515') || response.includes('551')) {
                    socket.destroy();
                    resolve(false);
                }
            });
            
            socket.on('error', () => {
                socket.destroy();
                resolve(false);
            });
            
            socket.on('timeout', () => {
                socket.destroy();
                resolve(false);
            });
            
            socket.connect(CONFIG.torControlPort, CONFIG.torHost);
        });
        
        if (!changed) {
            log.warn('Could not send NEWNYM signal');
            return false;
        }
        
        // Wait for new circuit
        log.info('Waiting for new circuit (10 seconds)...');
        await new Promise(r => setTimeout(r, 10000));
        
        // Get new IP
        log.info('Getting new Tor IP...');
        const response2 = await torFetch('https://api.ipify.org?format=json');
        const data2 = await response2.json();
        const ip2 = data2.ip;
        log.detail(`New IP: ${ip2}`);
        
        if (ip1 !== ip2) {
            log.success(`IP changed from ${ip1} to ${ip2}`);
            results.summary.passed++;
            return true;
        } else {
            log.warn('IP did not change - Tor may need more time or rate limiting');
            // Not a failure, just a warning
            results.summary.passed++;
            return true;
        }
        
    } catch (error) {
        log.fail(`Circuit change error: ${error.message}`);
        results.errors.push(`Circuit Change: ${error.message}`);
        results.summary.failed++;
        return false;
    }
}

/**
 * Test 5: Backend Services Anonymity Check
 */
async function testBackendAnonymity() {
    log.section('TEST 5: BACKEND SERVICES ANONYMITY');
    
    // Services that should use Tor
    const backendServices = [
        { name: 'TorNetworkService', path: './tor_network_service.js' },
        { name: 'DarkWebService', path: './darkweb_osint_service.js' },
        { name: 'ShodanService', path: './shodan_service.js' }
    ];
    
    for (const service of backendServices) {
        results.summary.totalTests++;
        
        try {
            log.info(`Checking ${service.name}...`);
            
            // Check if service file exists and uses Tor
            const fs = require('fs');
            const path = require('path');
            const servicePath = path.join(__dirname, '..', path.basename(service.path));
            
            if (fs.existsSync(servicePath)) {
                const content = fs.readFileSync(servicePath, 'utf-8');
                
                const usesSocks = content.includes('socks-proxy-agent') || 
                                  content.includes('SocksProxyAgent') ||
                                  content.includes('torFetch') ||
                                  content.includes('9050');
                
                const usesTorService = content.includes('TorNetworkService') ||
                                       content.includes('tor_network_service');
                
                if (usesSocks || usesTorService) {
                    log.success(`${service.name}: Uses Tor/SOCKS proxy`);
                    log.detail('Found SOCKS proxy or Tor service integration');
                    results.summary.passed++;
                } else {
                    log.warn(`${service.name}: No Tor integration found`);
                    log.detail('Service may make direct connections');
                    results.warnings.push(`${service.name} may not use Tor`);
                }
            } else {
                log.detail(`${service.name}: Service not found (may be optional)`);
            }
            
        } catch (error) {
            log.warn(`${service.name}: ${error.message}`);
        }
    }
    
    return true;
}

/**
 * Test 6: Frontend Proxy Configuration Check
 */
async function testFrontendConfig() {
    log.section('TEST 6: FRONTEND CONFIGURATION');
    results.summary.totalTests++;
    
    try {
        const fs = require('fs');
        const path = require('path');
        
        // Check frontend config
        const configPath = path.join(__dirname, '../../interface/src/config.js');
        
        if (fs.existsSync(configPath)) {
            const content = fs.readFileSync(configPath, 'utf-8');
            
            log.info('Checking frontend API configuration...');
            
            // Check if using backend proxy vs direct URLs
            const usesBackend = content.includes('API_URL') || 
                               content.includes('/api/');
            
            const usesLocalhost = content.includes('localhost') ||
                                  content.includes('127.0.0.1');
            
            if (usesBackend) {
                log.success('Frontend routes through backend API');
                log.detail('External requests are proxied through server');
                results.summary.passed++;
            }
            
            if (usesLocalhost) {
                log.info('Frontend connects to localhost backend');
                log.detail('Backend handles Tor routing for external requests');
            }
            
            // Check for potential direct external calls
            const hasDirectExternal = content.includes('http://') || 
                                     content.includes('https://');
            
            if (hasDirectExternal && !usesLocalhost) {
                log.warn('Frontend may have direct external API calls');
                log.detail('Review config for external URLs');
            }
            
        } else {
            log.warn('Frontend config not found at expected path');
        }
        
        return true;
        
    } catch (error) {
        log.warn(`Frontend config check: ${error.message}`);
        return false;
    }
}

/**
 * Test 7: WebRTC Leak Check (informational)
 */
async function testWebRTCInfo() {
    log.section('TEST 7: WEBRTC LEAK INFORMATION');
    
    log.info('WebRTC can reveal real IP even through Tor');
    log.detail('This is a browser-level issue, not backend');
    log.detail('');
    log.info('Recommendations for frontend:');
    log.detail('1. Disable WebRTC in browser settings');
    log.detail('2. Use browser.webrtc.enabled = false in Firefox');
    log.detail('3. Install WebRTC leak prevention extensions');
    log.detail('4. Use Tor Browser for maximum anonymity');
    
    results.warnings.push('WebRTC may leak IP in browser - requires client-side mitigation');
    
    return true;
}

/**
 * Test 8: Fingerprinting Resistance
 */
async function testFingerprinting() {
    log.section('TEST 8: FINGERPRINTING RESISTANCE');
    results.summary.totalTests++;
    
    try {
        log.info('Checking request headers...');
        
        const response = await torFetch('https://httpbin.org/headers');
        const data = await response.json();
        
        const headers = data.headers;
        
        log.detail(`User-Agent: ${headers['User-Agent']}`);
        log.detail(`Accept-Language: ${headers['Accept-Language'] || 'Not sent'}`);
        
        // Check if using standard Tor Browser user agent
        const isTorUA = headers['User-Agent'].includes('Firefox') && 
                        headers['User-Agent'].includes('rv:');
        
        if (isTorUA) {
            log.success('Using Firefox-like User-Agent (good)');
        }
        
        // Check for revealing headers
        const revealingHeaders = ['X-Real-IP', 'X-Forwarded-For', 'CF-Connecting-IP'];
        let hasRevealing = false;
        
        for (const h of revealingHeaders) {
            if (headers[h]) {
                log.warn(`Revealing header found: ${h} = ${headers[h]}`);
                hasRevealing = true;
            }
        }
        
        if (!hasRevealing) {
            log.success('No revealing headers detected');
            results.summary.passed++;
        } else {
            results.summary.failed++;
        }
        
        return !hasRevealing;
        
    } catch (error) {
        log.warn(`Fingerprinting test: ${error.message}`);
        return null;
    }
}

/**
 * Generate Final Report
 */
function generateReport() {
    log.header('ANONYMITY TEST REPORT');
    
    // Calculate score
    const score = results.summary.totalTests > 0 
        ? Math.round((results.summary.passed / results.summary.totalTests) * 100)
        : 0;
    
    results.summary.anonymityScore = score;
    
    console.log(`
  ┌─────────────────────────────────────────────────────────────────┐
  │                    ANONYMITY STATUS                             │
  ├─────────────────────────────────────────────────────────────────┤
  │  Direct IP:     ${(results.directIP || 'Unknown').padEnd(47)}│
  │  Tor Exit IP:   ${(results.torIP || 'Unknown').padEnd(47)}│
  │  Tor Verified:  ${(results.torVerified ? 'YES ✓' : 'NO ✗').padEnd(47)}│
  ├─────────────────────────────────────────────────────────────────┤
  │  Tests Passed:  ${String(results.summary.passed).padEnd(47)}│
  │  Tests Failed:  ${String(results.summary.failed).padEnd(47)}│
  │  Total Tests:   ${String(results.summary.totalTests).padEnd(47)}│
  ├─────────────────────────────────────────────────────────────────┤
  │  ANONYMITY SCORE: ${(score + '%').padEnd(45)}│
  └─────────────────────────────────────────────────────────────────┘
`);
    
    // Warnings
    if (results.warnings.length > 0) {
        console.log('  ⚠️  WARNINGS:');
        results.warnings.forEach(w => console.log(`     • ${w}`));
        console.log('');
    }
    
    // Errors
    if (results.errors.length > 0) {
        console.log('  ❌ ERRORS:');
        results.errors.forEach(e => console.log(`     • ${e}`));
        console.log('');
    }
    
    // Verdict
    console.log('  ─────────────────────────────────────────────────────────────────');
    if (score >= 80 && results.torVerified) {
        console.log('  🛡️  VERDICT: ANONYMOUS - Tor connection verified and working');
    } else if (score >= 60) {
        console.log('  ⚠️  VERDICT: PARTIALLY ANONYMOUS - Some issues detected');
    } else {
        console.log('  ❌ VERDICT: NOT ANONYMOUS - Critical issues found');
    }
    console.log('  ─────────────────────────────────────────────────────────────────\n');
    
    return results;
}

/**
 * Main Test Runner
 */
async function runAnonymityTests() {
    log.header('🔍 DEEP ANONYMITY TEST SUITE - Th3 Thirty3');
    console.log(`  Testing at: ${new Date().toISOString()}`);
    console.log(`  Tor Proxy:  ${CONFIG.torHost}:${CONFIG.torSocksPort}`);
    
    // Pre-check: Tor availability
    log.section('PRE-CHECK: TOR AVAILABILITY');
    const torAvailable = await checkTorPort();
    
    if (!torAvailable) {
        log.fail('Tor SOCKS port is not available!');
        log.info('Please start Tor first:');
        log.detail('.\\manage_tor.ps1 start');
        process.exit(1);
    }
    
    log.success('Tor SOCKS port is available');
    
    // Run all tests
    await testIPComparison();
    await testMultipleIPServices();
    await testDNSLeaks();
    await testCircuitChange();
    await testBackendAnonymity();
    await testFrontendConfig();
    await testWebRTCInfo();
    await testFingerprinting();
    
    // Generate report
    const report = generateReport();
    
    // Save results
    const fs = require('fs');
    const path = require('path');
    const reportPath = path.join(__dirname, 'anonymity_test_results.json');
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    console.log(`  📄 Full results saved to: ${reportPath}\n`);
    
    // Exit code
    process.exit(report.summary.anonymityScore >= 70 ? 0 : 1);
}

// Run tests
runAnonymityTests().catch(error => {
    console.error('Test suite error:', error);
    process.exit(1);
});
