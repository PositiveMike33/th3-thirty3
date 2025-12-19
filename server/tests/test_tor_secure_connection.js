/**
 * Tor Secure Connection Test
 * Tests Tor configuration with authentication
 */

require('dotenv').config();
const net = require('net');

// Configuration
const TOR_CONFIG = {
    host: process.env.TOR_HOST || '127.0.0.1',
    socksPort: parseInt(process.env.TOR_SOCKS_PORT) || 9050,
    controlPort: parseInt(process.env.TOR_CONTROL_PORT) || 9051,
    controlPassword: process.env.TOR_CONTROL_PASSWORD || 'Th3Thirty3SecureTor2024!'
};

console.log('\n' + '='.repeat(60));
console.log('🔐 TOR SECURE CONNECTION TEST');
console.log('='.repeat(60));

/**
 * Test 1: Check SOCKS Port
 */
async function testSocksPort() {
    console.log('\n[TEST 1] Checking SOCKS Port...');
    
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(5000);
        
        socket.on('connect', () => {
            console.log(`✅ SOCKS Port ${TOR_CONFIG.socksPort} is OPEN`);
            socket.destroy();
            resolve(true);
        });
        
        socket.on('timeout', () => {
            console.log(`❌ SOCKS Port ${TOR_CONFIG.socksPort} TIMEOUT`);
            socket.destroy();
            resolve(false);
        });
        
        socket.on('error', (err) => {
            console.log(`❌ SOCKS Port ${TOR_CONFIG.socksPort} ERROR:`, err.message);
            socket.destroy();
            resolve(false);
        });
        
        socket.connect(TOR_CONFIG.socksPort, TOR_CONFIG.host);
    });
}

/**
 * Test 2: Check Control Port
 */
async function testControlPort() {
    console.log('\n[TEST 2] Checking Control Port...');
    
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(5000);
        
        socket.on('connect', () => {
            console.log(`✅ Control Port ${TOR_CONFIG.controlPort} is OPEN`);
            socket.destroy();
            resolve(true);
        });
        
        socket.on('timeout', () => {
            console.log(`❌ Control Port ${TOR_CONFIG.controlPort} TIMEOUT`);
            socket.destroy();
            resolve(false);
        });
        
        socket.on('error', (err) => {
            console.log(`❌ Control Port ${TOR_CONFIG.controlPort} ERROR:`, err.message);
            socket.destroy();
            resolve(false);
        });
        
        socket.connect(TOR_CONFIG.controlPort, TOR_CONFIG.host);
    });
}

/**
 * Test 3: Authenticate to Control Port
 */
async function testAuthentication() {
    console.log('\n[TEST 3] Testing Authentication...');
    
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(10000);
        
        let response = '';
        let authenticated = false;
        
        socket.on('connect', () => {
            console.log('   → Sending authentication...');
            socket.write(`AUTHENTICATE "${TOR_CONFIG.controlPassword}"\r\n`);
        });
        
        socket.on('data', (data) => {
            response += data.toString();
            
            if (response.includes('250 OK')) {
                console.log('✅ Authentication SUCCESSFUL');
                authenticated = true;
                socket.destroy();
                resolve(true);
            } else if (response.includes('515') || response.includes('551')) {
                console.log('❌ Authentication FAILED');
                console.log('   Response:', response.trim());
                socket.destroy();
                resolve(false);
            }
        });
        
        socket.on('timeout', () => {
            console.log('❌ Authentication TIMEOUT');
            socket.destroy();
            resolve(false);
        });
        
        socket.on('error', (err) => {
            console.log('❌ Authentication ERROR:', err.message);
            socket.destroy();
            resolve(false);
        });
        
        socket.connect(TOR_CONFIG.controlPort, TOR_CONFIG.host);
    });
}

/**
 * Test 4: Send NEWNYM Command (Change Circuit)
 */
async function testCircuitChange() {
    console.log('\n[TEST 4] Testing Circuit Change (NEWNYM)...');
    
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(10000);
        
        let response = '';
        let step = 'auth';
        
        socket.on('connect', () => {
            console.log('   → Authenticating...');
            socket.write(`AUTHENTICATE "${TOR_CONFIG.controlPassword}"\r\n`);
        });
        
        socket.on('data', (data) => {
            response += data.toString();
            
            if (step === 'auth' && response.includes('250 OK')) {
                console.log('   → Sending NEWNYM command...');
                response = '';
                step = 'newnym';
                socket.write('SIGNAL NEWNYM\r\n');
            } else if (step === 'newnym' && response.includes('250 OK')) {
                console.log('✅ Circuit change SUCCESSFUL');
                socket.destroy();
                resolve(true);
            } else if (response.includes('515') || response.includes('551')) {
                console.log('❌ Circuit change FAILED');
                console.log('   Response:', response.trim());
                socket.destroy();
                resolve(false);
            }
        });
        
        socket.on('timeout', () => {
            console.log('❌ Circuit change TIMEOUT');
            socket.destroy();
            resolve(false);
        });
        
        socket.on('error', (err) => {
            console.log('❌ Circuit change ERROR:', err.message);
            socket.destroy();
            resolve(false);
        });
        
        socket.connect(TOR_CONFIG.controlPort, TOR_CONFIG.host);
    });
}

/**
 * Test 5: Verify Tor Connection via check.torproject.org
 */
async function testTorVerification() {
    console.log('\n[TEST 5] Verifying Tor Connection...');
    
    try {
        const { SocksProxyAgent } = require('socks-proxy-agent');
        const agent = new SocksProxyAgent(`socks5h://${TOR_CONFIG.host}:${TOR_CONFIG.socksPort}`);
        
        console.log('   → Fetching via Tor...');
        const response = await fetch('https://check.torproject.org/api/ip', {
            agent,
            signal: AbortSignal.timeout(20000)
        });
        
        const data = await response.json();
        
        console.log('   → Response:', data);
        
        if (data.IsTor) {
            console.log(`✅ Connected via TOR`);
            console.log(`   Exit IP: ${data.IP}`);
            return true;
        } else {
            console.log(`❌ NOT connected via Tor`);
            console.log(`   Direct IP: ${data.IP}`);
            return false;
        }
    } catch (error) {
        console.log('❌ Verification FAILED:', error.message);
        return false;
    }
}

/**
 * Test 6: Get Tor Circuit Info
 */
async function testGetCircuitInfo() {
    console.log('\n[TEST 6] Getting Circuit Information...');
    
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(10000);
        
        let response = '';
        let step = 'auth';
        
        socket.on('connect', () => {
            socket.write(`AUTHENTICATE "${TOR_CONFIG.controlPassword}"\r\n`);
        });
        
        socket.on('data', (data) => {
            response += data.toString();
            
            if (step === 'auth' && response.includes('250 OK')) {
                response = '';
                step = 'getinfo';
                socket.write('GETINFO circuit-status\r\n');
            } else if (step === 'getinfo' && response.includes('250')) {
                console.log('✅ Circuit info retrieved');
                const circuits = response.split('\n').filter(line => line.includes('BUILT'));
                console.log(`   Active circuits: ${circuits.length}`);
                socket.destroy();
                resolve(true);
            }
        });
        
        socket.on('timeout', () => {
            console.log('❌ Circuit info TIMEOUT');
            socket.destroy();
            resolve(false);
        });
        
        socket.on('error', (err) => {
            console.log('❌ Circuit info ERROR:', err.message);
            socket.destroy();
            resolve(false);
        });
        
        socket.connect(TOR_CONFIG.controlPort, TOR_CONFIG.host);
    });
}

/**
 * Run All Tests
 */
async function runAllTests() {
    const results = {
        socksPort: false,
        controlPort: false,
        authentication: false,
        circuitChange: false,
        torVerification: false,
        circuitInfo: false
    };
    
    try {
        results.socksPort = await testSocksPort();
        results.controlPort = await testControlPort();
        
        if (results.controlPort) {
            results.authentication = await testAuthentication();
            
            if (results.authentication) {
                results.circuitChange = await testCircuitChange();
                results.circuitInfo = await testGetCircuitInfo();
            }
        }
        
        if (results.socksPort) {
            results.torVerification = await testTorVerification();
        }
        
    } catch (error) {
        console.error('\n❌ Test suite error:', error.message);
    }
    
    // Summary
    console.log('\n' + '='.repeat(60));
    console.log('📊 TEST SUMMARY');
    console.log('='.repeat(60));
    
    const tests = [
        { name: 'SOCKS Port', result: results.socksPort },
        { name: 'Control Port', result: results.controlPort },
        { name: 'Authentication', result: results.authentication },
        { name: 'Circuit Change', result: results.circuitChange },
        { name: 'Tor Verification', result: results.torVerification },
        { name: 'Circuit Info', result: results.circuitInfo }
    ];
    
    tests.forEach(test => {
        const icon = test.result ? '✅' : '❌';
        console.log(`${icon} ${test.name.padEnd(20)} ${test.result ? 'PASS' : 'FAIL'}`);
    });
    
    const passed = tests.filter(t => t.result).length;
    const total = tests.length;
    
    console.log('\n' + '-'.repeat(60));
    console.log(`Results: ${passed}/${total} tests passed (${Math.round(passed/total*100)}%)`);
    console.log('='.repeat(60) + '\n');
    
    // Return exit code
    process.exit(passed === total ? 0 : 1);
}

// Run tests
runAllTests();
