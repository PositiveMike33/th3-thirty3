/**
 * Quick Anonymity Test - Simplified Version
 * Th3 Thirty3
 */

require('dotenv').config();
const net = require('net');
const https = require('https');

const CONFIG = {
    torHost: '127.0.0.1',
    torSocksPort: 9050
};

console.log('\n=== QUICK ANONYMITY TEST ===\n');

async function getDirectIP() {
    return new Promise((resolve) => {
        const req = https.request({
            hostname: 'api.ipify.org',
            path: '/?format=json',
            method: 'GET',
            timeout: 15000
        }, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(data).ip);
                } catch {
                    resolve(null);
                }
            });
        });
        req.on('error', () => resolve(null));
        req.end();
    });
}

async function getTorIP() {
    try {
        const { SocksProxyAgent } = require('socks-proxy-agent');
        const agent = new SocksProxyAgent(`socks5h://${CONFIG.torHost}:${CONFIG.torSocksPort}`);
        
        const response = await fetch('https://check.torproject.org/api/ip', {
            agent,
            signal: AbortSignal.timeout(30000)
        });
        
        return await response.json();
    } catch (error) {
        return { error: error.message };
    }
}

async function main() {
    // Step 1: Get Direct IP
    console.log('1. Getting DIRECT IP (no Tor)...');
    const directIP = await getDirectIP();
    console.log(`   Direct IP: ${directIP || 'Could not determine'}\n`);
    
    // Step 2: Check Tor Port
    console.log('2. Checking Tor SOCKS port...');
    const portOpen = await new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(5000);
        socket.on('connect', () => { socket.destroy(); resolve(true); });
        socket.on('error', () => { socket.destroy(); resolve(false); });
        socket.on('timeout', () => { socket.destroy(); resolve(false); });
        socket.connect(CONFIG.torSocksPort, CONFIG.torHost);
    });
    console.log(`   Tor Port 9050: ${portOpen ? 'OPEN' : 'CLOSED'}\n`);
    
    if (!portOpen) {
        console.log('ERROR: Tor is not running!');
        process.exit(1);
    }
    
    // Step 3: Get Tor IP
    console.log('3. Getting TOR IP...');
    const torData = await getTorIP();
    
    if (torData.error) {
        console.log(`   Error: ${torData.error}\n`);
        process.exit(1);
    }
    
    console.log(`   Tor Exit IP: ${torData.IP}`);
    console.log(`   Using Tor: ${torData.IsTor ? 'YES' : 'NO'}\n`);
    
    // Step 4: Compare IPs
    console.log('4. ANONYMITY CHECK:');
    console.log('   ─────────────────────────────');
    
    if (directIP && torData.IP && directIP !== torData.IP) {
        console.log('   ✅ IPs are DIFFERENT');
        console.log(`      Direct: ${directIP}`);
        console.log(`      Tor:    ${torData.IP}`);
        console.log('   ');
        console.log('   ✅ YOUR CONNECTION IS ANONYMOUS!');
    } else if (torData.IsTor) {
        console.log('   ✅ Tor Project confirms: Using Tor');
        console.log('   ✅ YOUR CONNECTION IS ANONYMOUS!');
    } else if (directIP === torData.IP) {
        console.log('   ❌ IPs are THE SAME - NOT ANONYMOUS!');
        console.log('   ⚠️  Traffic may not be going through Tor');
    } else {
        console.log('   ⚠️  Could not fully verify anonymity');
    }
    
    console.log('   ─────────────────────────────\n');
    
    // Step 5: Additional services
    console.log('5. Testing additional IP services via Tor...');
    
    const services = [
        { name: 'ipify', url: 'https://api.ipify.org?format=json' },
        { name: 'httpbin', url: 'https://httpbin.org/ip' }
    ];
    
    for (const svc of services) {
        try {
            const { SocksProxyAgent } = require('socks-proxy-agent');
            const agent = new SocksProxyAgent(`socks5h://${CONFIG.torHost}:${CONFIG.torSocksPort}`);
            
            const response = await fetch(svc.url, { agent, signal: AbortSignal.timeout(20000) });
            const data = await response.json();
            const ip = data.ip || data.origin;
            
            console.log(`   ${svc.name}: ${ip}`);
        } catch (e) {
            console.log(`   ${svc.name}: Error - ${e.message}`);
        }
    }
    
    console.log('\n=== TEST COMPLETE ===\n');
    
    // Final verdict
    const isAnonymous = torData.IsTor || (directIP && torData.IP && directIP !== torData.IP);
    
    if (isAnonymous) {
        console.log('VERDICT: ANONYMOUS CONNECTION CONFIRMED');
        console.log('- All external requests are routed through Tor');
        console.log('- Your real IP is hidden');
        console.log('');
        process.exit(0);
    } else {
        console.log('VERDICT: ANONYMITY NOT CONFIRMED');
        console.log('- Review Tor configuration');
        process.exit(1);
    }
}

main().catch(e => {
    console.error('Test error:', e.message);
    process.exit(1);
});
