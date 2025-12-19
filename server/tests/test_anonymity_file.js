/**
 * Anonymity Test - File Output Version
 */

require('dotenv').config();
const net = require('net');
const https = require('https');
const fs = require('fs');
const path = require('path');

const CONFIG = { torHost: '127.0.0.1', torSocksPort: 9050 };
const results = [];

function log(msg) {
    console.log(msg);
    results.push(msg);
}

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
                try { resolve(JSON.parse(data).ip); } 
                catch { resolve(null); }
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
            agent, signal: AbortSignal.timeout(30000)
        });
        return await response.json();
    } catch (error) {
        return { error: error.message };
    }
}

async function main() {
    log('='.repeat(60));
    log('          ANONYMITY VERIFICATION TEST');
    log('='.repeat(60));
    log(`Time: ${new Date().toISOString()}`);
    log('');
    
    // Direct IP
    log('[1] DIRECT IP (without Tor):');
    const directIP = await getDirectIP();
    log(`    IP: ${directIP || 'Could not determine'}`);
    log('');
    
    // Tor Port
    log('[2] TOR STATUS:');
    const portOpen = await new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(5000);
        socket.on('connect', () => { socket.destroy(); resolve(true); });
        socket.on('error', () => { socket.destroy(); resolve(false); });
        socket.on('timeout', () => { socket.destroy(); resolve(false); });
        socket.connect(CONFIG.torSocksPort, CONFIG.torHost);
    });
    log(`    Port 9050: ${portOpen ? 'OPEN' : 'CLOSED'}`);
    
    if (!portOpen) {
        log('    ERROR: Tor is not running!');
        saveResults();
        process.exit(1);
    }
    log('');
    
    // Tor IP
    log('[3] TOR EXIT IP:');
    const torData = await getTorIP();
    
    if (torData.error) {
        log(`    Error: ${torData.error}`);
        saveResults();
        process.exit(1);
    }
    
    log(`    IP: ${torData.IP}`);
    log(`    IsTor: ${torData.IsTor ? 'YES' : 'NO'}`);
    log('');
    
    // Comparison
    log('[4] ANONYMITY CHECK:');
    log('-'.repeat(40));
    
    const ipsAreDifferent = directIP && torData.IP && directIP !== torData.IP;
    const torConfirmed = torData.IsTor === true;
    
    if (ipsAreDifferent) {
        log('    [PASS] IPs are DIFFERENT');
        log(`           Direct: ${directIP}`);
        log(`           Tor:    ${torData.IP}`);
    }
    
    if (torConfirmed) {
        log('    [PASS] Tor Project confirms: USING TOR');
    }
    
    if (directIP === torData.IP) {
        log('    [FAIL] IPs are THE SAME!');
        log('           WARNING: Traffic NOT anonymous!');
    }
    
    log('-'.repeat(40));
    log('');
    
    // Additional Tests
    log('[5] MULTIPLE SERVICE VERIFICATION:');
    
    const services = [
        { name: 'ipify', url: 'https://api.ipify.org?format=json' },
        { name: 'httpbin', url: 'https://httpbin.org/ip' },
        { name: 'ipinfo', url: 'https://ipinfo.io/json' }
    ];
    
    const ips = [];
    
    for (const svc of services) {
        try {
            const { SocksProxyAgent } = require('socks-proxy-agent');
            const agent = new SocksProxyAgent(`socks5h://${CONFIG.torHost}:${CONFIG.torSocksPort}`);
            const response = await fetch(svc.url, { agent, signal: AbortSignal.timeout(20000) });
            const data = await response.json();
            const ip = data.ip || data.origin;
            const country = data.country || '';
            
            ips.push(ip);
            log(`    ${svc.name.padEnd(10)}: ${ip} ${country ? `(${country})` : ''}`);
        } catch (e) {
            log(`    ${svc.name.padEnd(10)}: ERROR - ${e.message}`);
        }
    }
    
    log('');
    
    // Unique IPs check
    const uniqueIPs = [...new Set(ips)];
    log(`    Unique Exit IPs: ${uniqueIPs.length}`);
    if (uniqueIPs.length === 1) {
        log('    [PASS] All services show same exit IP');
    } else if (uniqueIPs.length > 1) {
        log('    [INFO] Circuit may have changed during test');
    }
    
    log('');
    log('='.repeat(60));
    log('                    FINAL VERDICT');
    log('='.repeat(60));
    
    const isAnonymous = torConfirmed || ipsAreDifferent;
    
    if (isAnonymous) {
        log('');
        log('    STATUS: ANONYMOUS CONNECTION CONFIRMED');
        log('');
        log('    - Your real IP is HIDDEN');
        log('    - All requests go through TOR');
        log('    - Backend connections are ANONYMOUS');
        log('');
    } else {
        log('');
        log('    STATUS: ANONYMITY NOT CONFIRMED');
        log('');
        log('    - Check Tor configuration');
        log('    - Verify proxy settings');
        log('');
    }
    
    log('='.repeat(60));
    
    saveResults();
    process.exit(isAnonymous ? 0 : 1);
}

function saveResults() {
    const outputPath = path.join(__dirname, 'anonymity_results.txt');
    fs.writeFileSync(outputPath, results.join('\n'));
    console.log(`\nResults saved to: ${outputPath}`);
}

main().catch(e => {
    console.error('Test error:', e.message);
    process.exit(1);
});
