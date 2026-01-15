
/**
 * CLOUD SURVIVAL TEST - Node.js Edition
 * Replaces hardware stress tests with Network & API Latency tests.
 */

require('dotenv').config(); // Load from server/.env implicitly or ./
const https = require('https');
const dns = require('dns');

const CONFIG = {
    maxLatency: 1500, // ms
    endpoints: {
        internet: '1.1.1.1',
        gemini: 'generativelanguage.googleapis.com'
    }
};

const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';

function log(msg, type = 'info') {
    const timestamp = new Date().toISOString();
    const color = type === 'error' ? RED : type === 'success' ? GREEN : type === 'warn' ? YELLOW : RESET;
    console.log(`${color}[${timestamp}] ${msg}${RESET}`);
}

async function testDNS() {
    return new Promise((resolve, reject) => {
        const start = Date.now();
        dns.lookup('google.com', (err) => {
            if (err) {
                log(`DNS Resolution Failed: ${err.code}`, 'error');
                resolve(false);
            } else {
                const latency = Date.now() - start;
                log(`DNS Resolution OK (${latency}ms)`, 'success');
                resolve(true);
            }
        });
    });
}

function httpsRequest(options, name) {
    return new Promise((resolve) => {
        const start = Date.now();
        const req = https.request(options, (res) => {
            const latency = Date.now() - start;
            let body = '';
            res.on('data', c => body += c);
            res.on('end', () => {
                resolve({
                    statusCode: res.statusCode,
                    latency,
                    body
                });
            });
        });

        req.on('error', (e) => {
            log(`${name} Connection Error: ${e.message}`, 'error');
            resolve({ statusCode: 0, latency: 0, error: e });
        });

        req.setTimeout(5000, () => {
            req.destroy();
            log(`${name} Timeout`, 'error');
            resolve({ statusCode: 408, latency: 5000 });
        });

        req.end();
    });
}

async function testGeminiAuth() {
    const key = process.env.GEMINI_API_KEY;
    if (!key) {
        log('SKIP: GEMINI_API_KEY not found in .env', 'warn');
        return;
    }

    const options = {
        hostname: CONFIG.endpoints.gemini,
        path: `/v1beta/models?key=${key}`,
        method: 'GET'
    };

    const result = await httpsRequest(options, 'Gemini API');

    if (result.statusCode === 200) {
        log(`Gemini Auth OK (Latency: ${result.latency}ms)`, 'success');
        if (result.latency > CONFIG.maxLatency) {
            log(`WARNING: High Latency > ${CONFIG.maxLatency}ms`, 'warn');
        }
    } else {
        log(`Gemini Auth FAILED (Code: ${result.statusCode})`, 'error');
        try {
            const err = JSON.parse(result.body);
            log(`API Error: ${err.error?.message || result.body}`, 'error');
        } catch { } // ignore parse error
    }
}

async function runTests() {
    console.log('>>> Starting Cloud Connectivity Protocols...\n');

    // 1. Uplink
    const dnsOk = await testDNS();
    if (!dnsOk) {
        log('CRITICAL: No Internet Access. Aborting.', 'error');
        process.exit(1);
    }

    // 2. Gemini
    await testGeminiAuth();

    // 3. OpenAI (Optional)
    if (process.env.OPENAI_API_KEY) {
        // Implement similar test if needed
        log('OpenAI Key detected (Test not implemented yet)', 'info');
    }

    console.log('\n>>> Protocol Complete.');
}

runTests();
