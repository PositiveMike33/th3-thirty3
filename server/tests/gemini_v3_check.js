require('dotenv').config();
const https = require('https');

const API_KEY = process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY;
const PRIMARY_MODEL = process.env.TARGET_MODEL || 'gemini-3-pro-preview';
const BACKUP_MODEL = process.env.FALLBACK_MODEL || 'gemini-3-flash-preview';

const BASE_HOST = 'generativelanguage.googleapis.com';

function log(msg, type = 'info') {
    const icons = { info: 'ℹ️', success: '✅', error: '❌', warn: '⚠️' };
    console.log(`${icons[type] || ''} ${msg}`);
}

if (!API_KEY) {
    log('FATAL: API Key not found in .env', 'error');
    process.exit(1);
}

function callGemini(modelId) {
    return new Promise((resolve) => {
        const payload = JSON.stringify({
            contents: [{ parts: [{ text: "Hello, confirm operational." }] }],
            generationConfig: { maxOutputTokens: 1000 }
        });

        const options = {
            hostname: BASE_HOST,
            path: `/v1beta/models/${modelId}:generateContent?key=${API_KEY}`,
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        };

        const start = Date.now();
        const req = https.request(options, (res) => {
            let body = '';
            res.on('data', c => body += c);
            res.on('end', () => resolve({
                status: res.statusCode,
                body,
                latency: Date.now() - start
            }));
        });

        req.on('error', (e) => resolve({ status: 0, error: e }));
        req.write(payload);
        req.end();
    });
}

async function testModel(modelId, isPrimary) {
    log(`Testing Model: ${modelId}...`, 'info');
    const result = await callGemini(modelId);

    if (result.status === 200) {
        try {
            const data = JSON.parse(result.body);
            const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
            if (text) {
                log(`SUCCESS [${modelId}] - Latency: ${result.latency}ms`, 'success');
                log(`Response: ${text.trim().substring(0, 50)}...`, 'info');
                return true;
            } else {
                log(`Invalid JSON structure: ${result.body}`, 'error');
            }
        } catch (e) {
            log(`JSON Parse Error`, 'error');
        }
    } else {
        log(`FAILED [${modelId}] - Status: ${result.status}`, 'error');
        if (result.status === 404) {
            log(`Model not found (Preview access required?)`, 'warn');
        } else {
            log(`Error: ${result.body}`, 'error');
        }
    }
    return false;
}

async function run() {
    console.log(`>>> TARGET: ${PRIMARY_MODEL} (Backup: ${BACKUP_MODEL})`);

    const primaryOk = await testModel(PRIMARY_MODEL, true);
    if (!primaryOk) {
        log(`Primary model failed. Attempting backup...`, 'warn');
        const backupOk = await testModel(BACKUP_MODEL, false);
        if (!backupOk) {
            log(`ALL MODELS FAILED. System is offline.`, 'error');
            process.exit(1);
        }
    }
    log(`>>> System Operational via Gemini v3.`, 'success');
}

run();
