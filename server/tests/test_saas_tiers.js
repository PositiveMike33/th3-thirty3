// const fetch = require('node-fetch');

const BASE_URL = 'http://localhost:3000';

// Keys from users.json
const KEYS = {
    ADMIN: 'sk-ADMIN-TH3-THIRTY3-MASTER-KEY',
    INITIATE: 'sk-TEST-INITIATE',
    OPERATOR: 'sk-TEST-OPERATOR'
};

async function testEndpoint(name, url, method, body, key, expectedStatus) {
    console.log(`👉 Testing ${name} with key ${key.substring(0, 10)}...`);
    try {
        const options = {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': key
            }
        };
        if (body) options.body = JSON.stringify(body);

        const res = await fetch(url, options);

        if (res.status === expectedStatus) {
            console.log(`✅ PASS: Got ${res.status} as expected.`);
        } else {
            console.error(`❌ FAIL: Expected ${expectedStatus}, got ${res.status}`);
            const text = await res.text();
            console.log("Response:", text.substring(0, 100));
        }
    } catch (e) {
        console.error(`❌ ERROR: ${e.message}`);
    }
}

async function runTests() {
    console.log("🚀 STARTING SAAS TIER AUDIT");

    // 1. Test Chat (Local Model) - Should work for everyone
    await testEndpoint('Chat Local (Initiate)', `${BASE_URL}/chat`, 'POST', {
        message: 'Hello',
        provider: 'local',
        model: 'granite4:3b'
    }, KEYS.INITIATE, 200);

    // 2. Test Chat (Cloud Model) - Should FAIL for Initiate
    await testEndpoint('Chat Cloud (Initiate)', `${BASE_URL}/chat`, 'POST', {
        message: 'Hello',
        provider: 'anythingllm',
        model: 'gpt-4o'
    }, KEYS.INITIATE, 403);

    // 3. Test Chat (Cloud Model) - Should PASS for Operator
    await testEndpoint('Chat Cloud (Operator)', `${BASE_URL}/chat`, 'POST', {
        message: 'Hello',
        provider: 'anythingllm',
        model: 'gpt-4o'
    }, KEYS.OPERATOR, 200);

    // 4. Test Finance - Should FAIL for Initiate
    await testEndpoint('Finance (Initiate)', `${BASE_URL}/finance/portfolio`, 'GET', null, KEYS.INITIATE, 403);

    // 5. Test Finance - Should PASS for Operator
    await testEndpoint('Finance (Operator)', `${BASE_URL}/finance/portfolio`, 'GET', null, KEYS.OPERATOR, 200);

    // 6. Test Admin - Should PASS Everything
    await testEndpoint('OSINT (Admin)', `${BASE_URL}/osint/spiderfoot/status`, 'GET', null, KEYS.ADMIN, 200);
}

runTests();

