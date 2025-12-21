/**
 * Test Security Research API
 */

const http = require('http');

console.log('\n=== TEST SECURITY RESEARCH API ===\n');

// Test 1: List roles
function testRoles() {
    return new Promise((resolve, reject) => {
        console.log('TEST 1: GET /api/security/roles');
        
        const req = http.request({
            hostname: 'localhost',
            port: 3000,
            path: '/api/security/roles',
            method: 'GET'
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                console.log('Status:', res.statusCode);
                try {
                    const json = JSON.parse(data);
                    console.log('Roles disponibles:');
                    if (json.roles) {
                        json.roles.forEach(r => {
                            console.log('  -', r.id + ':', r.name, '(' + r.model + ')');
                        });
                    }
                    resolve(true);
                } catch(e) {
                    console.log('Parse error:', e.message);
                    resolve(false);
                }
            });
        });
        
        req.on('error', (e) => {
            console.log('Error:', e.message);
            console.log('Le serveur n\'est pas en cours d\'exécution.');
            reject(e);
        });
        
        req.end();
    });
}

// Test 2: Security query
function testSecurityQuery() {
    return new Promise((resolve, reject) => {
        console.log('\nTEST 2: POST /api/security/query');
        console.log('Question: Comment scanner un réseau local de manière défensive?');
        console.log('Role: networkAnalyst\n');
        
        const query = JSON.stringify({
            query: 'Comment scanner un réseau local pour identifier les appareils connectés de manière défensive?',
            role: 'networkAnalyst'
        });
        
        const req = http.request({
            hostname: 'localhost',
            port: 3000,
            path: '/api/security/query',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(query)
            }
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                console.log('Status:', res.statusCode);
                try {
                    const json = JSON.parse(data);
                    console.log('Role:', json.role);
                    console.log('Context:', json.context);
                    console.log('Response Time:', json.responseTime);
                    console.log('\n--- RÉPONSE ---');
                    console.log(json.response ? json.response.substring(0, 1000) : 'No response');
                    if (json.response && json.response.length > 1000) {
                        console.log('... (tronqué)');
                    }
                    resolve(true);
                } catch(e) {
                    console.log('Raw:', data.substring(0, 500));
                    resolve(false);
                }
            });
        });
        
        req.on('error', (e) => {
            console.log('Error:', e.message);
            reject(e);
        });
        
        req.write(query);
        req.end();
    });
}

// Run tests
async function runTests() {
    try {
        await testRoles();
        await testSecurityQuery();
        console.log('\n✅ Tests terminés!');
    } catch(e) {
        console.log('\n❌ Échec - Assurez-vous que le serveur est en cours d\'exécution:');
        console.log('   cd server && npm start');
    }
}

runTests();
