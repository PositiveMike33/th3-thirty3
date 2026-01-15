const http = require('http');
const net = require('net');

const PORTS = {
    'Backend API': 3000,
    'Frontend': 5173,
    'HexStrike AI': 8888,
    'GPU Trainer': 5000,
    'Tor Proxy': 9050
};

const ROUTES = {
    'Backend Health': { port: 3000, path: '/health' },
    'Backend Models': { port: 3000, path: '/api/models' },
    'HexStrike Health': { port: 8888, path: '/health' },
    'Trainer Health': { port: 5000, path: '/health' }
};

async function checkPort(port, name) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(2000);
        socket.on('connect', () => {
            socket.destroy();
            resolve({ name, port, status: 'OPEN', color: '\x1b[32m' }); // Green
        });
        socket.on('timeout', () => {
            socket.destroy();
            resolve({ name, port, status: 'TIMEOUT', color: '\x1b[31m' }); // Red
        });
        socket.on('error', (e) => {
            resolve({ name, port, status: 'CLOSED/BLOCKED', color: '\x1b[31m' }); // Red
        });
        socket.connect(port, '127.0.0.1');
    });
}

async function checkHttp(port, path, name) {
    return new Promise((resolve) => {
        const options = {
            hostname: '127.0.0.1',
            port: port,
            path: path,
            method: 'GET',
            timeout: 5000
        };

        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                const isSuccess = res.statusCode >= 200 && res.statusCode < 300;
                resolve({
                    name,
                    url: `http://localhost:${port}${path}`,
                    status: res.statusCode,
                    success: isSuccess,
                    color: isSuccess ? '\x1b[32m' : '\x1b[31m',
                    data: data.substring(0, 100) // Preview
                });
            });
        });

        req.on('error', (e) => {
            resolve({
                name,
                url: `http://localhost:${port}${path}`,
                status: `ERROR: ${e.message}`,
                success: false,
                color: '\x1b[31m'
            });
        });

        req.on('timeout', () => {
            req.destroy();
            resolve({
                name,
                url: `http://localhost:${port}${path}`,
                status: 'TIMEOUT',
                success: false,
                color: '\x1b[31m'
            });
        });

        req.end();
    });
}

async function runDiagnostics() {
    console.log('\n🔍 TH3 THIRTY3 SYSTEM DIAGNOSTICS');
    console.log('=================================');

    // 1. Check Ports
    console.log('\n[1] Checking Ports...');
    for (const [name, port] of Object.entries(PORTS)) {
        const res = await checkPort(port, name);
        console.log(`${res.color}[${res.status}] ${res.name} (Port ${res.port})\x1b[0m`);
    }

    // 2. Check API Endpoints
    console.log('\n[2] Checking Services...');
    for (const [name, config] of Object.entries(ROUTES)) {
        const res = await checkHttp(config.port, config.path, name);
        console.log(`${res.color}[${res.status}] ${res.name} - ${res.url}\x1b[0m`);
        if (!res.success) {
            console.log(`    Error Details: ${res.data || 'No response data'}`);
        }
    }

    console.log('\n=================================');
    console.log('🏁 Diagnostics Complete');
}

runDiagnostics();
