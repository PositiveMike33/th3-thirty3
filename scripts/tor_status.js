/**
 * Quick Tor Status Check
 * Run this anytime to verify Tor configuration
 */

const net = require('net');

const config = {
    socksPort: 9050,
    controlPort: 9051,
    password: process.env.TOR_CONTROL_PASSWORD || 'Th3Thirty3SecureTor2024!'
};

async function checkPort(port, name) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(3000);
        
        socket.on('connect', () => {
            socket.destroy();
            console.log(`  ✅ ${name.padEnd(20)} LISTENING`);
            resolve(true);
        });
        
        socket.on('timeout', () => {
            socket.destroy();
            console.log(`  ❌ ${name.padEnd(20)} TIMEOUT`);
            resolve(false);
        });
        
        socket.on('error', () => {
            socket.destroy();
            console.log(`  ❌ ${name.padEnd(20)} NOT AVAILABLE`);
            resolve(false);
        });
        
        socket.connect(port, '127.0.0.1');
    });
}

async function testAuth() {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(5000);
        let response = '';
        
        socket.on('connect', () => {
            socket.write(`AUTHENTICATE "${config.password}"\r\n`);
        });
        
        socket.on('data', (data) => {
            response += data.toString();
            if (response.includes('250 OK')) {
                socket.destroy();
                console.log(`  ✅ ${'Authentication'.padEnd(20)} SUCCESS`);
                resolve(true);
            } else if (response.includes('515') || response.includes('551')) {
                socket.destroy();
                console.log(`  ❌ ${'Authentication'.padEnd(20)} FAILED`);
                resolve(false);
            }
        });
        
        socket.on('timeout', () => {
            socket.destroy();
            console.log(`  ⚠️  ${'Authentication'.padEnd(20)} TIMEOUT`);
            resolve(false);
        });
        
        socket.on('error', () => {
            socket.destroy();
            console.log(`  ❌ ${'Authentication'.padEnd(20)} ERROR`);
            resolve(false);
        });
        
        socket.connect(config.controlPort, '127.0.0.1');
    });
}

async function main() {
    console.log('\n🔍 TOR STATUS CHECK\n');
    console.log('  Checking ports...\n');
    
    const socks = await checkPort(config.socksPort, 'SOCKS Port (9050)');
    const control = await checkPort(config.controlPort, 'Control Port (9051)');
    
    console.log('');
    
    if (control) {
        const auth = await testAuth();
        console.log('');
        
        if (socks && auth) {
            console.log('  🎉 TOR IS READY AND SECURE!\n');
            process.exit(0);
        } else if (socks && !auth) {
            console.log('  ⚠️  TOR running but authentication failed\n');
            console.log('  → Check TOR_CONTROL_PASSWORD in .env\n');
            process.exit(1);
        }
    } else if (socks) {
        console.log('  ⚠️  TOR running but Control Port unavailable\n');
        process.exit(1);
    } else {
        console.log('  ❌ TOR IS NOT RUNNING\n');
        console.log('  → Start Tor: C:\\Tor\\tor\\tor.exe -f C:\\Tor\\torrc\n');
        process.exit(1);
    }
}

main();
