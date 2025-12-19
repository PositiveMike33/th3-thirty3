/**
 * TH3 THIRTY3 - Proxy & Privacy Setup Service
 * Node.js Integration for Application-Level Proxy Configuration
 * 
 * Usage:
 *   node setup_proxy.js --check      # Check current configuration
 *   node setup_proxy.js --install    # Install/configure proxy
 *   node setup_proxy.js --test       # Test anonymous connection
 *   node setup_proxy.js --all        # Run all steps
 */

const { execSync, spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const net = require('net');

// Configuration
const CONFIG = {
    tor: {
        socksHost: '127.0.0.1',
        socksPort: 9050,
        controlPort: 9051,
        controlPassword: process.env.TOR_CONTROL_PASSWORD || ''
    },
    dns: {
        primary: '1.1.1.1',
        secondary: '1.0.0.1',
        dohUrl: 'https://cloudflare-dns.com/dns-query'
    },
    checkUrls: {
        ip: 'https://api.ipify.org?format=json',
        tor: 'https://check.torproject.org/api/ip',
        dns: 'https://1.1.1.1/help'
    }
};

// Colors for console output
const colors = {
    reset: '\x1b[0m',
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    cyan: '\x1b[36m',
    magenta: '\x1b[35m'
};

function log(type, message) {
    const icons = {
        info: `${colors.cyan}[*]${colors.reset}`,
        success: `${colors.green}[+]${colors.reset}`,
        error: `${colors.red}[-]${colors.reset}`,
        warning: `${colors.yellow}[!]${colors.reset}`
    };
    console.log(`${icons[type] || icons.info} ${message}`);
}

// ============================================
// STEP 1: Check TOR Availability
// ============================================
async function checkTorStatus() {
    log('info', 'Checking TOR status...');
    
    const result = {
        installed: false,
        running: false,
        socksOpen: false,
        controlOpen: false,
        isTor: false,
        exitIP: null
    };
    
    // Check if TOR process is running
    try {
        if (process.platform === 'win32') {
            const output = execSync('tasklist /FI "IMAGENAME eq tor.exe"', { encoding: 'utf8' });
            result.running = output.includes('tor.exe');
        } else {
            const output = execSync('pgrep -x tor', { encoding: 'utf8' });
            result.running = output.trim() !== '';
        }
    } catch (e) {
        result.running = false;
    }
    
    // Check SOCKS port
    result.socksOpen = await checkPort(CONFIG.tor.socksHost, CONFIG.tor.socksPort);
    
    // Check Control port
    result.controlOpen = await checkPort(CONFIG.tor.socksHost, CONFIG.tor.controlPort);
    
    // Check if actually routing through TOR
    if (result.socksOpen) {
        try {
            const { SocksProxyAgent } = require('socks-proxy-agent');
            const agent = new SocksProxyAgent(`socks5h://${CONFIG.tor.socksHost}:${CONFIG.tor.socksPort}`);
            
            const response = await fetch(CONFIG.checkUrls.tor, { 
                agent,
                timeout: 15000 
            });
            const data = await response.json();
            
            result.isTor = data.IsTor === true;
            result.exitIP = data.IP;
        } catch (e) {
            log('warning', `TOR check failed: ${e.message}`);
        }
    }
    
    // Log results
    log(result.running ? 'success' : 'warning', `TOR Process: ${result.running ? 'Running' : 'Not Running'}`);
    log(result.socksOpen ? 'success' : 'warning', `SOCKS5 Port (${CONFIG.tor.socksPort}): ${result.socksOpen ? 'Open' : 'Closed'}`);
    log(result.controlOpen ? 'success' : 'info', `Control Port (${CONFIG.tor.controlPort}): ${result.controlOpen ? 'Open' : 'Closed'}`);
    
    if (result.isTor) {
        log('success', `Routing through TOR: Yes (Exit IP: ${result.exitIP})`);
    } else if (result.socksOpen) {
        log('warning', 'SOCKS port open but not confirmed as TOR');
    }
    
    return result;
}

// ============================================
// STEP 2: Check Port Availability
// ============================================
function checkPort(host, port) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(3000);
        
        socket.on('connect', () => {
            socket.destroy();
            resolve(true);
        });
        
        socket.on('timeout', () => {
            socket.destroy();
            resolve(false);
        });
        
        socket.on('error', () => {
            socket.destroy();
            resolve(false);
        });
        
        socket.connect(port, host);
    });
}

// ============================================
// STEP 3: Start TOR (Windows)
// ============================================
async function startTor() {
    log('info', 'Attempting to start TOR...');
    
    // Check if already running
    const status = await checkTorStatus();
    if (status.running && status.socksOpen) {
        log('success', 'TOR is already running');
        return true;
    }
    
    // Find TOR executable
    const possiblePaths = [
        path.join(process.env.LOCALAPPDATA || '', 'Tor', 'tor', 'tor.exe'),
        'C:\\Program Files\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe',
        path.join(process.env.USERPROFILE || '', 'Desktop', 'Tor Browser', 'Browser', 'TorBrowser', 'Tor', 'tor.exe'),
        '/usr/bin/tor',
        '/usr/local/bin/tor'
    ];
    
    let torPath = null;
    for (const p of possiblePaths) {
        if (fs.existsSync(p)) {
            torPath = p;
            break;
        }
    }
    
    if (!torPath) {
        log('error', 'TOR executable not found');
        log('info', 'Install TOR from: https://www.torproject.org/download/tor/');
        log('info', 'Or run: powershell -ExecutionPolicy Bypass -File scripts/setup_proxy.ps1 -InstallTor');
        return false;
    }
    
    try {
        log('info', `Starting TOR from ${torPath}`);
        
        const torProcess = spawn(torPath, [], {
            detached: true,
            stdio: 'ignore',
            windowsHide: true
        });
        
        torProcess.unref();
        
        // Wait for TOR to start
        log('info', 'Waiting for TOR to establish connection...');
        for (let i = 0; i < 30; i++) {
            await new Promise(r => setTimeout(r, 1000));
            const isOpen = await checkPort(CONFIG.tor.socksHost, CONFIG.tor.socksPort);
            if (isOpen) {
                log('success', 'TOR started successfully!');
                return true;
            }
            process.stdout.write('.');
        }
        
        log('error', 'TOR failed to start within 30 seconds');
        return false;
    } catch (e) {
        log('error', `Failed to start TOR: ${e.message}`);
        return false;
    }
}

// ============================================
// STEP 4: Configure Application Proxy
// ============================================
async function configureAppProxy() {
    log('info', 'Configuring application proxy settings...');
    
    const envPath = path.join(__dirname, '..', '.env');
    
    // Read current .env
    let envContent = '';
    if (fs.existsSync(envPath)) {
        envContent = fs.readFileSync(envPath, 'utf8');
    }
    
    // Check if TOR settings exist
    const settings = {
        TOR_SOCKS_HOST: CONFIG.tor.socksHost,
        TOR_SOCKS_PORT: CONFIG.tor.socksPort.toString(),
        TOR_CONTROL_PORT: CONFIG.tor.controlPort.toString()
    };
    
    let updated = false;
    for (const [key, value] of Object.entries(settings)) {
        if (!envContent.includes(`${key}=`)) {
            envContent += `\n${key}=${value}`;
            updated = true;
            log('info', `Added ${key}=${value}`);
        }
    }
    
    if (updated) {
        fs.writeFileSync(envPath, envContent);
        log('success', '.env file updated with TOR configuration');
    } else {
        log('info', 'TOR configuration already present in .env');
    }
    
    return true;
}

// ============================================
// STEP 5: Test Anonymous Connection
// ============================================
async function testConnection() {
    log('info', 'Testing anonymous connection...');
    
    const results = {
        directIP: null,
        torIP: null,
        isTor: false,
        dnsSecure: false
    };
    
    // Get direct IP
    try {
        log('info', 'Getting direct IP...');
        const response = await fetch(CONFIG.checkUrls.ip);
        const data = await response.json();
        results.directIP = data.ip;
        log('info', `Direct IP: ${results.directIP}`);
    } catch (e) {
        log('warning', 'Could not get direct IP');
    }
    
    // Check TOR
    const torStatus = await checkTorStatus();
    results.torIP = torStatus.exitIP;
    results.isTor = torStatus.isTor;
    
    // Summary
    console.log('\n' + '='.repeat(50));
    console.log(`${colors.cyan}CONNECTION TEST RESULTS${colors.reset}`);
    console.log('='.repeat(50));
    console.log(`Direct IP:     ${results.directIP || 'Unknown'}`);
    console.log(`TOR Exit IP:   ${results.torIP || 'Not connected'}`);
    console.log(`Using TOR:     ${results.isTor ? colors.green + 'YES' + colors.reset : colors.yellow + 'NO' + colors.reset}`);
    console.log(`SOCKS5 Proxy:  ${CONFIG.tor.socksHost}:${CONFIG.tor.socksPort}`);
    console.log('='.repeat(50) + '\n');
    
    if (results.isTor) {
        log('success', 'Anonymous connection verified!');
    } else {
        log('warning', 'Not routing through TOR');
        log('info', 'To use TOR, configure your application to use SOCKS5 proxy:');
        log('info', `  Host: ${CONFIG.tor.socksHost}`);
        log('info', `  Port: ${CONFIG.tor.socksPort}`);
    }
    
    return results;
}

// ============================================
// STEP 6: Get Proxy Agent for HTTP Requests
// ============================================
function getProxyAgent() {
    try {
        const { SocksProxyAgent } = require('socks-proxy-agent');
        return new SocksProxyAgent(`socks5h://${CONFIG.tor.socksHost}:${CONFIG.tor.socksPort}`);
    } catch (e) {
        log('error', 'socks-proxy-agent not installed. Run: npm install socks-proxy-agent');
        return null;
    }
}

// ============================================
// STEP 7: Generate Configuration Report
// ============================================
async function generateReport() {
    console.log('\n');
    console.log(`${colors.magenta}╔════════════════════════════════════════════════════════════════╗${colors.reset}`);
    console.log(`${colors.magenta}║              TH3 THIRTY3 - PROXY CONFIGURATION                 ║${colors.reset}`);
    console.log(`${colors.magenta}╚════════════════════════════════════════════════════════════════╝${colors.reset}`);
    
    const status = await checkTorStatus();
    
    console.log('\n=== Current Configuration ===');
    console.log(`TOR Status:       ${status.running ? colors.green + 'Running' : colors.red + 'Stopped'}${colors.reset}`);
    console.log(`SOCKS5 Proxy:     ${CONFIG.tor.socksHost}:${CONFIG.tor.socksPort} (${status.socksOpen ? colors.green + 'Open' : colors.red + 'Closed'}${colors.reset})`);
    console.log(`Control Port:     ${CONFIG.tor.controlPort} (${status.controlOpen ? colors.green + 'Open' : colors.red + 'Closed'}${colors.reset})`);
    console.log(`Routing via TOR:  ${status.isTor ? colors.green + 'Yes' : colors.yellow + 'No'}${colors.reset}`);
    if (status.exitIP) {
        console.log(`TOR Exit IP:      ${colors.green}${status.exitIP}${colors.reset}`);
    }
    
    console.log('\n=== DNS Configuration ===');
    console.log(`Primary DNS:      ${CONFIG.dns.primary}`);
    console.log(`Secondary DNS:    ${CONFIG.dns.secondary}`);
    console.log(`DoH URL:          ${CONFIG.dns.dohUrl}`);
    
    console.log('\n=== Integration ===');
    console.log('For Node.js HTTP requests:');
    console.log(`  const agent = getProxyAgent();`);
    console.log(`  fetch(url, { agent });`);
    
    console.log('\n=== PowerShell Setup ===');
    console.log('Run as Administrator:');
    console.log('  powershell -ExecutionPolicy Bypass -File scripts/setup_proxy.ps1 -All');
    console.log('');
    
    return status;
}

// ============================================
// CLI Entry Point
// ============================================
async function main() {
    const args = process.argv.slice(2);
    
    console.log('\n');
    console.log(`${colors.magenta}╔════════════════════════════════════════════════════════════════╗${colors.reset}`);
    console.log(`${colors.magenta}║         TH3 THIRTY3 - PROXY & PRIVACY SETUP                    ║${colors.reset}`);
    console.log(`${colors.magenta}╚════════════════════════════════════════════════════════════════╝${colors.reset}`);
    console.log('');
    
    if (args.includes('--help') || args.includes('-h')) {
        console.log('Usage:');
        console.log('  node setup_proxy.js --check      Check current configuration');
        console.log('  node setup_proxy.js --install    Install/configure proxy');
        console.log('  node setup_proxy.js --start      Start TOR service');
        console.log('  node setup_proxy.js --test       Test anonymous connection');
        console.log('  node setup_proxy.js --report     Generate configuration report');
        console.log('  node setup_proxy.js --all        Run all steps');
        return;
    }
    
    if (args.includes('--check')) {
        await checkTorStatus();
        return;
    }
    
    if (args.includes('--start')) {
        await startTor();
        return;
    }
    
    if (args.includes('--install')) {
        await configureAppProxy();
        return;
    }
    
    if (args.includes('--test')) {
        await testConnection();
        return;
    }
    
    if (args.includes('--report')) {
        await generateReport();
        return;
    }
    
    if (args.includes('--all') || args.length === 0) {
        await checkTorStatus();
        await startTor();
        await configureAppProxy();
        await testConnection();
        await generateReport();
        return;
    }
}

// Export for use in other modules
module.exports = {
    checkTorStatus,
    startTor,
    configureAppProxy,
    testConnection,
    getProxyAgent,
    generateReport,
    CONFIG
};

// Run if executed directly
if (require.main === module) {
    main().catch(console.error);
}
