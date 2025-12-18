/**
 * Tor Startup Check & Auto-Launch Module
 * Th3 Thirty3 - Automatic Tor connection verification at app startup
 * 
 * Features:
 * - Checks if Tor is running on port 9050
 * - Auto-launches tor.exe if not running
 * - Verifies real Tor connection via check.torproject.org
 * - Logs status to console with visual indicators
 */

const net = require('net');
const { spawn, exec } = require('child_process');
const path = require('path');

// Configuration
const TOR_CONFIG = {
    host: process.env.TOR_HOST || '127.0.0.1',
    socksPort: parseInt(process.env.TOR_SOCKS_PORT) || 9050,
    controlPort: parseInt(process.env.TOR_CONTROL_PORT) || 9051,
    torExePath: process.env.TOR_EXE_PATH || 'C:\\Tor\\tor\\tor.exe',
    torrcPath: process.env.TORRC_PATH || 'C:\\Tor\\torrc',
    connectionTimeout: 30000, // 30 seconds to establish circuit
    retryAttempts: 3,
    retryDelay: 5000 // 5 seconds between retries
};

class TorStartupCheck {
    constructor() {
        this.isConnected = false;
        this.torProcess = null;
        this.currentIP = null;
        this.isTorVerified = false;
    }

    /**
     * Check if Tor SOCKS port is listening
     */
    async checkPort(port = TOR_CONFIG.socksPort, timeout = 5000) {
        return new Promise((resolve) => {
            const socket = new net.Socket();
            socket.setTimeout(timeout);

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

            socket.connect(port, TOR_CONFIG.host);
        });
    }

    /**
     * Start tor.exe process
     */
    async startTor() {
        return new Promise((resolve, reject) => {
            const fs = require('fs');
            
            // Check if tor.exe exists
            if (!fs.existsSync(TOR_CONFIG.torExePath)) {
                console.log('[TOR] ❌ tor.exe not found at:', TOR_CONFIG.torExePath);
                console.log('[TOR] 💡 Run install_tor_service_v2.ps1 to install Tor Expert Bundle');
                return reject(new Error('tor.exe not found'));
            }

            console.log('[TOR] 🚀 Starting tor.exe...');
            
            // Start tor.exe with torrc config
            const args = ['-f', TOR_CONFIG.torrcPath];
            
            this.torProcess = spawn(TOR_CONFIG.torExePath, args, {
                cwd: path.dirname(TOR_CONFIG.torExePath),
                detached: true,
                stdio: 'ignore',
                windowsHide: true
            });

            this.torProcess.unref(); // Allow parent to exit independently

            // Wait for Tor to establish connection
            console.log('[TOR] ⏳ Waiting for Tor to establish circuits...');
            
            let attempts = 0;
            const maxAttempts = 12; // 60 seconds total (12 * 5s)
            
            const checkConnection = async () => {
                attempts++;
                const portOpen = await this.checkPort();
                
                if (portOpen) {
                    console.log('[TOR] ✅ Port 9050 is now listening');
                    resolve(true);
                } else if (attempts < maxAttempts) {
                    setTimeout(checkConnection, 5000);
                } else {
                    reject(new Error('Tor failed to start after 60 seconds'));
                }
            };

            // Start checking after 3 seconds
            setTimeout(checkConnection, 3000);
        });
    }

    /**
     * Verify actual Tor connection via torproject.org API
     * Uses Docker container exec if available (more reliable on Windows)
     */
    async verifyTorConnection() {
        // First, try Docker Kali-Tor (most reliable)
        try {
            const dockerResult = await this.verifyViaDocker();
            if (dockerResult.isTor) {
                return dockerResult;
            }
        } catch (e) {
            // Docker not available, continue with direct check
        }

        // Fallback to direct SOCKS5 proxy
        try {
            const { SocksProxyAgent } = require('socks-proxy-agent');
            const agent = new SocksProxyAgent(`socks5h://${TOR_CONFIG.host}:${TOR_CONFIG.socksPort}`);
            
            const response = await fetch('https://check.torproject.org/api/ip', {
                agent,
                signal: AbortSignal.timeout(15000) // 15 second timeout
            });
            
            const data = await response.json();
            
            this.isTorVerified = data.IsTor || false;
            this.currentIP = data.IP || null;
            
            return {
                isTor: this.isTorVerified,
                ip: this.currentIP,
                method: 'direct_socks5',
                message: this.isTorVerified 
                    ? `✅ Connected via Tor (Exit IP: ${this.currentIP})`
                    : `⚠️ Not connected via Tor (IP: ${this.currentIP})`
            };
        } catch (error) {
            return {
                isTor: false,
                ip: null,
                error: error.message,
                message: `❌ Cannot verify Tor: ${error.message}`
            };
        }
    }

    /**
     * Verify Tor via Docker Kali-Tor container (most reliable on Windows)
     */
    async verifyViaDocker() {
        return new Promise((resolve, reject) => {
            const { exec } = require('child_process');
            
            // Check if Docker container is running
            exec('docker exec th3_kali_tor curl -s --connect-timeout 10 --socks5-hostname localhost:9050 https://check.torproject.org/api/ip', 
                { timeout: 20000 },
                (error, stdout, stderr) => {
                    if (error) {
                        reject(new Error('Docker Kali-Tor not available'));
                        return;
                    }
                    
                    try {
                        const data = JSON.parse(stdout.trim());
                        this.isTorVerified = data.IsTor || false;
                        this.currentIP = data.IP || null;
                        this.dockerAvailable = true;
                        
                        resolve({
                            isTor: this.isTorVerified,
                            ip: this.currentIP,
                            method: 'docker_kali_tor',
                            message: this.isTorVerified 
                                ? `✅ Connected via Docker Kali-Tor (Exit IP: ${this.currentIP})`
                                : `⚠️ Docker running but Tor not connected`
                        });
                    } catch (parseError) {
                        reject(new Error('Failed to parse Docker response'));
                    }
                }
            );
        });
    }

    /**
     * Main startup check - runs at server launch
     */
    async performStartupCheck() {
        console.log('\n' + '='.repeat(50));
        console.log('🧅 TOR STARTUP CHECK - Th3 Thirty3');
        console.log('='.repeat(50));
        
        // Step 1: Check if port 9050 is open
        console.log('\n[TOR] Checking port 9050...');
        let portOpen = await this.checkPort();
        
        if (!portOpen) {
            console.log('[TOR] ⚠️ Port 9050 not listening - attempting to start Tor...');
            
            try {
                await this.startTor();
                portOpen = true;
            } catch (error) {
                console.log('[TOR] ❌ Failed to start Tor:', error.message);
                console.log('[TOR] 💡 Options:');
                console.log('    1. Start Tor Browser manually');
                console.log('    2. Run: .\\start_tor_proxy.ps1');
                console.log('    3. Run: .\\install_tor_service_v2.ps1 (as admin)');
                return { success: false, error: error.message };
            }
        } else {
            console.log('[TOR] ✅ Port 9050 is already listening');
        }

        // Step 2: Verify actual Tor connection
        console.log('\n[TOR] Verifying Tor connection...');
        const verification = await this.verifyTorConnection();
        console.log('[TOR]', verification.message);
        
        // Step 3: Print status summary
        console.log('\n' + '-'.repeat(50));
        console.log('TOR STATUS SUMMARY:');
        console.log('-'.repeat(50));
        console.log(`  Port 9050:    ${portOpen ? '🟢 ACTIVE' : '🔴 INACTIVE'}`);
        console.log(`  Tor Verified: ${verification.isTor ? '🟢 YES' : '🟡 NO (Direct)'}`);
        console.log(`  Exit IP:      ${verification.ip || 'Unknown'}`);
        console.log('-'.repeat(50) + '\n');

        this.isConnected = portOpen && verification.isTor;
        
        return {
            success: true,
            portOpen,
            isTor: verification.isTor,
            ip: verification.ip,
            message: verification.message
        };
    }

    /**
     * Get current status (for API endpoints)
     */
    getStatus() {
        return {
            isConnected: this.isConnected,
            isTorVerified: this.isTorVerified,
            currentIP: this.currentIP,
            config: {
                host: TOR_CONFIG.host,
                socksPort: TOR_CONFIG.socksPort,
                controlPort: TOR_CONFIG.controlPort
            }
        };
    }

    /**
     * Kill tor.exe process (cleanup)
     */
    async stopTor() {
        return new Promise((resolve) => {
            exec('taskkill /F /IM tor.exe', (error) => {
                if (error) {
                    console.log('[TOR] No tor.exe process to stop');
                } else {
                    console.log('[TOR] 🛑 tor.exe stopped');
                }
                resolve(true);
            });
        });
    }
}

// Singleton instance
const torStartupCheck = new TorStartupCheck();

module.exports = torStartupCheck;
