/**
 * Tor Startup Check - PASSIVE Mode
 * Th3 Thirty3 - Automatic Tor detection at app startup
 * 
 * This module DOES NOT attempt to start Tor.
 * It only detects if Tor Browser or a Tor service is already running.
 * 
 * Features:
 * - Passive detection on ports 9150 (Tor Browser) and 9050 (Tor service)
 * - Graceful fallback to Direct Connection if Tor is not running
 * - No spawn, no PowerShell scripts, no retry loops
 */

const net = require('net');

// Configuration
const TOR_CONFIG = {
    host: process.env.TOR_HOST || '127.0.0.1',
    ports: [
        { port: 9150, name: 'Tor Browser' },   // Tor Browser default
        { port: 9050, name: 'Tor Service' }    // Background Tor service
    ],
    controlPort: parseInt(process.env.TOR_CONTROL_PORT) || 9051,
    detectionTimeout: 2000 // 2 seconds - quick check
};

class TorStartupCheck {
    constructor() {
        this.isConnected = false;
        this.activePort = null;
        this.activeName = null;
        this.currentIP = null;
        this.isTorVerified = false;
        this.mode = 'direct'; // 'tor' or 'direct'
    }

    /**
     * Quick port check with short timeout
     * @param {number} port - Port to check
     * @param {number} timeout - Timeout in ms
     * @returns {Promise<boolean>}
     */
    async checkPort(port, timeout = TOR_CONFIG.detectionTimeout) {
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
     * Detect if any Tor port is available (passive detection)
     * @returns {Promise<{found: boolean, port: number|null, name: string|null}>}
     */
    async detectTorPassive() {
        for (const config of TOR_CONFIG.ports) {
            const isOpen = await this.checkPort(config.port);
            if (isOpen) {
                return {
                    found: true,
                    port: config.port,
                    name: config.name
                };
            }
        }
        return { found: false, port: null, name: null };
    }

    /**
     * Verify actual Tor connection via torproject.org API
     * Only called if Tor port is detected
     */
    async verifyTorConnection() {
        if (!this.activePort) {
            return {
                isTor: false,
                ip: null,
                message: 'No Tor port active'
            };
        }

        try {
            const { SocksProxyAgent } = require('socks-proxy-agent');
            const agent = new SocksProxyAgent(`socks5h://${TOR_CONFIG.host}:${this.activePort}`);

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000);

            const response = await fetch('https://check.torproject.org/api/ip', {
                agent,
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            const data = await response.json();

            this.isTorVerified = data.IsTor || false;
            this.currentIP = data.IP || null;

            return {
                isTor: this.isTorVerified,
                ip: this.currentIP,
                message: this.isTorVerified
                    ? `✅ Connected via Tor (Exit IP: ${this.currentIP})`
                    : `⚠️ Port open but not Tor (IP: ${this.currentIP})`
            };
        } catch (error) {
            return {
                isTor: false,
                ip: null,
                error: error.message,
                message: `⚠️ Cannot verify Tor: ${error.message}`
            };
        }
    }

    /**
     * Main startup check - PASSIVE ONLY
     * Does NOT attempt to start Tor, only detects if it's running
     */
    async performStartupCheck() {
        console.log('\n' + '='.repeat(50));
        console.log('🧅 TOR PASSIVE DETECTION - Th3 Thirty3');
        console.log('='.repeat(50));

        // Step 1: Passive detection on all known ports
        console.log('\n[TOR] Scanning for Tor application...');
        const detection = await this.detectTorPassive();

        if (detection.found) {
            this.activePort = detection.port;
            this.activeName = detection.name;
            this.isConnected = true;
            this.mode = 'tor';

            console.log(`[TOR] ✅ ${detection.name} detected on port ${detection.port}`);

            // Step 2: Verify actual Tor connection
            console.log('[TOR] Verifying Tor connection...');
            const verification = await this.verifyTorConnection();
            console.log('[TOR]', verification.message);

            // Print status summary
            this.printStatusSummary(detection, verification);

            return {
                success: true,
                mode: 'tor',
                portOpen: true,
                port: detection.port,
                name: detection.name,
                isTor: verification.isTor,
                ip: verification.ip,
                message: verification.message
            };
        } else {
            // No Tor detected - switch to Direct mode gracefully
            this.isConnected = false;
            this.mode = 'direct';
            this.activePort = null;
            this.activeName = null;

            console.log('[TOR] ⚠️ Tor not running. Switching to Direct Connection.');
            console.log('[TOR] 💡 To enable Tor: Open Tor Browser before starting the server.');

            // Print status summary
            this.printStatusSummary(detection, null);

            return {
                success: true, // Success because we handled it gracefully
                mode: 'direct',
                portOpen: false,
                port: null,
                name: null,
                isTor: false,
                ip: null,
                message: 'Operating in Direct Connection mode (Tor not detected)'
            };
        }
    }

    /**
     * Print status summary to console
     */
    printStatusSummary(detection, verification) {
        console.log('\n' + '-'.repeat(50));
        console.log('TOR STATUS SUMMARY:');
        console.log('-'.repeat(50));
        console.log(`  Mode:         ${this.mode === 'tor' ? '🧅 TOR PROXY' : '🌐 DIRECT CONNECTION'}`);
        console.log(`  Application:  ${detection.found ? `${detection.name} (port ${detection.port})` : 'Not detected'}`);

        if (verification) {
            console.log(`  Tor Verified: ${verification.isTor ? '🟢 YES' : '🟡 NO'}`);
            console.log(`  Exit IP:      ${verification.ip || 'Unknown'}`);
        } else {
            console.log(`  Tor Verified: 🔴 N/A (Direct mode)`);
            console.log(`  Exit IP:      Your real IP`);
        }

        console.log('-'.repeat(50) + '\n');
    }

    /**
     * Get current status (for API endpoints)
     */
    getStatus() {
        return {
            mode: this.mode,
            isConnected: this.isConnected,
            isTorVerified: this.isTorVerified,
            activePort: this.activePort,
            activeName: this.activeName,
            currentIP: this.currentIP,
            config: {
                host: TOR_CONFIG.host,
                ports: TOR_CONFIG.ports,
                controlPort: TOR_CONFIG.controlPort
            }
        };
    }

    /**
     * Get SOCKS proxy URL if Tor is active
     * @returns {string|null}
     */
    getProxyUrl() {
        if (this.isConnected && this.activePort) {
            return `socks5h://${TOR_CONFIG.host}:${this.activePort}`;
        }
        return null;
    }

    /**
     * Check if we should use Tor for a request
     * @returns {boolean}
     */
    shouldUseTor() {
        return this.mode === 'tor' && this.isConnected;
    }
}

// Singleton instance
const torStartupCheck = new TorStartupCheck();

module.exports = torStartupCheck;
