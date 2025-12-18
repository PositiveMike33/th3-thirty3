/**
 * VPN Automation Service
 * Provides automated VPN connection management with rotation and verification
 * Supports: OpenVPN, WireGuard, Windows Built-in VPN, and ProtonVPN CLI
 */

const { exec, spawn } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const fs = require('fs');
const path = require('path');
const EventEmitter = require('events');

class VPNService extends EventEmitter {
    constructor() {
        super();
        
        this.isConnected = false;
        this.currentServer = null;
        this.currentIP = null;
        this.originalIP = null;
        this.connectionStartTime = null;
        this.rotationInterval = null;
        this.healthCheckInterval = null;
        
        // VPN configurations directory
        this.configDir = path.join(__dirname, 'vpn_configs');
        this.ensureConfigDir();
        
        // Available VPN providers/servers
        this.servers = {
            protonvpn: [
                { name: 'ProtonVPN-US', country: 'US', type: 'protonvpn' },
                { name: 'ProtonVPN-NL', country: 'NL', type: 'protonvpn' },
                { name: 'ProtonVPN-JP', country: 'JP', type: 'protonvpn' }
            ],
            openvpn: [], // Populated from config files
            wireguard: [], // Populated from config files
            windows: [] // Windows built-in VPN connections
        };
        
        // Free VPN endpoints (OpenVPN configs from vpngate.net)
        this.freeVPNEndpoints = [
            { host: 'public-vpn-186.opengw.net', port: 443, country: 'JP' },
            { host: 'public-vpn-76.opengw.net', port: 443, country: 'JP' },
            { host: 'public-vpn-201.opengw.net', port: 443, country: 'JP' },
            { host: 'public-vpn-53.opengw.net', port: 443, country: 'JP' },
            { host: 'public-vpn-253.opengw.net', port: 443, country: 'JP' }
        ];
        
        // TOR Configuration
        this.torConfig = {
            host: '127.0.0.1',
            port: 9050,
            controlPort: 9051,
            enabled: false
        };
        
        // Load socks-proxy-agent for TOR
        try {
            this.SocksProxyAgent = require('socks-proxy-agent').SocksProxyAgent;
            console.log('[VPN] SOCKS proxy agent loaded (TOR support enabled)');
        } catch (e) {
            this.SocksProxyAgent = null;
            console.log('[VPN] SOCKS proxy agent not available (run: npm install socks-proxy-agent)');
        }
        
        console.log('[VPN] Service initialized with TOR support');
    }

    ensureConfigDir() {
        if (!fs.existsSync(this.configDir)) {
            fs.mkdirSync(this.configDir, { recursive: true });
        }
    }

    // ==========================================
    // IP VERIFICATION
    // ==========================================

    /**
     * Get current public IP address
     */
    async getCurrentIP() {
        const services = [
            'https://api.ipify.org?format=json',
            'https://ipinfo.io/json',
            'https://api.myip.com'
        ];

        for (const service of services) {
            try {
                const response = await fetch(service);
                const data = await response.json();
                return data.ip || data.origin;
            } catch (error) {
                continue;
            }
        }
        throw new Error('Could not determine public IP');
    }

    /**
     * Get detailed IP information
     */
    async getIPInfo() {
        try {
            const response = await fetch('https://ipinfo.io/json');
            const data = await response.json();
            return {
                ip: data.ip,
                city: data.city,
                region: data.region,
                country: data.country,
                org: data.org,
                timezone: data.timezone
            };
        } catch (error) {
            const ip = await this.getCurrentIP();
            return { ip, city: 'Unknown', country: 'Unknown' };
        }
    }

    /**
     * Verify VPN is working (IP changed)
     */
    async verifyConnection() {
        const currentIP = await this.getCurrentIP();
        const isChanged = this.originalIP && currentIP !== this.originalIP;
        
        return {
            originalIP: this.originalIP,
            currentIP: currentIP,
            isProtected: isChanged,
            server: this.currentServer
        };
    }

    // ==========================================
    // TOR NETWORK SUPPORT
    // ==========================================

    /**
     * Check if TOR is available (Docker container running)
     */
    async isTorAvailable() {
        try {
            const https = require('https');
            
            if (!this.SocksProxyAgent) {
                return { available: false, reason: 'SOCKS proxy agent not installed' };
            }

            const agent = new this.SocksProxyAgent(`socks5://${this.torConfig.host}:${this.torConfig.port}`);
            
            return new Promise((resolve) => {
                const req = https.request({
                    hostname: 'check.torproject.org',
                    path: '/api/ip',
                    method: 'GET',
                    agent: agent,
                    timeout: 10000
                }, (res) => {
                    let data = '';
                    res.on('data', chunk => data += chunk);
                    res.on('end', () => {
                        try {
                            const json = JSON.parse(data);
                            resolve({ 
                                available: true, 
                                isTor: json.IsTor, 
                                ip: json.IP 
                            });
                        } catch {
                            resolve({ available: false, reason: 'Invalid response' });
                        }
                    });
                });
                
                req.on('error', (e) => {
                    resolve({ available: false, reason: e.message });
                });
                
                req.on('timeout', () => {
                    req.destroy();
                    resolve({ available: false, reason: 'Connection timeout' });
                });
                
                req.end();
            });
        } catch (error) {
            return { available: false, reason: error.message };
        }
    }

    /**
     * Get IP through TOR network
     */
    async getTorIP() {
        const https = require('https');
        
        if (!this.SocksProxyAgent) {
            throw new Error('SOCKS proxy agent not installed');
        }

        const agent = new this.SocksProxyAgent(`socks5://${this.torConfig.host}:${this.torConfig.port}`);
        
        return new Promise((resolve, reject) => {
            const req = https.request({
                hostname: 'check.torproject.org',
                path: '/api/ip',
                method: 'GET',
                agent: agent,
                timeout: 15000
            }, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        const json = JSON.parse(data);
                        resolve({
                            ip: json.IP,
                            isTor: json.IsTor
                        });
                    } catch (e) {
                        reject(new Error('Invalid TOR response'));
                    }
                });
            });
            
            req.on('error', reject);
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('TOR connection timeout'));
            });
            
            req.end();
        });
    }

    /**
     * Connect via TOR network
     */
    async connectTor() {
        try {
            if (!this.originalIP) {
                this.originalIP = await this.getCurrentIP();
            }

            console.log('[VPN] Connecting via TOR network...');
            
            const torCheck = await this.isTorAvailable();
            
            if (!torCheck.available) {
                return { 
                    success: false, 
                    error: `TOR not available: ${torCheck.reason}. Make sure Docker container is running.` 
                };
            }

            if (!torCheck.isTor) {
                return { 
                    success: false, 
                    error: 'Connection exists but not routing through TOR' 
                };
            }

            this.isConnected = true;
            this.currentServer = 'TOR Network';
            this.currentIP = torCheck.ip;
            this.torConfig.enabled = true;
            this.connectionStartTime = new Date();
            
            this.emit('connected', { server: 'TOR', ip: torCheck.ip, type: 'tor' });
            console.log(`[VPN] Connected via TOR! IP: ${torCheck.ip}`);
            
            return { 
                success: true, 
                ip: torCheck.ip,
                isTor: true,
                server: 'TOR Network',
                proxyUrl: `socks5://${this.torConfig.host}:${this.torConfig.port}`
            };
        } catch (error) {
            console.error('[VPN] TOR connection failed:', error.message);
            return { success: false, error: error.message };
        }
    }

    /**
     * Request new TOR identity (new exit node)
     */
    async newTorIdentity() {
        try {
            // Send NEWNYM signal to TOR control port
            const net = require('net');
            
            return new Promise((resolve, reject) => {
                const client = new net.Socket();
                
                client.connect(this.torConfig.controlPort, this.torConfig.host, () => {
                    // Authenticate (default is no password for local)
                    client.write('AUTHENTICATE\r\n');
                });

                let response = '';
                
                client.on('data', (data) => {
                    response += data.toString();
                    
                    if (response.includes('250 OK')) {
                        if (!response.includes('NEWNYM')) {
                            client.write('SIGNAL NEWNYM\r\n');
                        } else {
                            client.destroy();
                            console.log('[VPN] TOR identity changed (new exit node)');
                            resolve({ success: true, message: 'New TOR identity requested' });
                        }
                    } else if (response.includes('515') || response.includes('Authentication')) {
                        client.destroy();
                        reject(new Error('TOR authentication required'));
                    }
                });

                client.on('error', (err) => {
                    reject(err);
                });

                client.on('timeout', () => {
                    client.destroy();
                    reject(new Error('TOR control connection timeout'));
                });

                client.setTimeout(5000);
            });
        } catch (error) {
            console.error('[VPN] Failed to request new TOR identity:', error.message);
            return { success: false, error: error.message };
        }
    }

    /**
     * Get TOR proxy agent for use in HTTP requests
     */
    getTorAgent() {
        if (!this.SocksProxyAgent) {
            throw new Error('SOCKS proxy agent not installed');
        }
        return new this.SocksProxyAgent(`socks5://${this.torConfig.host}:${this.torConfig.port}`);
    }

    /**
     * Get TOR status
     */
    async getTorStatus() {
        const torCheck = await this.isTorAvailable();
        return {
            available: torCheck.available,
            connected: this.torConfig.enabled && torCheck.available,
            isTor: torCheck.isTor || false,
            ip: torCheck.ip || null,
            proxyHost: this.torConfig.host,
            proxyPort: this.torConfig.port,
            controlPort: this.torConfig.controlPort
        };
    }

    // ==========================================
    // WINDOWS BUILT-IN VPN
    // ==========================================

    /**
     * List Windows VPN connections
     */
    async listWindowsVPNs() {
        try {
            const { stdout } = await execPromise('Get-VpnConnection | Select-Object Name, ServerAddress, ConnectionStatus | ConvertTo-Json', { shell: 'powershell' });
            const vpns = JSON.parse(stdout || '[]');
            return Array.isArray(vpns) ? vpns : [vpns];
        } catch (error) {
            console.error('[VPN] Failed to list Windows VPNs:', error.message);
            return [];
        }
    }

    /**
     * Connect to Windows VPN
     */
    async connectWindowsVPN(connectionName) {
        try {
            // Store original IP before connecting
            if (!this.originalIP) {
                this.originalIP = await this.getCurrentIP();
            }

            console.log(`[VPN] Connecting to Windows VPN: ${connectionName}`);
            
            await execPromise(`rasdial "${connectionName}"`, { shell: 'cmd' });
            
            // Wait and verify
            await this.sleep(3000);
            const newIP = await this.getCurrentIP();
            
            if (newIP !== this.originalIP) {
                this.isConnected = true;
                this.currentServer = connectionName;
                this.currentIP = newIP;
                this.connectionStartTime = new Date();
                
                this.emit('connected', { server: connectionName, ip: newIP });
                console.log(`[VPN] Connected! New IP: ${newIP}`);
                
                return { success: true, ip: newIP, server: connectionName };
            } else {
                throw new Error('IP did not change after connection');
            }
        } catch (error) {
            console.error('[VPN] Windows VPN connection failed:', error.message);
            return { success: false, error: error.message };
        }
    }

    /**
     * Disconnect Windows VPN
     */
    async disconnectWindowsVPN(connectionName) {
        try {
            await execPromise(`rasdial "${connectionName}" /disconnect`, { shell: 'cmd' });
            this.isConnected = false;
            this.currentServer = null;
            this.emit('disconnected');
            console.log('[VPN] Disconnected from Windows VPN');
            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    // ==========================================
    // OPENVPN SUPPORT
    // ==========================================

    /**
     * Load OpenVPN configs from directory
     */
    loadOpenVPNConfigs() {
        const ovpnDir = path.join(this.configDir, 'openvpn');
        if (!fs.existsSync(ovpnDir)) {
            fs.mkdirSync(ovpnDir, { recursive: true });
            return [];
        }

        return fs.readdirSync(ovpnDir)
            .filter(f => f.endsWith('.ovpn'))
            .map(f => ({
                name: f.replace('.ovpn', ''),
                path: path.join(ovpnDir, f),
                type: 'openvpn'
            }));
    }

    /**
     * Connect using OpenVPN
     */
    async connectOpenVPN(configPath, credentials = null) {
        try {
            if (!this.originalIP) {
                this.originalIP = await this.getCurrentIP();
            }

            const configName = path.basename(configPath, '.ovpn');
            console.log(`[VPN] Connecting via OpenVPN: ${configName}`);

            // Build command
            let command = `openvpn --config "${configPath}" --daemon`;
            
            if (credentials) {
                // Create temp auth file
                const authFile = path.join(this.configDir, 'auth.txt');
                fs.writeFileSync(authFile, `${credentials.username}\n${credentials.password}`);
                command += ` --auth-user-pass "${authFile}"`;
            }

            await execPromise(command);
            
            // Wait and verify
            await this.sleep(10000);
            const verification = await this.verifyConnection();
            
            if (verification.isProtected) {
                this.isConnected = true;
                this.currentServer = configName;
                this.currentIP = verification.currentIP;
                this.connectionStartTime = new Date();
                
                this.emit('connected', { server: configName, ip: this.currentIP });
                return { success: true, ...verification };
            } else {
                throw new Error('VPN connection verification failed');
            }
        } catch (error) {
            console.error('[VPN] OpenVPN connection failed:', error.message);
            return { success: false, error: error.message };
        }
    }

    /**
     * Disconnect OpenVPN
     */
    async disconnectOpenVPN() {
        try {
            // Kill OpenVPN process on Windows
            await execPromise('taskkill /F /IM openvpn.exe', { shell: 'cmd' }).catch(() => {});
            
            this.isConnected = false;
            this.currentServer = null;
            this.emit('disconnected');
            
            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    // ==========================================
    // WIREGUARD SUPPORT
    // ==========================================

    /**
     * Load WireGuard configs
     */
    loadWireGuardConfigs() {
        const wgDir = path.join(this.configDir, 'wireguard');
        if (!fs.existsSync(wgDir)) {
            fs.mkdirSync(wgDir, { recursive: true });
            return [];
        }

        return fs.readdirSync(wgDir)
            .filter(f => f.endsWith('.conf'))
            .map(f => ({
                name: f.replace('.conf', ''),
                path: path.join(wgDir, f),
                type: 'wireguard'
            }));
    }

    /**
     * Connect using WireGuard
     */
    async connectWireGuard(tunnelName) {
        try {
            if (!this.originalIP) {
                this.originalIP = await this.getCurrentIP();
            }

            console.log(`[VPN] Connecting via WireGuard: ${tunnelName}`);
            
            // Use wireguard-tools or wg-quick
            await execPromise(`wireguard /installtunnelservice "${path.join(this.configDir, 'wireguard', tunnelName + '.conf')}"`, { shell: 'cmd' });
            
            await this.sleep(5000);
            const verification = await this.verifyConnection();
            
            if (verification.isProtected) {
                this.isConnected = true;
                this.currentServer = tunnelName;
                this.currentIP = verification.currentIP;
                this.connectionStartTime = new Date();
                
                this.emit('connected', { server: tunnelName, ip: this.currentIP });
                return { success: true, ...verification };
            } else {
                throw new Error('WireGuard connection verification failed');
            }
        } catch (error) {
            console.error('[VPN] WireGuard connection failed:', error.message);
            return { success: false, error: error.message };
        }
    }

    /**
     * Disconnect WireGuard
     */
    async disconnectWireGuard(tunnelName) {
        try {
            await execPromise(`wireguard /uninstalltunnelservice "${tunnelName}"`, { shell: 'cmd' });
            this.isConnected = false;
            this.currentServer = null;
            this.emit('disconnected');
            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    // ==========================================
    // PROTONVPN SUPPORT (CLI)
    // ==========================================

    /**
     * Check if ProtonVPN CLI is installed
     */
    async isProtonVPNInstalled() {
        try {
            await execPromise('protonvpn-cli --version');
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Connect via ProtonVPN CLI
     */
    async connectProtonVPN(country = 'fastest') {
        try {
            if (!await this.isProtonVPNInstalled()) {
                return { success: false, error: 'ProtonVPN CLI not installed. Install with: pip install protonvpn-cli' };
            }

            if (!this.originalIP) {
                this.originalIP = await this.getCurrentIP();
            }

            console.log(`[VPN] Connecting via ProtonVPN: ${country}`);
            
            const command = country === 'fastest' 
                ? 'protonvpn-cli connect --fastest'
                : `protonvpn-cli connect --cc ${country}`;
            
            await execPromise(command);
            
            await this.sleep(5000);
            const verification = await this.verifyConnection();
            
            if (verification.isProtected) {
                this.isConnected = true;
                this.currentServer = `ProtonVPN-${country}`;
                this.currentIP = verification.currentIP;
                this.connectionStartTime = new Date();
                
                this.emit('connected', { server: this.currentServer, ip: this.currentIP });
                return { success: true, ...verification };
            }
            
            throw new Error('ProtonVPN connection verification failed');
        } catch (error) {
            console.error('[VPN] ProtonVPN connection failed:', error.message);
            return { success: false, error: error.message };
        }
    }

    /**
     * Disconnect ProtonVPN
     */
    async disconnectProtonVPN() {
        try {
            await execPromise('protonvpn-cli disconnect');
            this.isConnected = false;
            this.currentServer = null;
            this.emit('disconnected');
            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    // ==========================================
    // AUTOMATED ROTATION
    // ==========================================

    /**
     * Start automatic VPN rotation
     */
    startRotation(intervalMinutes = 30, servers = null) {
        if (this.rotationInterval) {
            console.log('[VPN] Rotation already running');
            return;
        }

        const serverList = servers || this.getAllServers();
        let currentIndex = 0;

        console.log(`[VPN] Starting rotation every ${intervalMinutes} minutes with ${serverList.length} servers`);

        const rotate = async () => {
            try {
                // Disconnect current
                await this.disconnect();
                await this.sleep(2000);

                // Connect to next server
                const server = serverList[currentIndex];
                currentIndex = (currentIndex + 1) % serverList.length;

                console.log(`[VPN] Rotating to: ${server.name}`);
                
                let result;
                switch (server.type) {
                    case 'openvpn':
                        result = await this.connectOpenVPN(server.path);
                        break;
                    case 'wireguard':
                        result = await this.connectWireGuard(server.name);
                        break;
                    case 'protonvpn':
                        result = await this.connectProtonVPN(server.country);
                        break;
                    case 'windows':
                        result = await this.connectWindowsVPN(server.name);
                        break;
                    default:
                        console.error('[VPN] Unknown server type:', server.type);
                }

                this.emit('rotated', { server: server.name, result });
            } catch (error) {
                console.error('[VPN] Rotation failed:', error.message);
                this.emit('rotationError', error);
            }
        };

        // Initial connection
        rotate();

        // Schedule rotation
        this.rotationInterval = setInterval(rotate, intervalMinutes * 60 * 1000);
    }

    /**
     * Stop rotation
     */
    stopRotation() {
        if (this.rotationInterval) {
            clearInterval(this.rotationInterval);
            this.rotationInterval = null;
            console.log('[VPN] Rotation stopped');
        }
    }

    // ==========================================
    // HEALTH CHECK
    // ==========================================

    /**
     * Start health check
     */
    startHealthCheck(intervalSeconds = 60) {
        if (this.healthCheckInterval) {
            return;
        }

        console.log(`[VPN] Starting health check every ${intervalSeconds}s`);

        this.healthCheckInterval = setInterval(async () => {
            if (!this.isConnected) return;

            try {
                const verification = await this.verifyConnection();
                
                if (!verification.isProtected) {
                    console.warn('[VPN] Connection lost! IP exposed.');
                    this.emit('connectionLost', verification);
                    
                    // Attempt reconnection
                    if (this.currentServer) {
                        console.log('[VPN] Attempting reconnection...');
                        // Reconnect logic here
                    }
                }
            } catch (error) {
                console.error('[VPN] Health check failed:', error.message);
            }
        }, intervalSeconds * 1000);
    }

    /**
     * Stop health check
     */
    stopHealthCheck() {
        if (this.healthCheckInterval) {
            clearInterval(this.healthCheckInterval);
            this.healthCheckInterval = null;
            console.log('[VPN] Health check stopped');
        }
    }

    // ==========================================
    // QUICK CONNECT (AUTO-SELECT BEST)
    // ==========================================

    /**
     * Quick connect to best available VPN
     */
    async quickConnect() {
        console.log('[VPN] Quick connect - finding best available VPN...');
        
        if (!this.originalIP) {
            this.originalIP = await this.getCurrentIP();
        }

        // Try in order of preference
        
        // 1. Try ProtonVPN first (if installed)
        if (await this.isProtonVPNInstalled()) {
            console.log('[VPN] Trying ProtonVPN...');
            const result = await this.connectProtonVPN('fastest');
            if (result.success) return result;
        }

        // 2. Try Windows VPN
        const windowsVPNs = await this.listWindowsVPNs();
        if (windowsVPNs.length > 0) {
            console.log('[VPN] Trying Windows VPN...');
            const result = await this.connectWindowsVPN(windowsVPNs[0].Name);
            if (result.success) return result;
        }

        // 3. Try OpenVPN configs
        const ovpnConfigs = this.loadOpenVPNConfigs();
        if (ovpnConfigs.length > 0) {
            console.log('[VPN] Trying OpenVPN...');
            const result = await this.connectOpenVPN(ovpnConfigs[0].path);
            if (result.success) return result;
        }

        // 4. Try WireGuard
        const wgConfigs = this.loadWireGuardConfigs();
        if (wgConfigs.length > 0) {
            console.log('[VPN] Trying WireGuard...');
            const result = await this.connectWireGuard(wgConfigs[0].name);
            if (result.success) return result;
        }

        return { 
            success: false, 
            error: 'No VPN connections available. Please configure OpenVPN, WireGuard, Windows VPN, or install ProtonVPN CLI.' 
        };
    }

    /**
     * Disconnect from current VPN
     */
    async disconnect() {
        if (!this.isConnected) {
            return { success: true, message: 'Already disconnected' };
        }

        try {
            // Try all disconnect methods
            await this.disconnectProtonVPN().catch(() => {});
            await this.disconnectOpenVPN().catch(() => {});
            
            // Disconnect all Windows VPNs
            const windowsVPNs = await this.listWindowsVPNs();
            for (const vpn of windowsVPNs) {
                if (vpn.ConnectionStatus === 'Connected') {
                    await this.disconnectWindowsVPN(vpn.Name).catch(() => {});
                }
            }

            this.isConnected = false;
            this.currentServer = null;
            this.currentIP = null;
            this.emit('disconnected');
            
            console.log('[VPN] Disconnected');
            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    // ==========================================
    // UTILITIES
    // ==========================================

    /**
     * Get all available servers
     */
    getAllServers() {
        return [
            ...this.servers.protonvpn,
            ...this.loadOpenVPNConfigs(),
            ...this.loadWireGuardConfigs()
        ];
    }

    /**
     * Get current status
     */
    async getStatus() {
        const ipInfo = await this.getIPInfo().catch(() => ({ ip: 'Unknown' }));
        
        return {
            isConnected: this.isConnected,
            currentServer: this.currentServer,
            currentIP: this.currentIP || ipInfo.ip,
            originalIP: this.originalIP,
            isProtected: this.isConnected && this.currentIP !== this.originalIP,
            connectionTime: this.connectionStartTime 
                ? Math.floor((Date.now() - this.connectionStartTime) / 1000) 
                : 0,
            ipInfo,
            availableServers: {
                openvpn: this.loadOpenVPNConfigs().length,
                wireguard: this.loadWireGuardConfigs().length,
                protonvpn: this.servers.protonvpn.length
            }
        };
    }

    /**
     * Download free VPN configs from VPNGate
     */
    async downloadFreeVPNConfigs() {
        console.log('[VPN] Downloading free VPN configs from VPNGate...');
        
        try {
            const response = await fetch('https://www.vpngate.net/api/iphone/');
            const csvData = await response.text();
            
            const lines = csvData.split('\n').slice(2); // Skip headers
            const configs = [];
            
            for (const line of lines.slice(0, 10)) { // Get first 10
                const parts = line.split(',');
                if (parts.length > 14 && parts[14]) {
                    try {
                        const ovpnBase64 = parts[14];
                        const ovpnContent = Buffer.from(ovpnBase64, 'base64').toString('utf-8');
                        const country = parts[6] || 'Unknown';
                        const host = parts[1] || 'vpngate';
                        
                        const filename = `vpngate_${country}_${host}.ovpn`;
                        const filepath = path.join(this.configDir, 'openvpn', filename);
                        
                        fs.writeFileSync(filepath, ovpnContent);
                        configs.push({ filename, country, host });
                    } catch (e) {
                        continue;
                    }
                }
            }
            
            console.log(`[VPN] Downloaded ${configs.length} VPN configs`);
            return { success: true, configs };
        } catch (error) {
            console.error('[VPN] Failed to download free VPN configs:', error.message);
            return { success: false, error: error.message };
        }
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Stop all services
     */
    stop() {
        this.stopRotation();
        this.stopHealthCheck();
        console.log('[VPN] Service stopped');
    }
}

module.exports = VPNService;
