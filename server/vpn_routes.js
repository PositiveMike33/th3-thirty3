/**
 * VPN API Routes
 * Provides REST endpoints for VPN automation and management
 */

const express = require('express');
const router = express.Router();
const VPNService = require('./vpn_service');

const vpnService = new VPNService();

// Event logging
vpnService.on('connected', (data) => {
    console.log(`[VPN_ROUTE] Connected to ${data.server} - IP: ${data.ip}`);
});

vpnService.on('disconnected', () => {
    console.log('[VPN_ROUTE] Disconnected');
});

vpnService.on('rotated', (data) => {
    console.log(`[VPN_ROUTE] Rotated to ${data.server}`);
});

vpnService.on('connectionLost', (data) => {
    console.log('[VPN_ROUTE] Connection lost - IP exposed!', data);
});

// ==========================================
// STATUS & INFO
// ==========================================

/**
 * GET /api/vpn/status
 * Get current VPN status
 */
router.get('/status', async (req, res) => {
    try {
        const status = await vpnService.getStatus();
        res.json(status);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/vpn/ip
 * Get current public IP and info
 */
router.get('/ip', async (req, res) => {
    try {
        const ipInfo = await vpnService.getIPInfo();
        res.json(ipInfo);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/vpn/verify
 * Verify VPN connection is working
 */
router.get('/verify', async (req, res) => {
    try {
        const verification = await vpnService.verifyConnection();
        res.json(verification);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/vpn/servers
 * List all available VPN servers
 */
router.get('/servers', async (req, res) => {
    try {
        const servers = vpnService.getAllServers();
        const windowsVPNs = await vpnService.listWindowsVPNs();
        const hasProton = await vpnService.isProtonVPNInstalled();
        
        res.json({
            total: servers.length + windowsVPNs.length,
            openvpn: vpnService.loadOpenVPNConfigs(),
            wireguard: vpnService.loadWireGuardConfigs(),
            windows: windowsVPNs,
            protonvpn: {
                installed: hasProton,
                servers: hasProton ? vpnService.servers.protonvpn : []
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// CONNECTION
// ==========================================

/**
 * POST /api/vpn/connect/quick
 * Quick connect to best available VPN
 */
router.post('/connect/quick', async (req, res) => {
    try {
        const result = await vpnService.quickConnect();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/vpn/connect/protonvpn
 * Connect via ProtonVPN
 */
router.post('/connect/protonvpn', async (req, res) => {
    try {
        const { country = 'fastest' } = req.body;
        const result = await vpnService.connectProtonVPN(country);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/vpn/connect/openvpn
 * Connect via OpenVPN config
 */
router.post('/connect/openvpn', async (req, res) => {
    try {
        const { configPath, username, password } = req.body;
        
        if (!configPath) {
            return res.status(400).json({ error: 'configPath required' });
        }
        
        const credentials = username && password ? { username, password } : null;
        const result = await vpnService.connectOpenVPN(configPath, credentials);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/vpn/connect/wireguard
 * Connect via WireGuard
 */
router.post('/connect/wireguard', async (req, res) => {
    try {
        const { tunnelName } = req.body;
        
        if (!tunnelName) {
            return res.status(400).json({ error: 'tunnelName required' });
        }
        
        const result = await vpnService.connectWireGuard(tunnelName);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/vpn/connect/windows
 * Connect via Windows built-in VPN
 */
router.post('/connect/windows', async (req, res) => {
    try {
        const { connectionName } = req.body;
        
        if (!connectionName) {
            return res.status(400).json({ error: 'connectionName required' });
        }
        
        const result = await vpnService.connectWindowsVPN(connectionName);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/vpn/disconnect
 * Disconnect from current VPN
 */
router.post('/disconnect', async (req, res) => {
    try {
        const result = await vpnService.disconnect();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// AUTOMATION
// ==========================================

/**
 * POST /api/vpn/rotation/start
 * Start automatic VPN rotation
 */
router.post('/rotation/start', async (req, res) => {
    try {
        const { intervalMinutes = 30 } = req.body;
        vpnService.startRotation(intervalMinutes);
        res.json({ 
            success: true, 
            message: `Rotation started every ${intervalMinutes} minutes` 
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/vpn/rotation/stop
 * Stop VPN rotation
 */
router.post('/rotation/stop', async (req, res) => {
    try {
        vpnService.stopRotation();
        res.json({ success: true, message: 'Rotation stopped' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/vpn/healthcheck/start
 * Start health check monitoring
 */
router.post('/healthcheck/start', async (req, res) => {
    try {
        const { intervalSeconds = 60 } = req.body;
        vpnService.startHealthCheck(intervalSeconds);
        res.json({ 
            success: true, 
            message: `Health check started every ${intervalSeconds}s` 
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/vpn/healthcheck/stop
 * Stop health check
 */
router.post('/healthcheck/stop', async (req, res) => {
    try {
        vpnService.stopHealthCheck();
        res.json({ success: true, message: 'Health check stopped' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// CONFIG MANAGEMENT
// ==========================================

/**
 * POST /api/vpn/configs/download-free
 * Download free VPN configs from VPNGate
 */
router.post('/configs/download-free', async (req, res) => {
    try {
        const result = await vpnService.downloadFreeVPNConfigs();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/vpn/configs/list
 * List all VPN configurations
 */
router.get('/configs/list', (req, res) => {
    try {
        res.json({
            openvpn: vpnService.loadOpenVPNConfigs(),
            wireguard: vpnService.loadWireGuardConfigs()
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// TOR NETWORK
// ==========================================

/**
 * GET /api/vpn/tor/status
 * Get TOR network status
 */
router.get('/tor/status', async (req, res) => {
    try {
        const status = await vpnService.getTorStatus();
        res.json(status);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/vpn/tor/connect
 * Connect via TOR network
 */
router.post('/tor/connect', async (req, res) => {
    try {
        const result = await vpnService.connectTor();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/vpn/tor/ip
 * Get current IP through TOR
 */
router.get('/tor/ip', async (req, res) => {
    try {
        const ipInfo = await vpnService.getTorIP();
        res.json(ipInfo);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/vpn/tor/new-identity
 * Request new TOR identity (new exit node)
 */
router.post('/tor/new-identity', async (req, res) => {
    try {
        const result = await vpnService.newTorIdentity();
        
        // Get new IP after identity change
        await new Promise(r => setTimeout(r, 2000));
        const newIP = await vpnService.getTorIP().catch(() => ({ ip: 'Unknown' }));
        
        res.json({
            ...result,
            newIP: newIP.ip
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/vpn/tor/check
 * Check if connection is going through TOR
 */
router.get('/tor/check', async (req, res) => {
    try {
        const torAvailable = await vpnService.isTorAvailable();
        res.json(torAvailable);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Export service for external access
router.vpnService = vpnService;

module.exports = router;
