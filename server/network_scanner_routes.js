/**
 * Network Security Scanner Routes
 * ================================
 * Integrates Nmap and Wireshark/TShark from WSL Ubuntu
 * For network reconnaissance and traffic analysis
 */

const express = require('express');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

const router = express.Router();

// WSL Ubuntu distribution name
const WSL_DISTRO = 'Ubuntu';

/**
 * Execute command in WSL Ubuntu
 */
async function runWSLCommand(command, timeout = 60000) {
    try {
        const wslCmd = `wsl -d ${WSL_DISTRO} -- bash -c "${command.replace(/"/g, '\\"')}"`;
        const { stdout, stderr } = await execPromise(wslCmd, { 
            timeout,
            maxBuffer: 10 * 1024 * 1024 // 10MB buffer for large outputs
        });
        return { success: true, output: stdout, stderr };
    } catch (error) {
        return { 
            success: false, 
            error: error.message,
            output: error.stdout || '',
            stderr: error.stderr || ''
        };
    }
}

/**
 * GET /nmap/status
 * Check if Nmap is available
 */
router.get('/nmap/status', async (req, res) => {
    try {
        const result = await runWSLCommand('nmap --version | head -1');
        if (result.success && result.output.includes('Nmap')) {
            res.json({ 
                available: true, 
                version: result.output.trim(),
                wsl: WSL_DISTRO
            });
        } else {
            res.json({ available: false, error: 'Nmap not found in WSL' });
        }
    } catch (error) {
        res.status(500).json({ available: false, error: error.message });
    }
});

/**
 * POST /nmap/scan
 * Run Nmap scan
 * Body: { target, scanType, ports?, options? }
 */
router.post('/nmap/scan', async (req, res) => {
    const { target, scanType = 'quick', ports, options = '' } = req.body;
    
    if (!target) {
        return res.status(400).json({ error: 'Target is required' });
    }
    
    // Validate target (basic security check)
    const targetRegex = /^[a-zA-Z0-9\.\-_:\/]+$/;
    if (!targetRegex.test(target)) {
        return res.status(400).json({ error: 'Invalid target format' });
    }
    
    // Build Nmap command based on scan type
    let nmapArgs = '';
    switch (scanType) {
        case 'quick':
            nmapArgs = '-T4 -F'; // Fast scan, top 100 ports
            break;
        case 'ping':
            nmapArgs = '-sn'; // Ping sweep only
            break;
        case 'ports':
            nmapArgs = `-sS -T4 ${ports ? `-p ${ports}` : '-p-'}`; // SYN scan
            break;
        case 'service':
            nmapArgs = '-sV -T4'; // Service version detection
            break;
        case 'os':
            nmapArgs = '-O -T4'; // OS detection (requires root)
            break;
        case 'vuln':
            nmapArgs = '--script=vuln -T4'; // Vulnerability scan
            break;
        case 'full':
            nmapArgs = '-sS -sV -O -A -T4'; // Comprehensive scan
            break;
        case 'stealth':
            nmapArgs = '-sS -T2 -f'; // Slow stealth scan
            break;
        case 'camera':
            // Special scan for IP cameras
            nmapArgs = '-sS -sV -p 80,443,554,8080,8000,8001,8443,8554,9000,37777,34567 -T4';
            break;
        default:
            nmapArgs = '-T4 -F';
    }
    
    // Add custom options if provided
    if (options) {
        nmapArgs += ` ${options}`;
    }
    
    console.log(`[NMAP] Starting ${scanType} scan on ${target}`);
    
    // Set timeout based on scan type
    const timeout = scanType === 'full' ? 300000 : 
                    scanType === 'stealth' ? 180000 : 
                    120000;
    
    try {
        const result = await runWSLCommand(`nmap ${nmapArgs} ${target}`, timeout);
        
        if (result.success) {
            // Parse key information from output
            const parsed = parseNmapOutput(result.output);
            res.json({
                success: true,
                target,
                scanType,
                raw: result.output,
                parsed
            });
        } else {
            res.status(500).json({
                success: false,
                target,
                scanType,
                error: result.error,
                output: result.output
            });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * Parse Nmap output to extract key information
 */
function parseNmapOutput(output) {
    const parsed = {
        hosts: [],
        openPorts: [],
        services: [],
        os: null
    };
    
    const lines = output.split('\n');
    let currentHost = null;
    
    for (const line of lines) {
        // Host detection
        if (line.includes('Nmap scan report for')) {
            const match = line.match(/Nmap scan report for ([^\s]+)/);
            if (match) {
                currentHost = match[1];
                parsed.hosts.push(currentHost);
            }
        }
        
        // Open ports
        const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+(open|filtered)\s+(\S+)(?:\s+(.*))?/);
        if (portMatch) {
            parsed.openPorts.push({
                port: parseInt(portMatch[1]),
                protocol: portMatch[2],
                state: portMatch[3],
                service: portMatch[4],
                version: portMatch[5] || '',
                host: currentHost
            });
        }
        
        // Service detection
        if (line.includes('Service Info:')) {
            parsed.services.push(line.trim());
        }
        
        // OS detection
        if (line.includes('OS:') || line.includes('Running:')) {
            parsed.os = line.trim();
        }
    }
    
    return parsed;
}

/**
 * GET /tshark/status
 * Check if TShark is available
 */
router.get('/tshark/status', async (req, res) => {
    try {
        const result = await runWSLCommand('tshark --version | head -1');
        if (result.success && result.output.includes('TShark')) {
            // Get available interfaces
            const ifaceResult = await runWSLCommand('tshark -D 2>/dev/null || echo "Permission needed"');
            res.json({ 
                available: true, 
                version: result.output.trim(),
                interfaces: ifaceResult.output.trim().split('\n').filter(l => l.trim()),
                wsl: WSL_DISTRO
            });
        } else {
            res.json({ available: false, error: 'TShark not found in WSL' });
        }
    } catch (error) {
        res.status(500).json({ available: false, error: error.message });
    }
});

/**
 * POST /tshark/capture
 * Capture network traffic (requires elevated permissions)
 * Body: { interface, duration, filter? }
 */
router.post('/tshark/capture', async (req, res) => {
    const { interface: iface = 'eth0', duration = 10, filter = '' } = req.body;
    
    if (duration > 60) {
        return res.status(400).json({ error: 'Max capture duration is 60 seconds' });
    }
    
    let tsharkCmd = `sudo tshark -i ${iface} -a duration:${duration} -c 100`;
    if (filter) {
        tsharkCmd += ` -f "${filter}"`;
    }
    
    console.log(`[TSHARK] Starting capture on ${iface} for ${duration}s`);
    
    try {
        const result = await runWSLCommand(tsharkCmd, (duration + 10) * 1000);
        
        if (result.success) {
            const packets = result.output.split('\n').filter(l => l.trim()).length;
            res.json({
                success: true,
                interface: iface,
                duration,
                filter: filter || 'none',
                packetsCapture: packets,
                raw: result.output
            });
        } else {
            res.json({
                success: false,
                error: result.error || 'Capture failed - may need elevated permissions',
                stderr: result.stderr
            });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /tshark/analyze-pcap
 * Analyze a PCAP file
 * Body: { filePath }
 */
router.post('/tshark/analyze-pcap', async (req, res) => {
    const { filePath } = req.body;
    
    if (!filePath) {
        return res.status(400).json({ error: 'File path is required' });
    }
    
    try {
        // Get protocol statistics
        const statsResult = await runWSLCommand(`tshark -r "${filePath}" -q -z io,phs`);
        
        // Get conversation summary
        const convResult = await runWSLCommand(`tshark -r "${filePath}" -q -z conv,ip`);
        
        // Get first 50 packets
        const packetsResult = await runWSLCommand(`tshark -r "${filePath}" -c 50`);
        
        res.json({
            success: true,
            protocolHierarchy: statsResult.output,
            conversations: convResult.output,
            samplePackets: packetsResult.output
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /network/interfaces
 * List network interfaces in WSL
 */
router.get('/network/interfaces', async (req, res) => {
    try {
        const result = await runWSLCommand('ip -o link show | awk -F": " \'{print $2}\'');
        const interfaces = result.output.trim().split('\n').filter(i => i);
        
        // Get IP addresses
        const ipResult = await runWSLCommand('ip -o addr show | awk \'{print $2, $4}\'');
        const ips = ipResult.output.trim().split('\n').filter(i => i);
        
        const interfaceMap = {};
        for (const iface of interfaces) {
            interfaceMap[iface] = { name: iface, addresses: [] };
        }
        for (const ip of ips) {
            const [iface, addr] = ip.split(' ');
            if (interfaceMap[iface]) {
                interfaceMap[iface].addresses.push(addr);
            }
        }
        
        res.json({
            success: true,
            interfaces: Object.values(interfaceMap)
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /network/discover
 * Discover hosts on local network
 */
router.post('/network/discover', async (req, res) => {
    const { subnet } = req.body;
    
    // Auto-detect subnet if not provided
    let targetSubnet = subnet;
    if (!targetSubnet) {
        const result = await runWSLCommand('ip route | grep default | awk \'{print $3}\' | head -1');
        if (result.success && result.output) {
            const gateway = result.output.trim();
            // Assume /24 subnet from gateway
            targetSubnet = gateway.replace(/\.\d+$/, '.0/24');
        }
    }
    
    if (!targetSubnet) {
        return res.status(400).json({ error: 'Could not determine subnet. Please provide one.' });
    }
    
    console.log(`[NETWORK] Discovering hosts on ${targetSubnet}`);
    
    try {
        const result = await runWSLCommand(`nmap -sn ${targetSubnet}`, 60000);
        
        if (result.success) {
            // Parse discovered hosts
            const hosts = [];
            const lines = result.output.split('\n');
            let currentHost = null;
            
            for (const line of lines) {
                if (line.includes('Nmap scan report for')) {
                    const match = line.match(/for ([^\s]+)\s*(?:\(([^)]+)\))?/);
                    if (match) {
                        currentHost = {
                            hostname: match[1],
                            ip: match[2] || match[1]
                        };
                    }
                }
                if (line.includes('MAC Address:') && currentHost) {
                    const match = line.match(/MAC Address: ([^\s]+)\s+\(([^)]+)\)/);
                    if (match) {
                        currentHost.mac = match[1];
                        currentHost.vendor = match[2];
                    }
                    hosts.push(currentHost);
                    currentHost = null;
                }
                if (line.includes('Host is up') && currentHost) {
                    if (!currentHost.mac) {
                        hosts.push(currentHost);
                        currentHost = null;
                    }
                }
            }
            
            res.json({
                success: true,
                subnet: targetSubnet,
                hostsFound: hosts.length,
                hosts,
                raw: result.output
            });
        } else {
            res.status(500).json({
                success: false,
                error: result.error
            });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;
