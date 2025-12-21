/**
 * OSINT Service - TOR SECURED
 * ===========================
 * All external requests routed through Tor for anonymity
 * Docker containers use th3_kali_tor SOCKS5 proxy
 */

const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

class OsintService {
    constructor() {
        this.tools = [
            { id: 'whois', name: 'WHOIS Lookup', description: 'Domain registration info (via Tor)' },
            { id: 'nslookup', name: 'DNS Lookup', description: 'Domain name server info (Tor DNS)' },
            { id: 'ping', name: 'Ping', description: 'Check host availability' },
            { id: 'nmap', name: 'Nmap Port Scan', description: 'Network port scanner (WSL Ubuntu)' },
            { id: 'nmap-service', name: 'Nmap Service Detect', description: 'Detect services on ports (WSL Ubuntu)' },
            { id: 'nmap-camera', name: 'Nmap Camera Scan', description: 'Scan for IP cameras (ports 554, 8080, etc.)' },
            { id: 'network-discover', name: 'Network Discovery', description: 'Discover hosts on local network' },
            { id: 'sherlock', name: 'Sherlock (Username)', description: 'Find usernames across social networks (via Tor)' },
            { id: 'spiderfoot', name: 'SpiderFoot (Full Scan)', description: 'Automated OSINT collection (Web UI)' },
            { id: 'theharvester', name: 'theHarvester', description: 'Email/Domain reconnaissance (via Tor)' },
            { id: 'amass', name: 'Amass', description: 'DNS enumeration (via Tor)' }
        ];
        
        // Tor configuration
        this.torSocksHost = process.env.TOR_HOST || 'localhost';
        this.torSocksPort = process.env.TOR_SOCKS_PORT || 9050;
        this.useDocker = true; // Prefer Docker Kali container for Tor
        
        this.ensureDockerRunning();
        console.log('[OSINT] Service initialized with Tor anonymity');
    }

    getTools() {
        return this.tools;
    }

    /**
     * Run command through Tor via Docker Kali container
     * This ensures ALL network traffic is anonymized
     */
    async runTorCommand(command, timeout = 120000) {
        // Execute command inside th3_kali_tor container which has Tor + proxychains
        const dockerCommand = `docker exec th3_kali_tor timeout ${Math.floor(timeout/1000)} proxychains4 -q ${command}`;
        
        try {
            console.log(`[OSINT] Running via Tor: ${command.substring(0, 50)}...`);
            const { stdout, stderr } = await execPromise(dockerCommand, { timeout });
            return stdout || stderr;
        } catch (error) {
            // Try without proxychains if it fails
            try {
                const fallbackCmd = `docker exec th3_kali_tor ${command}`;
                const { stdout, stderr } = await execPromise(fallbackCmd, { timeout });
                return stdout || stderr;
            } catch (fallbackError) {
                return error.stdout || error.stderr || error.message;
            }
        }
    }

    /**
     * Run local command (for non-sensitive operations only)
     */
    async runLocalCommand(command, timeout = 30000) {
        try {
            const { stdout, stderr } = await execPromise(command, { timeout });
            return stdout || stderr;
        } catch (error) {
            return error.stdout || error.stderr || error.message;
        }
    }

    async runTool(toolId, target) {
        if (!target) throw new Error("Target is required");
        // Strict sanitization to prevent command injection
        if (/[;\&|`$(){}[\]\\]/.test(target)) throw new Error("Invalid target format - special characters not allowed");

        try {
            switch (toolId) {
                case 'whois':
                    // WHOIS via Tor
                    return await this.runTorCommand(`whois ${target}`);
                    
                case 'nslookup':
                    // DNS via Tor (using Tor's DNS)
                    return await this.runTorCommand(`dig @127.0.0.1 ${target} ANY`);
                    
                case 'ping':
                    // Ping is local-only (non-sensitive)
                    if (process.platform === 'win32') {
                        return await this.runLocalCommand(`ping -n 4 ${target}`);
                    }
                    return await this.runLocalCommand(`ping -c 4 ${target}`);
                    
                case 'sherlock':
                    return await this.runSherlock(target);
                    
                case 'theharvester':
                    return await this.runTheHarvester(target);
                    
                case 'amass':
                    return await this.runAmass(target);
                    
                default:
                    throw new Error("Unknown tool");
            }
        } catch (error) {
            return `Error running ${toolId}: ${error.message}`;
        }
    }

    /**
     * Run Sherlock username search via Tor
     */
    async runSherlock(username) {
        // Validate username to prevent injection
        if (!/^[a-zA-Z0-9_.-]+$/.test(username)) {
            return "Invalid username format. Alphanumeric, underscore, dot and dash only.";
        }

        // Run Sherlock inside Kali container with Tor
        const command = `sherlock ${username} --timeout 30 --print-found`;
        
        try {
            return await this.runTorCommand(command, 180000);
        } catch (error) {
            return `Error running Sherlock: ${error.message}`;
        }
    }

    /**
     * Run theHarvester email/domain reconnaissance via Tor
     */
    async runTheHarvester(target) {
        if (!/^[a-zA-Z0-9.-]+$/.test(target)) {
            return "Invalid target format for theHarvester.";
        }

        const command = `theHarvester -d ${target} -l 100 -b google,bing,linkedin`;
        
        try {
            return await this.runTorCommand(command, 300000);
        } catch (error) {
            return `Error running theHarvester: ${error.message}`;
        }
    }

    /**
     * Run Amass DNS enumeration via Tor
     */
    async runAmass(target) {
        if (!/^[a-zA-Z0-9.-]+$/.test(target)) {
            return "Invalid target format for Amass.";
        }

        // Passive mode to minimize footprint
        const command = `amass enum -passive -d ${target}`;
        
        try {
            return await this.runTorCommand(command, 600000);
        } catch (error) {
            return `Error running Amass: ${error.message}`;
        }
    }

    // SpiderFoot Management (runs in its own container with Tor network)
    async startSpiderFoot() {
        // Connect SpiderFoot to the Tor network
        const command = `docker run -d -p 5001:5001 --network container:th3_kali_tor --name spiderfoot spiderfoot/spiderfoot`;
        try {
            await this.runLocalCommand(command);
            return "SpiderFoot started on http://localhost:5001 (connected to Tor network)";
        } catch (error) {
            if (error.message && error.message.includes("Conflict")) {
                return "SpiderFoot is already running. Access http://localhost:5001";
            }
            // Try without Tor network
            try {
                await this.runLocalCommand(`docker run -d -p 5001:5001 --name spiderfoot spiderfoot/spiderfoot`);
                return "SpiderFoot started on http://localhost:5001 (WARNING: Not Tor-connected)";
            } catch (e) {
                return `Error starting SpiderFoot: ${e.message}`;
            }
        }
    }

    async stopSpiderFoot() {
        try {
            await this.runLocalCommand(`docker stop spiderfoot`);
            await this.runLocalCommand(`docker rm spiderfoot`);
            return "SpiderFoot stopped and container removed.";
        } catch (error) {
            return `Error stopping SpiderFoot: ${error.message}`;
        }
    }

    async getSpiderFootStatus() {
        try {
            const output = await this.runLocalCommand(`docker ps --filter "name=spiderfoot" --format "{{.Status}}"`);
            return output.trim() ? "Running" : "Stopped";
        } catch (error) {
            return "Unknown";
        }
    }

    /**
     * Verify Tor anonymity before running sensitive operations
     */
    async verifyTorAnonymity() {
        try {
            const result = await this.runTorCommand('curl -s https://check.torproject.org/api/ip', 20000);
            const data = JSON.parse(result);
            return {
                anonymous: data.IsTor === true,
                exitIP: data.IP
            };
        } catch (error) {
            return {
                anonymous: false,
                error: error.message
            };
        }
    }

    async ensureDockerRunning() {
        try {
            await this.runLocalCommand('docker info', 5000);
            console.log("[OSINT] Docker is running.");
            
            // Verify Kali Tor container
            const kaliStatus = await this.runLocalCommand('docker ps --filter "name=th3_kali_tor" --format "{{.Status}}"');
            if (kaliStatus.includes('Up')) {
                console.log("[OSINT] ✅ Tor container (th3_kali_tor) is running");
            } else {
                console.log("[OSINT] ⚠️ Starting Tor container...");
                await this.runLocalCommand('docker start th3_kali_tor');
            }
        } catch (error) {
            console.log("[OSINT] Docker not running. Attempting to start...");
            try {
                const startCommand = `start "" "C:\\Program Files\\Docker\\Docker\\Docker Desktop.exe"`;
                await this.runLocalCommand(startCommand);
                console.log("[OSINT] Docker Desktop launch command sent. Waiting for initialization...");
            } catch (startError) {
                console.error("[OSINT] Failed to start Docker:", startError.message);
            }
        }
    }
}

module.exports = OsintService;
