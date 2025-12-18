const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

class OsintService {
    constructor() {
        this.tools = [
            { id: 'whois', name: 'WHOIS Lookup', description: 'Domain registration info' },
            { id: 'nslookup', name: 'DNS Lookup', description: 'Domain name server info' },
            { id: 'ping', name: 'Ping', description: 'Check host availability' },
            { id: 'sherlock', name: 'Sherlock (Username)', description: 'Find usernames across social networks' },
            { id: 'spiderfoot', name: 'SpiderFoot (Full Scan)', description: 'Automated OSINT collection (Web UI)' }
        ];
        this.ensureDockerRunning();
    }

    getTools() {
        return this.tools;
    }

    // Validate domain format
    isValidDomain(domain) {
        // Basic domain validation: allows domain.tld, sub.domain.tld, IP addresses
        const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^(?:\d{1,3}\.){3}\d{1,3}$/;
        return domainRegex.test(domain);
    }

    // Validate IP or hostname for ping
    isValidPingTarget(target) {
        // Allow domain names, IPs
        const targetRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$|^(?:\d{1,3}\.){3}\d{1,3}$/;
        return targetRegex.test(target);
    }

    async runTool(toolId, target) {
        if (!target) throw new Error("Target is required");
        
        // Trim and clean target
        target = target.trim();
        
        // Basic sanitization to prevent command injection
        if (/[;&|`$(){}[\]<>\\]/.test(target)) {
            return `[ERROR] Invalid target format: Special characters not allowed. Please use only alphanumeric characters, dots, and hyphens.`;
        }

        console.log(`[OSINT] Running ${toolId} on target: ${target}`);

        try {
            switch (toolId) {
                case 'whois':
                    // Validate domain before running whois
                    if (!this.isValidDomain(target)) {
                        return `[ERROR] Invalid domain format: "${target}"\n\nPlease enter a valid domain name (e.g., example.com, google.com) or IP address (e.g., 8.8.8.8).\n\nExamples of valid targets:\n  • google.com\n  • github.com\n  • 1.1.1.1`;
                    }
                    return await this.runWhois(target);
                    
                case 'nslookup':
                    if (!this.isValidPingTarget(target)) {
                        return `[ERROR] Invalid target: "${target}"\n\nPlease enter a valid domain name or IP address.`;
                    }
                    return await this.runCommand(`nslookup ${target}`);
                    
                case 'ping':
                    if (!this.isValidPingTarget(target)) {
                        return `[ERROR] Invalid target: "${target}"\n\nPlease enter a valid domain name or IP address.`;
                    }
                    // Windows ping needs -n for count
                    return await this.runCommand(`ping -n 4 ${target}`);
                    
                case 'sherlock':
                    return await this.runSherlock(target);
                    
                default:
                    throw new Error("Unknown tool");
            }
        } catch (error) {
            console.error(`[OSINT] Error running ${toolId}:`, error.message);
            return `[ERROR] Running ${toolId}: ${error.message}`;
        }
    }

    // WHOIS with fallback to online API
    async runWhois(domain) {
        console.log(`[OSINT] WHOIS lookup for: ${domain}`);
        
        // First try local whois command
        try {
            const result = await this.runCommand(`whois ${domain}`);
            if (result && !result.includes("'whois' is not recognized") && !result.includes("not found")) {
                return `[WHOIS LOOKUP - LOCAL]\nDomain: ${domain}\n${'='.repeat(50)}\n\n${result}`;
            }
        } catch (localError) {
            console.log(`[OSINT] Local whois failed, trying online API...`);
        }

        // Fallback to online WHOIS API
        try {
            const response = await fetch(`https://api.whoisfreaks.com/v1.0/whois?whois=live&domainName=${domain}&apiKey=free`);
            
            if (!response.ok) {
                // Try alternative free API
                return await this.runWhoisAlternative(domain);
            }
            
            const data = await response.json();
            return this.formatWhoisResponse(domain, data);
        } catch (apiError) {
            console.log(`[OSINT] Primary API failed, trying alternative...`);
            return await this.runWhoisAlternative(domain);
        }
    }

    // Alternative WHOIS using RDAP (official ICANN protocol)
    async runWhoisAlternative(domain) {
        try {
            // RDAP is the official ICANN replacement for WHOIS
            const tld = domain.split('.').pop();
            const rdapUrl = `https://rdap.org/domain/${domain}`;
            
            const response = await fetch(rdapUrl, {
                headers: { 'Accept': 'application/rdap+json' }
            });
            
            if (!response.ok) {
                throw new Error(`RDAP lookup failed: ${response.status}`);
            }
            
            const data = await response.json();
            return this.formatRdapResponse(domain, data);
        } catch (rdapError) {
            console.error(`[OSINT] RDAP lookup failed:`, rdapError.message);
            
            // Last resort: basic DNS info
            try {
                const dnsResult = await this.runCommand(`nslookup ${domain}`);
                return `[WHOIS LOOKUP - FALLBACK MODE]\nDomain: ${domain}\n${'='.repeat(50)}\n\n⚠️ WHOIS servers unavailable. Showing DNS info instead:\n\n${dnsResult}\n\n💡 TIP: For full WHOIS, try:\n  • https://who.is/${domain}\n  • https://whois.domaintools.com/${domain}`;
            } catch (e) {
                return `[ERROR] WHOIS lookup failed for ${domain}.\n\nThe local 'whois' command is not installed and online APIs are unavailable.\n\n🔧 SOLUTIONS:\n1. Install whois on Windows: choco install whois\n2. Use online tool: https://who.is/${domain}`;
            }
        }
    }

    formatWhoisResponse(domain, data) {
        let output = `[WHOIS LOOKUP - ONLINE API]\nDomain: ${domain}\n${'='.repeat(50)}\n\n`;
        
        if (data.domain_name) output += `Domain Name: ${data.domain_name}\n`;
        if (data.registrar) output += `Registrar: ${data.registrar}\n`;
        if (data.creation_date) output += `Created: ${data.creation_date}\n`;
        if (data.expiration_date) output += `Expires: ${data.expiration_date}\n`;
        if (data.updated_date) output += `Updated: ${data.updated_date}\n`;
        if (data.name_servers) output += `Name Servers:\n${data.name_servers.map(ns => `  • ${ns}`).join('\n')}\n`;
        if (data.status) output += `Status: ${Array.isArray(data.status) ? data.status.join(', ') : data.status}\n`;
        
        return output || `[WHOIS] No data found for ${domain}`;
    }

    formatRdapResponse(domain, data) {
        let output = `[WHOIS LOOKUP - RDAP]\nDomain: ${domain}\n${'='.repeat(50)}\n\n`;
        
        if (data.ldhName) output += `Domain Name: ${data.ldhName}\n`;
        if (data.handle) output += `Handle: ${data.handle}\n`;
        
        // Registration dates
        if (data.events) {
            data.events.forEach(event => {
                if (event.eventAction === 'registration') output += `Created: ${event.eventDate}\n`;
                if (event.eventAction === 'expiration') output += `Expires: ${event.eventDate}\n`;
                if (event.eventAction === 'last changed') output += `Updated: ${event.eventDate}\n`;
            });
        }
        
        // Nameservers
        if (data.nameservers && data.nameservers.length > 0) {
            output += `Name Servers:\n`;
            data.nameservers.forEach(ns => {
                output += `  • ${ns.ldhName || ns}\n`;
            });
        }
        
        // Status
        if (data.status && data.status.length > 0) {
            output += `Status: ${data.status.join(', ')}\n`;
        }
        
        // Registrar
        if (data.entities) {
            const registrar = data.entities.find(e => e.roles && e.roles.includes('registrar'));
            if (registrar && registrar.vcardArray) {
                const vcard = registrar.vcardArray[1];
                const fnEntry = vcard.find(v => v[0] === 'fn');
                if (fnEntry) output += `Registrar: ${fnEntry[3]}\n`;
            }
        }
        
        return output;
    }

    async runCommand(command) {
        try {
            const { stdout, stderr } = await execPromise(command, { timeout: 30000 });
            return stdout || stderr || '[No output]';
        } catch (error) {
            // Exec throws on non-zero exit code, but we might still want the output
            if (error.stdout || error.stderr) {
                return error.stdout || error.stderr;
            }
            throw error;
        }
    }

    async runSherlock(username) {
        // Validate username to prevent injection
        if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
            return "Invalid username format. Alphanumeric, underscore, and dash only.";
        }

        // Using Docker container
        // --timeout 60: Limit execution time
        // --print-found: Only print found accounts
        const command = `docker run --rm sherlock/sherlock ${username} --timeout 60 --print-found`;

        try {
            // We use runCommand which wraps exec
            // Note: Docker might take a while, so the frontend needs to handle the wait.
            return await this.runCommand(command);
        } catch (error) {
            return `Error running Sherlock: ${error.message}`;
        }
    }

    // SpiderFoot Management
    async startSpiderFoot() {
        // Runs SpiderFoot on port 5001
        const command = `docker run -d -p 5001:5001 --name spiderfoot spiderfoot/spiderfoot`;
        try {
            await this.runCommand(command);
            return "SpiderFoot started on http://localhost:5001";
        } catch (error) {
            if (error.message.includes("Conflict")) {
                return "SpiderFoot is already running (or container exists). Try accessing http://localhost:5001";
            }
            return `Error starting SpiderFoot: ${error.message}`;
        }
    }

    async stopSpiderFoot() {
        try {
            await this.runCommand(`docker stop spiderfoot`);
            await this.runCommand(`docker rm spiderfoot`);
            return "SpiderFoot stopped and container removed.";
        } catch (error) {
            return `Error stopping SpiderFoot: ${error.message}`;
        }
    }

    async getSpiderFootStatus() {
        try {
            const output = await this.runCommand(`docker ps --filter "name=spiderfoot" --format "{{.Status}}"`);
            return output.trim() ? "Running" : "Stopped";
        } catch (error) {
            return "Unknown";
        }
    }

    async ensureDockerRunning() {
        try {
            await this.runCommand('docker info');
            console.log("[OSINT] Docker is running.");
        } catch (error) {
            console.log("[OSINT] Docker not running. Attempting to start...");
            try {
                // Attempt to start Docker Desktop on Windows
                // Using 'start' command to launch the executable without waiting
                const startCommand = `start "" "C:\\Program Files\\Docker\\Docker\\Docker Desktop.exe"`;
                await this.runCommand(startCommand);
                console.log("[OSINT] Docker Desktop launch command sent. Waiting for initialization...");
            } catch (startError) {
                console.error("[OSINT] Failed to start Docker:", startError.message);
            }
        }
    }
}

module.exports = OsintService;
