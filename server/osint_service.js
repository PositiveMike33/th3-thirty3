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

    async runTool(toolId, target) {
        if (!target) throw new Error("Target is required");
        // Basic sanitization to prevent command injection
        if (/[;&|]/.test(target)) throw new Error("Invalid target format");

        try {
            switch (toolId) {
                case 'whois':
                    return await this.runCommand(`whois ${target}`); // Requires whois installed on system
                case 'nslookup':
                    return await this.runCommand(`nslookup ${target}`);
                case 'ping':
                    // Windows ping needs -n for count
                    return await this.runCommand(`ping -n 4 ${target}`);
                case 'sherlock':
                    // Placeholder for Sherlock - assuming it's installed or we simulate it for now
                    // In a real scenario, this would call the python script
                    return await this.runSherlock(target);
                default:
                    throw new Error("Unknown tool");
            }
        } catch (error) {
            return `Error running ${toolId}: ${error.message}`;
        }
    }

    async runCommand(command) {
        try {
            const { stdout, stderr } = await execPromise(command);
            return stdout || stderr;
        } catch (error) {
            // Exec throws on non-zero exit code, but we might still want the output
            return error.stdout || error.stderr || error.message;
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
