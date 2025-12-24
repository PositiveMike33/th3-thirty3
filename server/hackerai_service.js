/**
 * HACKERAI SERVICE
 * 
 * Integration with HackerAI (hackerai.co) and HackerGPT
 * Provides penetration testing AI capabilities via local agent or cloud
 * 
 * Setup:
 * - Install: npx @hackerai/local@latest
 * - With token: npx @hackerai/local@latest --token YOUR_TOKEN --name "Machine Name"
 * - Kali mode: npx @hackerai/local@latest --token YOUR_TOKEN --name "Kali" --image kalilinux/kali-rolling
 */

const { spawn, exec } = require('child_process');
const path = require('path');

class HackerAIService {
    constructor() {
        this.token = process.env.HACKERAI_TOKEN;
        this.mode = process.env.HACKERAI_MODE || 'docker';
        this.agentProcess = null;
        this.isRunning = false;
        this.logs = [];
        
        if (this.token) {
            console.log('[HACKERAI] HackerAI Service initialized (Token configured)');
        } else {
            console.log('[HACKERAI] HackerAI Service initialized (No token - configure HACKERAI_TOKEN)');
        }
    }

    /**
     * Get service status
     */
    getStatus() {
        return {
            configured: !!this.token,
            running: this.isRunning,
            mode: this.mode,
            logsCount: this.logs.length
        };
    }

    /**
     * Start the local HackerAI agent
     * @param {Object} options - Agent options
     * @param {string} options.name - Machine name
     * @param {string} options.image - Docker image (optional, default: hackerai default)
     */
    async startAgent(options = {}) {
        if (!this.token) {
            throw new Error('HACKERAI_TOKEN not configured. Add it to .env');
        }

        if (this.isRunning) {
            return { success: false, message: 'Agent already running' };
        }

        const args = [
            '@hackerai/local@latest',
            '--token', this.token,
            '--name', options.name || 'Th3Thirty3-Agent'
        ];

        // Add Kali Linux image if specified
        if (options.image) {
            args.push('--image', options.image);
        }

        // Dangerous mode (host instead of docker)
        if (options.hostMode || this.mode === 'host') {
            args.push('--dangerous');
        }

        return new Promise((resolve, reject) => {
            try {
                console.log(`[HACKERAI] Starting agent: npx ${args.join(' ')}`);
                
                this.agentProcess = spawn('npx', args, {
                    shell: true,
                    stdio: ['pipe', 'pipe', 'pipe']
                });

                this.isRunning = true;

                this.agentProcess.stdout.on('data', (data) => {
                    const log = data.toString();
                    this.logs.push({ type: 'stdout', msg: log, time: new Date() });
                    console.log('[HACKERAI]', log);
                });

                this.agentProcess.stderr.on('data', (data) => {
                    const log = data.toString();
                    this.logs.push({ type: 'stderr', msg: log, time: new Date() });
                    console.error('[HACKERAI ERROR]', log);
                });

                this.agentProcess.on('close', (code) => {
                    this.isRunning = false;
                    console.log(`[HACKERAI] Agent exited with code ${code}`);
                });

                // Give it a moment to start
                setTimeout(() => {
                    resolve({
                        success: true,
                        message: 'HackerAI Agent started',
                        pid: this.agentProcess.pid,
                        mode: options.hostMode ? 'host' : 'docker',
                        image: options.image || 'default'
                    });
                }, 2000);

            } catch (error) {
                this.isRunning = false;
                reject(error);
            }
        });
    }

    /**
     * Start with Kali Linux image
     */
    async startKaliAgent(name = 'Kali-Th3Thirty3') {
        return this.startAgent({
            name,
            image: 'kalilinux/kali-rolling'
        });
    }

    /**
     * Stop the running agent
     */
    async stopAgent() {
        if (!this.agentProcess) {
            return { success: false, message: 'No agent running' };
        }

        this.agentProcess.kill('SIGTERM');
        this.isRunning = false;
        this.agentProcess = null;

        return { success: true, message: 'Agent stopped' };
    }

    /**
     * Get agent logs
     */
    getLogs(limit = 50) {
        return this.logs.slice(-limit);
    }

    /**
     * Clear logs
     */
    clearLogs() {
        this.logs = [];
        return { success: true };
    }

    /**
     * Check if HackerAI local package is installed
     */
    async checkInstallation() {
        return new Promise((resolve) => {
            exec('npx @hackerai/local@latest --version', (error, stdout, stderr) => {
                if (error) {
                    resolve({
                        installed: false,
                        message: 'HackerAI local package not found. Run: npx @hackerai/local@latest'
                    });
                } else {
                    resolve({
                        installed: true,
                        version: stdout.trim(),
                        message: 'HackerAI local package available'
                    });
                }
            });
        });
    }

    /**
     * Get quick start commands
     */
    getQuickStartCommands() {
        const token = this.token || 'YOUR_TOKEN_HERE';
        return {
            basic: `npx @hackerai/local@latest --token ${token} --name "My Machine"`,
            kali: `npx @hackerai/local@latest --token ${token} --name "Kali" --image kalilinux/kali-rolling`,
            dangerous: `npx @hackerai/local@latest --token ${token} --name "Host Mode" --dangerous`
        };
    }
}

// Singleton instance
let instance = null;

function getHackerAIService() {
    if (!instance) {
        instance = new HackerAIService();
    }
    return instance;
}

module.exports = { HackerAIService, getHackerAIService };
