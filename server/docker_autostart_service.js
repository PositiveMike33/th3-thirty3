/**
 * Docker Auto-Start Service
 * Th3 Thirty3 - Automatic container management at application startup
 * 
 * Manages:
 * - Docker Desktop startup
 * - Container health checks
 * - Auto-restart of required containers
 * - Graceful error handling
 */

const { exec, spawn } = require('child_process');
const EventEmitter = require('events');

class DockerAutoStartService extends EventEmitter {
    constructor() {
        super();
        
        // Container configurations
        this.containers = {
            // ====================================
            // CORE INFRASTRUCTURE CONTAINERS
            // ====================================
            'th3_kali_tor': {
                name: 'th3_kali_tor',
                description: 'Kali Linux + TOR for anonymous operations',
                required: true,
                composeFile: require('path').join(__dirname, '..', 'docker', 'docker-compose.yml'),
                service: 'kali-tor',
                healthCheck: async () => this.checkTorHealth(),
                startDelay: 30000 // Wait for TOR bootstrap
            },
            'th3_redis': {
                name: 'th3_redis',
                description: 'Redis cache for session management',
                required: false,
                composeFile: require('path').join(__dirname, '..', 'docker', 'docker-compose.yml'),
                service: 'redis',
                healthCheck: async () => this.checkRedisHealth()
            },
            'th3_ollama_proxy': {
                name: 'th3_ollama_proxy',
                description: 'Ollama load balancer and proxy',
                required: false,
                composeFile: require('path').join(__dirname, '..', 'docker', 'docker-compose.yml'),
                service: 'ollama-proxy',
                depends: ['th3_redis']
            },
            
            // ====================================
            // MCP (Model Context Protocol) CONTAINERS
            // ====================================
            'mcp_stripe': {
                name: 'mcp_stripe',
                description: 'Stripe MCP for payment processing',
                required: false,
                image: 'mcp/stripe',
                dockerArgs: [
                    '--rm',
                    '-d',
                    '--name', 'mcp_stripe',
                    '-e', `STRIPE_SECRET_KEY=${process.env.STRIPE_SECRET_KEY || ''}`,
                    'mcp/stripe',
                    '--tools=all'  // Required argument - enables all Stripe tools
                ],
                envRequired: ['STRIPE_SECRET_KEY'],
                healthCheck: async () => this.checkMCPHealth('mcp_stripe')
            },
            'mcp_paypal': {
                name: 'mcp_paypal',
                description: 'PayPal MCP for payment processing',
                required: false,
                image: 'mcp/paypal',
                dockerArgs: [
                    '--rm',
                    '-d',
                    '--name', 'mcp_paypal',
                    '-e', `PAYPAL_CLIENT_ID=${process.env.PAYPAL_CLIENT_ID || ''}`,
                    '-e', `PAYPAL_CLIENT_SECRET=${process.env.PAYPAL_CLIENT_SECRET || ''}`,
                    '-e', `PAYPAL_MODE=${process.env.PAYPAL_MODE || 'sandbox'}`,
                    'mcp/paypal',
                    '--tools=all'
                ],
                envRequired: ['PAYPAL_CLIENT_ID', 'PAYPAL_CLIENT_SECRET'],
                healthCheck: async () => this.checkMCPHealth('mcp_paypal')
            },
            'mcp_brave_search': {
                name: 'mcp_brave_search',
                description: 'Brave Search MCP for web search',
                required: false,
                image: 'mcp/brave-search',
                dockerArgs: [
                    '--rm',
                    '-d',
                    '--name', 'mcp_brave_search',
                    '-e', `BRAVE_API_KEY=${process.env.BRAVE_API_KEY || ''}`,
                    'mcp/brave-search'
                ],
                envRequired: ['BRAVE_API_KEY'],
                healthCheck: async () => this.checkMCPHealth('mcp_brave_search')
            },
            'mcp_playwright': {
                name: 'mcp_playwright',
                description: 'Playwright MCP for browser automation',
                required: false,
                image: 'mcp/playwright',
                dockerArgs: [
                    '--rm',
                    '-d',
                    '--name', 'mcp_playwright',
                    '--shm-size=1g',  // Important for Chrome
                    'mcp/playwright'
                ],
                healthCheck: async () => this.checkMCPHealth('mcp_playwright')
            }
        };
        
        // Status tracking
        this.status = {
            dockerRunning: false,
            containersStatus: {},
            errors: [],
            lastCheck: null
        };
        
        console.log('[DOCKER] Auto-Start Service initialized');
    }

    /**
     * Check if Docker Desktop is running
     */
    async isDockerRunning() {
        return new Promise((resolve) => {
            exec('docker info', { timeout: 10000 }, (error) => {
                resolve(!error);
            });
        });
    }

    /**
     * Start Docker Desktop (Windows)
     */
    async startDockerDesktop() {
        console.log('[DOCKER] Starting Docker Desktop...');
        
        return new Promise((resolve, reject) => {
            // Find Docker Desktop path
            const dockerPaths = [
                'C:\\Program Files\\Docker\\Docker\\Docker Desktop.exe',
                `${process.env.LOCALAPPDATA}\\Docker\\Docker Desktop.exe`
            ];
            
            const fs = require('fs');
            let dockerPath = null;
            
            for (const p of dockerPaths) {
                if (fs.existsSync(p)) {
                    dockerPath = p;
                    break;
                }
            }
            
            if (!dockerPath) {
                console.log('[DOCKER] Docker Desktop not found');
                return resolve(false);
            }
            
            // Start Docker Desktop
            spawn(dockerPath, [], { 
                detached: true, 
                stdio: 'ignore',
                windowsHide: true
            }).unref();
            
            // Wait for Docker to be ready
            console.log('[DOCKER] Waiting for Docker to start...');
            let attempts = 0;
            const maxAttempts = 30; // 60 seconds
            
            const checkInterval = setInterval(async () => {
                attempts++;
                const running = await this.isDockerRunning();
                
                if (running) {
                    clearInterval(checkInterval);
                    console.log('[DOCKER] Docker Desktop is now running');
                    resolve(true);
                } else if (attempts >= maxAttempts) {
                    clearInterval(checkInterval);
                    console.log('[DOCKER] Docker Desktop startup timeout');
                    resolve(false);
                }
            }, 2000);
        });
    }

    /**
     * Get container status
     */
    async getContainerStatus(containerName) {
        return new Promise((resolve) => {
            exec(`docker inspect -f "{{.State.Status}}" ${containerName}`, (error, stdout) => {
                if (error) {
                    resolve({ exists: false, status: 'not_found' });
                } else {
                    const status = stdout.trim();
                    resolve({ exists: true, status });
                }
            });
        });
    }

    /**
     * Start a single container
     */
    async startContainer(containerName) {
        const config = this.containers[containerName];
        if (!config) {
            console.log(`[DOCKER] Unknown container: ${containerName}`);
            return false;
        }

        // Check required environment variables for MCP containers
        if (config.envRequired) {
            const missing = config.envRequired.filter(env => !process.env[env]);
            if (missing.length > 0) {
                console.log(`[DOCKER] ⚠️ ${containerName} skipped - Missing env: ${missing.join(', ')}`);
                return false;
            }
        }

        console.log(`[DOCKER] Starting ${containerName}...`);
        
        return new Promise((resolve) => {
            // First try to start existing container
            exec(`docker start ${containerName}`, (error) => {
                if (!error) {
                    console.log(`[DOCKER] ✅ ${containerName} started`);
                    resolve(true);
                } else {
                    // Container doesn't exist
                    
                    // Method 1: MCP containers with direct docker run
                    if (config.dockerArgs) {
                        console.log(`[DOCKER] Creating MCP container with docker run...`);
                        
                        // Build dynamic docker args with fresh env values
                        const args = this.buildDockerArgs(config);
                        const dockerCmd = `docker run ${args.join(' ')}`;
                        
                        exec(dockerCmd, { cwd: process.cwd() }, (dockerError, stdout, stderr) => {
                            if (dockerError) {
                                console.error(`[DOCKER] ❌ Failed to start ${containerName}: ${stderr}`);
                                this.status.errors.push({
                                    container: containerName,
                                    error: stderr,
                                    timestamp: new Date().toISOString()
                                });
                                resolve(false);
                            } else {
                                console.log(`[DOCKER] ✅ ${containerName} created and started`);
                                resolve(true);
                            }
                        });
                    }
                    // Method 2: Docker Compose
                    else if (config.composeFile) {
                        console.log(`[DOCKER] Using docker-compose...`);
                        
                        const composeCmd = `docker-compose -f ${config.composeFile} up -d ${config.service}`;
                        exec(composeCmd, { cwd: process.cwd() }, (composeError, stdout, stderr) => {
                            if (composeError) {
                                console.error(`[DOCKER] ❌ Failed to start ${containerName}: ${stderr}`);
                                this.status.errors.push({
                                    container: containerName,
                                    error: stderr,
                                    timestamp: new Date().toISOString()
                                });
                                resolve(false);
                            } else {
                                console.log(`[DOCKER] ✅ ${containerName} created and started`);
                                resolve(true);
                            }
                        });
                    } else {
                        console.error(`[DOCKER] ❌ No start method for ${containerName}`);
                        resolve(false);
                    }
                }
            });
        });
    }

    /**
     * Build docker run arguments with current environment values
     */
    buildDockerArgs(config) {
        if (!config.dockerArgs) return [];
        
        return config.dockerArgs.map(arg => {
            // Replace environment variable placeholders
            if (typeof arg === 'string' && arg.includes('${')) {
                return arg.replace(/\$\{(\w+)\}/g, (match, envVar) => {
                    return process.env[envVar] || '';
                });
            }
            return arg;
        });
    }

    /**
     * Stop a container
     */
    async stopContainer(containerName) {
        return new Promise((resolve) => {
            exec(`docker stop ${containerName}`, (error) => {
                resolve(!error);
            });
        });
    }

    /**
     * Check TOR container health
     */
    async checkTorHealth() {
        return new Promise((resolve) => {
            exec('docker exec th3_kali_tor curl -s --socks5 localhost:9050 https://check.torproject.org/api/ip --max-time 15', 
                { timeout: 20000 }, 
                (error, stdout) => {
                    if (error) {
                        resolve({ healthy: false, error: error.message });
                    } else {
                        try {
                            const data = JSON.parse(stdout);
                            resolve({ 
                                healthy: data.IsTor === true, 
                                ip: data.IP,
                                isTor: data.IsTor 
                            });
                        } catch {
                            resolve({ healthy: false, error: 'Parse error' });
                        }
                    }
                });
        });
    }

    /**
     * Check Redis health
     */
    async checkRedisHealth() {
        return new Promise((resolve) => {
            exec('docker exec th3_redis redis-cli ping', { timeout: 5000 }, (error, stdout) => {
                resolve({ healthy: stdout.trim() === 'PONG' });
            });
        });
    }

    /**
     * Check MCP container health (generic check for MCP containers)
     */
    async checkMCPHealth(containerName) {
        return new Promise((resolve) => {
            // Check if container is running
            exec(`docker inspect -f "{{.State.Running}}" ${containerName}`, { timeout: 5000 }, (error, stdout) => {
                if (error) {
                    resolve({ healthy: false, error: 'Container not found' });
                } else {
                    const isRunning = stdout.trim() === 'true';
                    if (isRunning) {
                        // Check container logs for errors
                        exec(`docker logs ${containerName} --tail 5 2>&1`, { timeout: 5000 }, (logError, logOutput) => {
                            const hasError = logOutput.toLowerCase().includes('error') || 
                                            logOutput.toLowerCase().includes('failed');
                            resolve({ 
                                healthy: !hasError, 
                                running: true,
                                lastLogs: logOutput.substring(0, 200)
                            });
                        });
                    } else {
                        resolve({ healthy: false, running: false, error: 'Container stopped' });
                    }
                }
            });
        });
    }

    /**
     * Start all required containers
     */
    async startAllContainers() {
        console.log('\n[DOCKER] ═══════════════════════════════════════════════');
        console.log('[DOCKER]   STARTING DOCKER INFRASTRUCTURE');
        console.log('[DOCKER] ═══════════════════════════════════════════════\n');

        // Check Docker
        const dockerRunning = await this.isDockerRunning();
        
        if (!dockerRunning) {
            console.log('[DOCKER] Docker is not running, attempting to start...');
            const started = await this.startDockerDesktop();
            
            if (!started) {
                console.log('[DOCKER] ❌ Could not start Docker Desktop');
                console.log('[DOCKER] Please start Docker Desktop manually');
                return { success: false, error: 'Docker not available' };
            }
        }

        this.status.dockerRunning = true;
        console.log('[DOCKER] ✅ Docker is running\n');

        // Start containers in order (respecting dependencies)
        const results = {};
        
        for (const [name, config] of Object.entries(this.containers)) {
            // Check dependencies
            if (config.depends) {
                for (const dep of config.depends) {
                    if (!results[dep]) {
                        console.log(`[DOCKER] Waiting for dependency: ${dep}`);
                        await this.startContainer(dep);
                        await new Promise(r => setTimeout(r, 3000));
                    }
                }
            }
            
            // Check current status
            const status = await this.getContainerStatus(name);
            
            if (status.status === 'running') {
                console.log(`[DOCKER] ✅ ${name} is already running`);
                results[name] = { success: true, status: 'already_running' };
            } else {
                // Start container
                const started = await this.startContainer(name);
                results[name] = { success: started, status: started ? 'started' : 'failed' };
                
                // Wait for startup delay if specified
                if (started && config.startDelay) {
                    console.log(`[DOCKER] Waiting ${config.startDelay/1000}s for ${name} to initialize...`);
                    await new Promise(r => setTimeout(r, config.startDelay));
                }
            }
            
            // Run health check if available
            if (config.healthCheck && results[name].success) {
                console.log(`[DOCKER] Health check for ${name}...`);
                const health = await config.healthCheck();
                results[name].health = health;
                
                if (health.healthy) {
                    console.log(`[DOCKER] ✅ ${name} health check passed`);
                } else {
                    console.log(`[DOCKER] ⚠️ ${name} health check: ${health.error || 'Not healthy'}`);
                }
            }
            
            this.status.containersStatus[name] = results[name];
        }

        this.status.lastCheck = new Date().toISOString();

        // Summary
        console.log('\n[DOCKER] ───────────────────────────────────────────────');
        console.log('[DOCKER]   CONTAINER STATUS SUMMARY');
        console.log('[DOCKER] ───────────────────────────────────────────────');
        
        let allSuccess = true;
        for (const [name, result] of Object.entries(results)) {
            const icon = result.success ? '✅' : '❌';
            const healthInfo = result.health ? (result.health.healthy ? '(healthy)' : '(unhealthy)') : '';
            console.log(`[DOCKER]   ${icon} ${name}: ${result.status} ${healthInfo}`);
            if (!result.success && this.containers[name].required) {
                allSuccess = false;
            }
        }
        console.log('[DOCKER] ───────────────────────────────────────────────\n');

        return { success: allSuccess, results };
    }

    /**
     * Stop all containers
     */
    async stopAllContainers() {
        console.log('[DOCKER] Stopping all containers...');
        
        for (const name of Object.keys(this.containers)) {
            await this.stopContainer(name);
        }
        
        console.log('[DOCKER] All containers stopped');
    }

    /**
     * Get current status
     */
    getStatus() {
        return this.status;
    }

    /**
     * Cleanup stale containers
     */
    async cleanupStaleContainers() {
        return new Promise((resolve) => {
            exec('docker container prune -f', (error, stdout) => {
                if (!error) {
                    console.log('[DOCKER] Cleaned up stale containers');
                }
                resolve(!error);
            });
        });
    }
}

// Singleton
const dockerAutoStart = new DockerAutoStartService();

module.exports = dockerAutoStart;
