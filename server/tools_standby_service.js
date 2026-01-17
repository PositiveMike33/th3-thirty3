/**
 * Tools Standby Service pour Th3 Thirty3
 * Maintient les outils de sécurité prêts et en standby
 * Tor reste en activation manuelle uniquement
 */

const dockerService = require('./docker_container_service');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

class ToolsStandbyService {
    constructor() {
        // Configuration des outils en standby
        this.standbyTools = {
            hexstrike: {
                name: 'HexStrike',
                type: 'python_server',
                port: 8888,
                autoStart: true,
                status: 'idle'
            },
            kali: {
                name: 'Kali Container',
                container: 'th3-kali',
                autoStart: true,  // Auto-start mais Tor désactivé par défaut
                torEnabled: false, // Tor reste manuel
                status: 'idle'
            },
            osint: {
                name: 'OSINT Tools',
                container: 'th3-kali', // Partagé avec Kali
                autoStart: true,
                status: 'idle'
            }
        };

        // Tor configuration - MANUEL uniquement
        this.torConfig = {
            enabled: false,
            autoStart: false, // Ne jamais démarrer automatiquement
            port: 9050,
            controlPort: 9051
        };

        // Health check interval
        this.healthCheckInterval = null;
        this.isInitialized = false;

        console.log('[STANDBY] Tools Standby Service initialized');
    }

    /**
     * Initialiser tous les outils en standby
     */
    async initialize() {
        console.log('[STANDBY] Initializing standby tools...');

        // 1. Vérifier Docker
        const dockerAvailable = await dockerService.checkDockerAvailable();
        if (!dockerAvailable.available) {
            console.log('[STANDBY] Docker not available, skipping container startup');
        } else {
            // 2. Démarrer Kali container (sans Tor)
            await this.startKaliContainer();
        }

        // 3. Vérifier HexStrike
        await this.checkHexStrike();

        // 4. Démarrer health checks périodiques
        this.startHealthChecks();

        this.isInitialized = true;
        console.log('[STANDBY] ✅ All standby tools ready');

        return this.getStatus();
    }

    /**
     * Démarrer le container Kali (Tor désactivé par défaut)
     */
    async startKaliContainer() {
        try {
            const status = await dockerService.checkContainerStatus('th3-kali');

            if (!status.running) {
                console.log('[STANDBY] Starting Kali container...');
                await dockerService.startContainer('th3-kali');

                // Attendre que le container soit prêt
                await new Promise(resolve => setTimeout(resolve, 3000));
            }

            this.standbyTools.kali.status = 'ready';
            this.standbyTools.osint.status = 'ready';
            console.log('[STANDBY] ✅ Kali container ready (Tor disabled)');

        } catch (error) {
            console.error('[STANDBY] Failed to start Kali:', error.message);
            this.standbyTools.kali.status = 'error';
        }
    }

    /**
     * Vérifier si HexStrike est actif
     */
    async checkHexStrike() {
        try {
            const response = await fetch('http://localhost:8888/health', { timeout: 5000 });
            if (response.ok) {
                this.standbyTools.hexstrike.status = 'ready';
                console.log('[STANDBY] ✅ HexStrike is ready');
            }
        } catch {
            this.standbyTools.hexstrike.status = 'offline';
            console.log('[STANDBY] HexStrike offline (start with: python hexstrike_server.py)');
        }
    }

    /**
     * Activer Tor via Docker Container
     */
    async enableTor() {
        console.log('[STANDBY] 🧅 Enabling Tor via Docker...');

        try {
            // Start Docker Container
            const startResult = await dockerService.startContainer('th3-tor');

            if (startResult.success) {
                this.torConfig.enabled = true;
                this.torConfig.port = 9050;
                this.standbyTools.kali.torEnabled = true;

                // Wait for Tor to bootstrap (simple delay for now, could check logs)
                await new Promise(resolve => setTimeout(resolve, 5000));

                return {
                    success: true,
                    message: 'Tor Network Proxy activé!',
                    status: 'connected',
                    port: 9050,
                    instruction: 'Le proxy Tor est actif sur le port 9050.'
                };
            } else {
                return {
                    success: false,
                    message: 'Erreur lors du démarrage du conteneur Tor.',
                    error: startResult.error
                };
            }

        } catch (error) {
            console.error('[STANDBY] Failed to enable Tor:', error.message);
            return { success: false, error: error.message };
        }
    }

    /**
     * Désactiver Tor
     */
    async disableTor() {
        console.log('[STANDBY] Disabling Tor...');

        try {
            const stopResult = await dockerService.stopContainer('th3-tor');

            this.torConfig.enabled = false;
            this.standbyTools.kali.torEnabled = false;
            console.log('[STANDBY] Tor disabled');
            return { success: true, message: 'Tor désactivé' };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * Health checks périodiques
     */
    startHealthChecks() {
        if (this.healthCheckInterval) return;

        this.healthCheckInterval = setInterval(async () => {
            // Check Kali container
            try {
                const kaliStatus = await dockerService.checkContainerStatus('th3-kali');
                this.standbyTools.kali.status = kaliStatus.running ? 'ready' : 'offline';
                this.standbyTools.osint.status = kaliStatus.running ? 'ready' : 'offline';
            } catch {
                this.standbyTools.kali.status = 'error';
            }

            // Check HexStrike
            await this.checkHexStrike();

        }, 30000); // Toutes les 30 secondes

        console.log('[STANDBY] Health checks started (30s interval)');
    }

    /**
     * Arrêter les health checks
     */
    stopHealthChecks() {
        if (this.healthCheckInterval) {
            clearInterval(this.healthCheckInterval);
            this.healthCheckInterval = null;
        }
    }

    /**
     * Exécuter une commande rapide (pre-warmed)
     */
    async quickExec(tool, command, target) {
        const startTime = Date.now();

        // Vérifier que l'outil est prêt
        if (this.standbyTools[tool]?.status !== 'ready') {
            throw new Error(`Tool ${tool} not ready. Status: ${this.standbyTools[tool]?.status}`);
        }

        let result;
        switch (tool) {
            case 'kali':
            case 'osint':
                result = await dockerService.execInKali(command);
                break;
            case 'hexstrike':
                result = await this.hexstrikeExec(command, target);
                break;
            default:
                throw new Error(`Unknown tool: ${tool}`);
        }

        const execTime = Date.now() - startTime;
        console.log(`[STANDBY] Quick exec ${tool}: ${execTime}ms`);

        return { ...result, execTime };
    }

    /**
     * Exécution HexStrike
     */
    async hexstrikeExec(toolName, target) {
        try {
            const url = process.env.HEXSTRIKE_URL || 'http://hexstrike:8888';
            const response = await fetch(`${url}/execute`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ tool: toolName, params: { target } })
            });
            return await response.json();
        } catch (error) {
            throw new Error(`HexStrike exec failed: ${error.message}`);
        }
    }

    /**
     * Obtenir le statut de tous les outils
     */
    getStatus() {
        return {
            initialized: this.isInitialized,
            tools: this.standbyTools,
            tor: {
                ...this.torConfig,
                message: this.torConfig.enabled
                    ? '🧅 Tor ACTIF'
                    : '⏸️ Tor MANUEL (cliquez pour activer)'
            }
        };
    }

    /**
     * Pré-chauffer les outils pour une réponse rapide
     */
    async warmup() {
        console.log('[STANDBY] Warming up tools...');

        // Ping Kali container
        if (this.standbyTools.kali.status === 'ready') {
            await dockerService.execInKali('echo "warmup"', 5000);
        }

        // Ping HexStrike
        if (this.standbyTools.hexstrike.status === 'ready') {
            try {
                const url = process.env.HEXSTRIKE_URL || 'http://hexstrike:8888';
                await fetch(`${url}/health`);
            } catch { }
        }

        console.log('[STANDBY] ✅ Warmup complete');
    }
}

// Export singleton
module.exports = new ToolsStandbyService();
