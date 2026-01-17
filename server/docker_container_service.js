/**
 * Docker Container Service pour Th3 Thirty3
 * Gère les connexions aux conteneurs: Kali-Tor, Redis, HexStrike
 */

const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

class DockerContainerService {
    constructor() {
        // Configuration des conteneurs
        this.containers = {
            kaliTor: {
                name: 'th3-kali',
                ports: { socks: 9050, control: 9051 },
                type: 'security'
            },
            redis: {
                name: 'th3_redis',
                ports: { main: 6379 },
                type: 'cache'
            },
            hexstrike: {
                name: 'th3-hexstrike',
                ports: { api: 8888 },
                type: 'security'
            }
        };

        // État des conteneurs
        this.status = {};

        console.log('[DOCKER] Container Service initialized');
    }

    /**
     * Vérifier si Docker est disponible
     */
    async checkDockerAvailable() {
        try {
            const { stdout } = await execPromise('docker --version', { timeout: 5000 });
            return { available: true, version: stdout.trim() };
        } catch (error) {
            return { available: false, error: error.message };
        }
    }

    /**
     * Lister tous les conteneurs en cours d'exécution
     */
    async listRunningContainers() {
        try {
            const { stdout } = await execPromise('docker ps --format "{{.Names}}|{{.Status}}|{{.Ports}}"', { timeout: 10000 });
            const containers = stdout.trim().split('\n').filter(Boolean).map(line => {
                const [name, status, ports] = line.split('|');
                return { name, status, ports, running: status.includes('Up') };
            });
            return containers;
        } catch (error) {
            console.error('[DOCKER] List containers error:', error.message);
            return [];
        }
    }

    /**
     * Vérifier le statut d'un conteneur spécifique
     */
    async checkContainerStatus(containerName) {
        try {
            const { stdout } = await execPromise(`docker inspect --format='{{.State.Status}}' ${containerName}`, { timeout: 5000 });
            return {
                running: stdout.trim() === 'running',
                status: stdout.trim()
            };
        } catch (error) {
            return { running: false, status: 'not_found', error: error.message };
        }
    }

    /**
     * Obtenir le statut de tous les conteneurs configurés
     */
    async getAllContainersStatus() {
        const status = {};

        for (const [key, config] of Object.entries(this.containers)) {
            const containerStatus = await this.checkContainerStatus(config.name);
            status[key] = {
                ...config,
                ...containerStatus
            };
        }

        this.status = status;
        return status;
    }

    /**
     * Démarrer un conteneur
     */
    async startContainer(containerName) {
        try {
            await execPromise(`docker start ${containerName}`, { timeout: 30000 });
            console.log(`[DOCKER] Container ${containerName} started`);
            return { success: true, message: `Container ${containerName} démarré` };
        } catch (error) {
            console.error(`[DOCKER] Failed to start ${containerName}:`, error.message);
            return { success: false, error: error.message };
        }
    }

    /**
     * Arrêter un conteneur
     */
    async stopContainer(containerName) {
        try {
            await execPromise(`docker stop ${containerName}`, { timeout: 30000 });
            console.log(`[DOCKER] Container ${containerName} stopped`);
            return { success: true, message: `Container ${containerName} arrêté` };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * Exécuter une commande dans le conteneur Kali-Tor
     */
    async execInKali(command, timeout = 60000) {
        try {
            const { stdout, stderr } = await execPromise(
                `docker exec ${this.containers.kaliTor.name} ${command}`,
                { timeout }
            );
            return { success: true, output: stdout, stderr };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * Exécuter un scan Nmap via Kali
     */
    async nmapScan(target, options = {}) {
        const flags = options.flags || '-sV -sC';
        const command = `nmap ${flags} ${target}`;
        console.log(`[DOCKER] Executing Nmap scan: ${command}`);
        return await this.execInKali(command, 120000);
    }

    /**
     * Exécuter Gobuster via Kali
     */
    async gobusterScan(url, wordlist = '/usr/share/wordlists/dirb/common.txt') {
        const command = `gobuster dir -u ${url} -w ${wordlist} -q`;
        console.log(`[DOCKER] Executing Gobuster: ${command}`);
        return await this.execInKali(command, 300000);
    }

    /**
     * Exécuter Nikto via Kali
     */
    async niktoScan(target) {
        const command = `nikto -h ${target} -Tuning 123bde`;
        console.log(`[DOCKER] Executing Nikto: ${command}`);
        return await this.execInKali(command, 600000);
    }

    /**
     * Exécuter SQLMap via Kali
     */
    async sqlmapScan(url, options = {}) {
        const level = options.level || 3;
        const risk = options.risk || 2;
        const command = `sqlmap -u "${url}" --batch --level ${level} --risk ${risk}`;
        console.log(`[DOCKER] Executing SQLMap: ${command}`);
        return await this.execInKali(command, 300000);
    }

    /**
     * Exécuter Sherlock (OSINT username) via Kali
     */
    async sherlockSearch(username) {
        const command = `sherlock ${username} --print-found`;
        console.log(`[DOCKER] Executing Sherlock: ${command}`);
        return await this.execInKali(command, 120000);
    }

    /**
     * Exécuter theHarvester (OSINT) via Kali
     */
    async theHarvester(domain, source = 'all') {
        const command = `theHarvester -d ${domain} -b ${source}`;
        console.log(`[DOCKER] Executing theHarvester: ${command}`);
        return await this.execInKali(command, 180000);
    }

    /**
     * Exécuter Amass (enumeration) via Kali
     */
    async amassScan(domain, passive = true) {
        const mode = passive ? '-passive' : '';
        const command = `amass enum ${mode} -d ${domain}`;
        console.log(`[DOCKER] Executing Amass: ${command}`);
        return await this.execInKali(command, 300000);
    }

    /**
     * Exécuter une requête via Tor dans Kali
     */
    async torRequest(url, method = 'GET') {
        const command = `curl -s --socks5-hostname localhost:9050 -X ${method} "${url}"`;
        console.log(`[DOCKER] Tor request: ${url}`);
        return await this.execInKali(command, 60000);
    }

    /**
     * Vérifier IP Tor
     */
    async checkTorIP() {
        return await this.torRequest('https://check.torproject.org/api/ip');
    }

    /**
     * Démarrer le stack Docker complet
     */
    async startStack(composeFile = './docker/docker-compose.yml') {
        try {
            const { stdout } = await execPromise(`docker-compose -f ${composeFile} up -d`, { timeout: 120000 });
            console.log('[DOCKER] Stack started successfully');
            return { success: true, output: stdout };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * Arrêter le stack Docker
     */
    async stopStack(composeFile = './docker/docker-compose.yml') {
        try {
            const { stdout } = await execPromise(`docker-compose -f ${composeFile} down`, { timeout: 60000 });
            return { success: true, output: stdout };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * Obtenir les logs d'un conteneur
     */
    async getContainerLogs(containerName, lines = 50) {
        try {
            const { stdout } = await execPromise(`docker logs --tail ${lines} ${containerName}`, { timeout: 10000 });
            return { success: true, logs: stdout };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }
}

// Export singleton
module.exports = new DockerContainerService();
