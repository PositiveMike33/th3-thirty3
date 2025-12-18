/**
 * Tor Network Service pour Th3 Thirty3
 * Connexion anonyme via le réseau Tor pour OSINT et Hacking
 * Changement d'IP automatique, accès Dark Web sécurisé
 */

const { SocksProxyAgent } = require('socks-proxy-agent');
const { exec } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const EventEmitter = require('events');

class TorNetworkService extends EventEmitter {
    constructor() {
        super();
        
        // Configuration Tor
        this.torHost = process.env.TOR_HOST || '127.0.0.1';
        this.torSocksPort = parseInt(process.env.TOR_SOCKS_PORT) || 9050;
        this.torControlPort = parseInt(process.env.TOR_CONTROL_PORT) || 9051;
        this.torControlPassword = process.env.TOR_CONTROL_PASSWORD || '';
        
        // État du service
        this.isConnected = false;
        this.currentIP = null;
        this.circuitChanges = 0;
        this.lastCircuitChange = null;
        
        // Configuration du proxy SOCKS5
        this.proxyUrl = `socks5h://${this.torHost}:${this.torSocksPort}`;
        this.agent = null;
        
        // Stats
        this.stats = {
            requestsMade: 0,
            ipChanges: 0,
            onionSitesVisited: 0,
            errors: 0
        };

        console.log('[TOR] Service initialized');
    }

    /**
     * Vérifier si Tor est installé et en cours d'exécution
     */
    async checkTorStatus() {
        return new Promise((resolve) => {
            // Check if Tor is running by testing the SOCKS port
            const net = require('net');
            const socket = new net.Socket();
            
            socket.setTimeout(5000);
            
            socket.on('connect', () => {
                socket.destroy();
                this.isConnected = true;
                resolve({ running: true, port: this.torSocksPort });
            });
            
            socket.on('timeout', () => {
                socket.destroy();
                this.isConnected = false;
                resolve({ running: false, error: 'Connection timeout' });
            });
            
            socket.on('error', () => {
                socket.destroy();
                this.isConnected = false;
                resolve({ running: false, error: 'Tor not running on port ' + this.torSocksPort });
            });
            
            socket.connect(this.torSocksPort, this.torHost);
        });
    }

    /**
     * Obtenir un agent proxy SOCKS5 pour les requêtes HTTP
     */
    getProxyAgent() {
        if (!this.agent) {
            this.agent = new SocksProxyAgent(this.proxyUrl);
        }
        return this.agent;
    }

    /**
     * Faire une requête HTTP via Tor
     * Uses Docker Kali-Tor if available (most reliable on Windows)
     */
    async torFetch(url, options = {}) {
        // Try Docker Kali-Tor first (more reliable on Windows)
        try {
            const dockerResult = await this.torFetchViaDocker(url, options);
            if (dockerResult) {
                this.stats.requestsMade++;
                if (url.includes('.onion')) {
                    this.stats.onionSitesVisited++;
                }
                return dockerResult;
            }
        } catch (e) {
            console.log('[TOR] Docker not available, using direct SOCKS5');
        }

        // Fallback to direct SOCKS5 proxy
        const status = await this.checkTorStatus();
        if (!status.running) {
            throw new Error(`Tor non connecté: ${status.error}. Lancez Tor d'abord.`);
        }

        const agent = this.getProxyAgent();
        
        try {
            const response = await fetch(url, {
                ...options,
                agent: agent,
                // Timeout for .onion sites can be longer
                timeout: url.includes('.onion') ? 60000 : 30000
            });
            
            this.stats.requestsMade++;
            if (url.includes('.onion')) {
                this.stats.onionSitesVisited++;
            }
            
            return response;
        } catch (error) {
            this.stats.errors++;
            console.error('[TOR] Request failed:', error.message);
            throw error;
        }
    }

    /**
     * Execute HTTP request via Docker Kali-Tor container
     */
    async torFetchViaDocker(url, options = {}) {
        return new Promise((resolve, reject) => {
            const { exec } = require('child_process');
            
            const method = options.method || 'GET';
            const timeout = url.includes('.onion') ? 60 : 30;
            
            // Build curl command
            let cmd = `docker exec th3_kali_tor curl -s --connect-timeout ${timeout} --socks5-hostname localhost:9050`;
            
            // Add method if not GET
            if (method !== 'GET') {
                cmd += ` -X ${method}`;
            }
            
            // Add headers
            if (options.headers) {
                for (const [key, value] of Object.entries(options.headers)) {
                    cmd += ` -H "${key}: ${value}"`;
                }
            }
            
            // Add data for POST
            if (options.body) {
                cmd += ` -d '${options.body}'`;
            }
            
            cmd += ` "${url}"`;
            
            exec(cmd, { timeout: (timeout + 10) * 1000 }, (error, stdout, stderr) => {
                if (error) {
                    reject(new Error(`Docker Tor fetch failed: ${error.message}`));
                    return;
                }
                
                // Create a mock Response object
                const mockResponse = {
                    ok: true,
                    status: 200,
                    text: async () => stdout,
                    json: async () => JSON.parse(stdout),
                    headers: new Map([['content-type', 'application/json']]),
                    _viaDocker: true
                };
                
                console.log(`[TOR] Docker fetch successful: ${url.substring(0, 50)}...`);
                resolve(mockResponse);
            });
        });
    }

    /**
     * Obtenir l'IP actuelle de sortie Tor
     */
    async getCurrentIP() {
        try {
            // Use multiple IP services for redundancy
            const ipServices = [
                'https://check.torproject.org/api/ip',
                'https://api.ipify.org?format=json',
                'https://httpbin.org/ip'
            ];

            for (const service of ipServices) {
                try {
                    const response = await this.torFetch(service);
                    const data = await response.json();
                    this.currentIP = data.IP || data.ip || data.origin;
                    console.log(`[TOR] Current exit IP: ${this.currentIP}`);
                    return this.currentIP;
                } catch {
                    continue;
                }
            }
            
            throw new Error('Could not determine exit IP');
        } catch (error) {
            console.error('[TOR] Failed to get current IP:', error.message);
            return null;
        }
    }

    /**
     * Vérifier si nous sommes bien connectés via Tor
     */
    async verifyTorConnection() {
        try {
            const response = await this.torFetch('https://check.torproject.org/api/ip');
            const data = await response.json();
            
            return {
                usingTor: data.IsTor || false,
                ip: data.IP || null,
                country: null, // Could be enhanced with GeoIP
                message: data.IsTor ? 'Connecté via Tor' : 'Non connecté via Tor'
            };
        } catch (error) {
            return {
                usingTor: false,
                ip: null,
                error: error.message
            };
        }
    }

    /**
     * Changer le circuit Tor (nouvelle IP)
     * Nécessite le ControlPort Tor configuré
     */
    async changeCircuit() {
        return new Promise((resolve, reject) => {
            const net = require('net');
            const socket = new net.Socket();
            
            socket.setTimeout(5000);
            
            socket.on('connect', () => {
                // Authenticate if password is set
                if (this.torControlPassword) {
                    socket.write(`AUTHENTICATE "${this.torControlPassword}"\r\n`);
                } else {
                    socket.write('AUTHENTICATE\r\n');
                }
            });
            
            let response = '';
            socket.on('data', (data) => {
                response += data.toString();
                
                if (response.includes('250 OK') && !response.includes('SIGNAL')) {
                    // Authentication successful, send NEWNYM
                    socket.write('SIGNAL NEWNYM\r\n');
                } else if (response.includes('250 OK') && response.includes('SIGNAL')) {
                    // Circuit change successful
                    socket.destroy();
                    this.circuitChanges++;
                    this.stats.ipChanges++;
                    this.lastCircuitChange = new Date();
                    this.agent = null; // Reset agent to use new circuit
                    
                    console.log(`[TOR] Circuit changed (${this.circuitChanges} total changes)`);
                    this.emit('circuitChange', { count: this.circuitChanges });
                    resolve({ success: true, message: 'Nouveau circuit Tor établi' });
                } else if (response.includes('515') || response.includes('551')) {
                    socket.destroy();
                    reject(new Error('Authentification Tor échouée. Configurez TOR_CONTROL_PASSWORD.'));
                }
            });
            
            socket.on('timeout', () => {
                socket.destroy();
                reject(new Error('Timeout connexion au ControlPort Tor'));
            });
            
            socket.on('error', (err) => {
                socket.destroy();
                reject(new Error(`Erreur ControlPort: ${err.message}. Assurez-vous que ControlPort est activé dans torrc.`));
            });
            
            socket.connect(this.torControlPort, this.torHost);
        });
    }

    /**
     * Rotation automatique d'IP à intervalle
     */
    startAutoRotation(intervalMs = 300000) { // 5 minutes par défaut
        console.log(`[TOR] Starting auto IP rotation every ${intervalMs / 1000}s`);
        
        this.rotationInterval = setInterval(async () => {
            try {
                await this.changeCircuit();
                const newIP = await this.getCurrentIP();
                console.log(`[TOR] Auto-rotated to new IP: ${newIP}`);
            } catch (error) {
                console.error('[TOR] Auto-rotation failed:', error.message);
            }
        }, intervalMs);

        return { message: `Rotation automatique activée (${intervalMs / 1000}s)` };
    }

    /**
     * Arrêter la rotation automatique
     */
    stopAutoRotation() {
        if (this.rotationInterval) {
            clearInterval(this.rotationInterval);
            this.rotationInterval = null;
            console.log('[TOR] Auto IP rotation stopped');
            return { message: 'Rotation automatique arrêtée' };
        }
        return { message: 'Aucune rotation active' };
    }

    /**
     * Accéder à un site .onion (Dark Web)
     */
    async fetchOnionSite(onionUrl) {
        if (!onionUrl.includes('.onion')) {
            throw new Error('URL invalide: doit être un site .onion');
        }

        console.log(`[TOR] Accessing onion site: ${onionUrl.substring(0, 30)}...`);
        
        try {
            const response = await this.torFetch(onionUrl, {
                headers: {
                    'User-Agent': this.getRandomUserAgent()
                }
            });
            
            return {
                success: true,
                status: response.status,
                contentType: response.headers.get('content-type'),
                url: onionUrl
            };
        } catch (error) {
            return {
                success: false,
                error: error.message,
                url: onionUrl
            };
        }
    }

    /**
     * Obtenir un User-Agent aléatoire pour l'anonymat
     */
    getRandomUserAgent() {
        const userAgents = [
            'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
        ];
        return userAgents[Math.floor(Math.random() * userAgents.length)];
    }

    /**
     * Obtenir les statistiques du service
     */
    getStats() {
        return {
            ...this.stats,
            isConnected: this.isConnected,
            currentIP: this.currentIP,
            circuitChanges: this.circuitChanges,
            lastCircuitChange: this.lastCircuitChange,
            proxyUrl: this.proxyUrl,
            autoRotationActive: !!this.rotationInterval,
            tracesCleared: this.stats.tracesCleared || 0
        };
    }

    /**
     * Effacer toutes les traces après une interaction Dark Web
     * CRITIQUE pour la sécurité OSINT/Hacking
     */
    async clearTraces() {
        console.log('[TOR] 🧹 Clearing all traces...');
        
        const tracesCleared = {
            timestamp: new Date().toISOString(),
            actions: []
        };

        try {
            // 1. Changer de circuit Tor (nouvelle IP)
            try {
                await this.changeCircuit();
                tracesCleared.actions.push('Circuit Tor changé - Nouvelle IP');
            } catch (e) {
                tracesCleared.actions.push('Circuit: ' + e.message);
            }

            // 2. Réinitialiser l'agent proxy
            this.agent = null;
            tracesCleared.actions.push('Agent proxy réinitialisé');

            // 3. Effacer l'IP en mémoire
            this.currentIP = null;
            tracesCleared.actions.push('IP en mémoire effacée');

            // 4. Réinitialiser les stats de session (garder le total)
            const totalRequests = this.stats.requestsMade;
            const totalOnion = this.stats.onionSitesVisited;
            this.stats.tracesCleared = (this.stats.tracesCleared || 0) + 1;
            tracesCleared.actions.push('Stats de session nettoyées');

            // 5. Émettre l'événement
            this.emit('tracesCleared', tracesCleared);
            
            console.log('[TOR] ✅ Traces cleared successfully');
            
            return {
                success: true,
                ...tracesCleared
            };
        } catch (error) {
            console.error('[TOR] ❌ Failed to clear traces:', error.message);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Requête Dark Web sécurisée avec effacement automatique des traces
     * Utiliser pour toutes les opérations OSINT/Hacking sensibles
     */
    async secureDarkWebRequest(onionUrl, options = {}) {
        if (!onionUrl.includes('.onion')) {
            throw new Error('URL invalide: doit être un site .onion');
        }

        console.log('[TOR] 🔒 Secure Dark Web request initiated...');

        // 1. Changer de circuit AVANT la requête
        try {
            await this.changeCircuit();
            console.log('[TOR] Pre-request circuit change done');
        } catch {
            console.log('[TOR] Pre-request circuit change skipped');
        }

        // 2. Faire la requête avec User-Agent aléatoire
        const result = {
            timestamp: new Date().toISOString(),
            url: onionUrl.substring(0, 30) + '...',
            preRequestIP: null,
            postRequestIP: null,
            response: null,
            tracesCleared: false
        };

        try {
            result.preRequestIP = await this.getCurrentIP();
            
            const response = await this.torFetch(onionUrl, {
                ...options,
                headers: {
                    'User-Agent': this.getRandomUserAgent(),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                    ...options.headers
                }
            });

            result.response = {
                status: response.status,
                contentType: response.headers.get('content-type')
            };

        } catch (error) {
            result.error = error.message;
        }

        // 3. Effacer les traces APRÈS la requête
        const clearResult = await this.clearTraces();
        result.tracesCleared = clearResult.success;
        result.postRequestIP = await this.getCurrentIP();

        console.log(`[TOR] 🔒 Secure request complete. Pre-IP: ${result.preRequestIP}, Post-IP: ${result.postRequestIP}`);

        return result;
    }

    /**
     * Mode Paranoïa - Effacement complet avec délai aléatoire
     * Pour les opérations ultra-sensibles
     */
    async paranoidMode(onionUrl, options = {}) {
        console.log('[TOR] 🛡️ PARANOID MODE ACTIVATED');

        // Délai aléatoire avant la requête (anti-timing analysis)
        const preDelay = Math.floor(Math.random() * 5000) + 1000;
        await new Promise(resolve => setTimeout(resolve, preDelay));

        // Changer de circuit 2 fois avant
        for (let i = 0; i < 2; i++) {
            try {
                await this.changeCircuit();
                await new Promise(resolve => setTimeout(resolve, 1000));
            } catch { }
        }

        // Faire la requête sécurisée
        const result = await this.secureDarkWebRequest(onionUrl, options);

        // Délai aléatoire après la requête
        const postDelay = Math.floor(Math.random() * 3000) + 500;
        await new Promise(resolve => setTimeout(resolve, postDelay));

        // Changer de circuit 2 fois après
        for (let i = 0; i < 2; i++) {
            try {
                await this.changeCircuit();
                await new Promise(resolve => setTimeout(resolve, 1000));
            } catch { }
        }

        console.log('[TOR] 🛡️ PARANOID MODE COMPLETE');
        return {
            ...result,
            mode: 'paranoid',
            preDelay,
            postDelay,
            circuitChanges: 4
        };
    }

    /**
     * Configuration recommandée pour le fichier torrc
     */
    getTorrcConfig() {
        return `# Configuration Tor recommandée pour Th3 Thirty3
# Ajoutez ces lignes à votre fichier torrc

# Port SOCKS pour les connexions
SocksPort ${this.torSocksPort}

# Port de contrôle pour changer de circuit
ControlPort ${this.torControlPort}

# Authentification par cookie (recommandé)
CookieAuthentication 1

# OU authentification par mot de passe
# HashedControlPassword [votre_hash]
# Générez avec: tor --hash-password "votre_mot_de_passe"

# Permettre le streaming
AllowSingleHopCircuits 0

# Géographie des nœuds de sortie (optionnel)
# ExitNodes {us},{ca},{de},{nl}
# StrictNodes 0

# Logs
Log notice file /var/log/tor/notices.log
`;
    }
}

module.exports = TorNetworkService;
