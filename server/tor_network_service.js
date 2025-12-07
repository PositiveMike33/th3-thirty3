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
     */
    async torFetch(url, options = {}) {
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
            autoRotationActive: !!this.rotationInterval
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
