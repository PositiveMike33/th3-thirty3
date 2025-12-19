/**
 * Offline Mode Service - Détection réseau et optimisation énergétique
 * Bascule automatiquement vers les agents locaux quand internet est perdu
 */

const dns = require('dns').promises;
const EventEmitter = require('events');

class OfflineModeService extends EventEmitter {
    constructor(io = null) {
        super();
        this.io = io;
        this.isOnline = true;
        this.checkInterval = null;
        this.lastCheck = Date.now();
        
        // Configuration
        this.config = {
            checkIntervalMs: 10000,          // Vérifier toutes les 10 secondes
            offlineModel: 'granite3.1-moe:1b', // Modèle ultra-léger offline (801M)
            onlineModel: 'granite3.1-moe:1b',         // Modèle normal online
            testHosts: ['8.8.8.8', '1.1.1.1', 'google.com'],
            energyMode: 'normal'              // 'normal', 'eco', 'ultra-eco'
        };

        // Services désactivables en mode offline
        this.cloudServices = {
            anythingLLM: true,
            gemini: true,
            groq: true,
            pieces: true,
            webSearch: true
        };

        // Stats
        this.stats = {
            offlineEvents: 0,
            onlineEvents: 0,
            totalOfflineTime: 0,
            lastOfflineStart: null,
            energySaved: 0
        };

        console.log('[OFFLINE-MODE] Service initialized');
        this.startMonitoring();
    }

    /**
     * Démarrer la surveillance réseau
     */
    startMonitoring() {
        this.checkInterval = setInterval(() => this.checkConnection(), this.config.checkIntervalMs);
        this.checkConnection(); // Check immédiat
        console.log('[OFFLINE-MODE] Network monitoring started');
    }

    /**
     * Arrêter la surveillance
     */
    stopMonitoring() {
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
            this.checkInterval = null;
        }
    }

    /**
     * Vérifier la connexion internet
     */
    async checkConnection() {
        const wasOnline = this.isOnline;
        let connectionOk = false;

        for (const host of this.config.testHosts) {
            try {
                await dns.lookup(host);
                connectionOk = true;
                break;
            } catch (error) {
                // Continuer avec le prochain host
            }
        }

        // Alternative: ping HTTP
        if (!connectionOk) {
            try {
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 3000);
                
                await fetch('https://www.google.com/generate_204', {
                    method: 'HEAD',
                    signal: controller.signal
                });
                clearTimeout(timeout);
                connectionOk = true;
            } catch (error) {
                // Pas de connexion
            }
        }

        this.isOnline = connectionOk;
        this.lastCheck = Date.now();

        // Détecter changement d'état
        if (wasOnline && !this.isOnline) {
            this.handleOffline();
        } else if (!wasOnline && this.isOnline) {
            this.handleOnline();
        }

        return this.isOnline;
    }

    /**
     * Gérer la perte de connexion
     */
    handleOffline() {
        console.log('[OFFLINE-MODE] 🔴 Internet connection LOST - Switching to OFFLINE mode');
        
        this.stats.offlineEvents++;
        this.stats.lastOfflineStart = Date.now();
        
        // Désactiver services cloud
        Object.keys(this.cloudServices).forEach(service => {
            this.cloudServices[service] = false;
        });

        // Passer en mode éco
        this.setEnergyMode('eco');

        // Émettre événement
        this.emit('offline', {
            timestamp: new Date().toISOString(),
            model: this.config.offlineModel,
            energyMode: this.config.energyMode
        });

        // Notifier via Socket.io
        if (this.io) {
            this.io.emit('system:offline', {
                message: '🔴 Mode OFFLINE activé - Agents locaux optimisés',
                model: this.config.offlineModel,
                energyMode: this.config.energyMode
            });
        }
    }

    /**
     * Gérer la reprise de connexion
     */
    handleOnline() {
        console.log('[OFFLINE-MODE] 🟢 Internet connection RESTORED - Switching to ONLINE mode');
        
        this.stats.onlineEvents++;
        
        // Calculer temps offline
        if (this.stats.lastOfflineStart) {
            this.stats.totalOfflineTime += Date.now() - this.stats.lastOfflineStart;
            this.stats.lastOfflineStart = null;
        }

        // Réactiver services cloud
        Object.keys(this.cloudServices).forEach(service => {
            this.cloudServices[service] = true;
        });

        // Retour mode normal
        this.setEnergyMode('normal');

        // Émettre événement
        this.emit('online', {
            timestamp: new Date().toISOString(),
            model: this.config.onlineModel,
            energyMode: this.config.energyMode
        });

        // Notifier via Socket.io
        if (this.io) {
            this.io.emit('system:online', {
                message: '🟢 Mode ONLINE restauré - Services cloud actifs',
                model: this.config.onlineModel,
                energyMode: this.config.energyMode
            });
        }
    }

    /**
     * Définir le mode énergétique
     */
    setEnergyMode(mode) {
        this.config.energyMode = mode;
        
        const modeConfigs = {
            normal: {
                checkIntervalMs: 10000,
                model: this.config.onlineModel,
                maxTokens: 2000,
                temperature: 0.7
            },
            eco: {
                checkIntervalMs: 30000,  // Moins de checks
                model: this.config.offlineModel,
                maxTokens: 1000,
                temperature: 0.4
            },
            'ultra-eco': {
                checkIntervalMs: 60000,  // Encore moins de checks
                model: this.config.offlineModel,
                maxTokens: 500,
                temperature: 0.3
            }
        };

        const cfg = modeConfigs[mode] || modeConfigs.normal;
        
        // Appliquer la config
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
            this.checkInterval = setInterval(() => this.checkConnection(), cfg.checkIntervalMs);
        }

        console.log(`[OFFLINE-MODE] Energy mode: ${mode.toUpperCase()}`);
        this.emit('energyModeChanged', { mode, config: cfg });

        return cfg;
    }

    /**
     * Obtenir le modèle approprié selon l'état
     */
    getOptimalModel() {
        if (!this.isOnline) {
            return this.config.offlineModel;
        }
        return this.config.onlineModel;
    }

    /**
     * Obtenir les options optimisées pour Ollama
     */
    getOptimizedOptions() {
        const modeOptions = {
            normal: {
                num_predict: 2000,
                temperature: 0.7,
                top_k: 40,
                top_p: 0.9
            },
            eco: {
                num_predict: 1000,
                temperature: 0.4,
                top_k: 20,
                top_p: 0.7
            },
            'ultra-eco': {
                num_predict: 500,
                temperature: 0.3,
                top_k: 10,
                top_p: 0.5
            }
        };

        return modeOptions[this.config.energyMode] || modeOptions.normal;
    }

    /**
     * Vérifier si un service cloud est disponible
     */
    isServiceAvailable(serviceName) {
        if (!this.isOnline) return false;
        return this.cloudServices[serviceName] !== false;
    }

    /**
     * Obtenir l'état complet
     */
    getStatus() {
        return {
            isOnline: this.isOnline,
            energyMode: this.config.energyMode,
            currentModel: this.getOptimalModel(),
            lastCheck: new Date(this.lastCheck).toISOString(),
            cloudServices: this.cloudServices,
            stats: {
                ...this.stats,
                currentOfflineTime: this.stats.lastOfflineStart 
                    ? Date.now() - this.stats.lastOfflineStart 
                    : 0,
                totalOfflineTimeFormatted: this.formatDuration(this.stats.totalOfflineTime)
            }
        };
    }

    /**
     * Formater durée en texte lisible
     */
    formatDuration(ms) {
        const seconds = Math.floor(ms / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        
        if (hours > 0) return `${hours}h ${minutes % 60}m`;
        if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
        return `${seconds}s`;
    }

    /**
     * Forcer un mode (test)
     */
    forceMode(online) {
        if (online && !this.isOnline) {
            this.isOnline = true;
            this.handleOnline();
        } else if (!online && this.isOnline) {
            this.isOnline = false;
            this.handleOffline();
        }
    }
}

module.exports = OfflineModeService;
