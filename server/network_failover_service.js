/**
 * Network Failover Service - RISK-006 Mitigation
 * Monitors internet connectivity and automatically switches between cloud and local models
 * 
 * Features:
 * - Real-time connectivity monitoring with multiple endpoint checks
 * - Automatic failover from cloud to local models when internet is down
 * - Automatic recovery when internet is restored
 * - Event-based notifications for UI updates
 * - Configurable check intervals and timeout thresholds
 * 
 * Architecture:
 * - Primary: Cloud models (Groq, OpenAI, Gemini, Anthropic)
 * - Fallback: Local Ollama models (uandinotai/dolphin-uncensored:latest, uandinotai/dolphin-uncensored:latest)
 * - Emergency: Cached responses / offline mode
 */

const EventEmitter = require('events');

// Endpoints to check for connectivity (must be reachable and fast)
const CONNECTIVITY_ENDPOINTS = [
    { url: 'https://api.groq.com/healthz', name: 'Groq', timeout: 3000 },
    { url: 'https://api.openai.com/v1/models', name: 'OpenAI', timeout: 3000 },
    { url: 'https://www.google.com/generate_204', name: 'Google', timeout: 2000 },
    { url: 'https://cloudflare.com/cdn-cgi/trace', name: 'Cloudflare', timeout: 2000 }
];

// Local Ollama endpoint
const OLLAMA_ENDPOINT = 'http://localhost:11434/api/tags';

// Network states
const NetworkState = {
    ONLINE: 'ONLINE',           // Internet available, cloud models active
    OFFLINE: 'OFFLINE',         // Internet down, local models active
    DEGRADED: 'DEGRADED',       // Partial connectivity, hybrid mode
    CHECKING: 'CHECKING',       // Currently checking connectivity
    UNKNOWN: 'UNKNOWN'          // Initial state
};

// Failover modes
const FailoverMode = {
    AUTO: 'AUTO',               // Automatic switching (recommended)
    CLOUD_ONLY: 'CLOUD_ONLY',   // Never failover to local (will fail if offline)
    LOCAL_ONLY: 'LOCAL_ONLY',   // Always use local (no cloud dependency)
    MANUAL: 'MANUAL'            // User-controlled switching
};

class NetworkFailoverService extends EventEmitter {
    constructor() {
        super();
        
        this.state = NetworkState.UNKNOWN;
        this.previousState = NetworkState.UNKNOWN;
        this.mode = FailoverMode.AUTO;
        this.isOnline = false;
        this.isOllamaAvailable = false;
        
        // Configuration
        this.checkIntervalMs = 10000;        // Check every 10 seconds
        this.offlineThreshold = 3;           // Require 3 failed checks to go offline
        this.onlineThreshold = 2;            // Require 2 successful checks to go online
        
        // Tracking
        this.consecutiveFailures = 0;
        this.consecutiveSuccesses = 0;
        this.lastCheck = null;
        this.lastOnline = null;
        this.lastOffline = null;
        this.checkInterval = null;
        
        // Statistics
        this.stats = {
            totalChecks: 0,
            onlineChecks: 0,
            offlineChecks: 0,
            failovers: 0,
            recoveries: 0,
            averageLatency: 0,
            lastLatencies: []
        };
        
        // Endpoint status cache
        this.endpointStatus = {};
        
        console.log('[NETWORK_FAILOVER] Service initialized');
    }

    /**
     * Start monitoring network connectivity
     */
    start() {
        if (this.checkInterval) {
            console.log('[NETWORK_FAILOVER] Already running');
            return;
        }
        
        console.log('[NETWORK_FAILOVER] Starting connectivity monitoring...');
        console.log(`[NETWORK_FAILOVER] Mode: ${this.mode}, Interval: ${this.checkIntervalMs}ms`);
        
        // Initial check
        this.performConnectivityCheck();
        
        // Start periodic checks
        this.checkInterval = setInterval(() => {
            this.performConnectivityCheck();
        }, this.checkIntervalMs);
        
        this.emit('started');
    }

    /**
     * Stop monitoring
     */
    stop() {
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
            this.checkInterval = null;
            console.log('[NETWORK_FAILOVER] Monitoring stopped');
            this.emit('stopped');
        }
    }

    /**
     * Perform a comprehensive connectivity check
     */
    async performConnectivityCheck() {
        this.state = NetworkState.CHECKING;
        this.lastCheck = new Date();
        this.stats.totalChecks++;
        
        const startTime = Date.now();
        
        try {
            // Check internet connectivity (at least 1 endpoint must respond)
            const internetResults = await this.checkInternetConnectivity();
            
            // Check local Ollama availability
            const ollamaResult = await this.checkOllamaAvailability();
            
            const latency = Date.now() - startTime;
            this.updateLatencyStats(latency);
            
            // Determine new state
            const wasOnline = this.isOnline;
            const wasOllamaAvailable = this.isOllamaAvailable;
            
            this.isOnline = internetResults.online;
            this.isOllamaAvailable = ollamaResult.available;
            
            // Update consecutive counters
            if (this.isOnline) {
                this.consecutiveSuccesses++;
                this.consecutiveFailures = 0;
                this.stats.onlineChecks++;
            } else {
                this.consecutiveFailures++;
                this.consecutiveSuccesses = 0;
                this.stats.offlineChecks++;
            }
            
            // Determine actual state based on thresholds
            this.updateNetworkState(wasOnline, wasOllamaAvailable);
            
            // Emit status update
            this.emit('statusUpdate', this.getStatus());
            
        } catch (error) {
            console.error('[NETWORK_FAILOVER] Check error:', error.message);
            this.consecutiveFailures++;
            this.emit('error', error);
        }
    }

    /**
     * Check internet connectivity through multiple endpoints
     */
    async checkInternetConnectivity() {
        const results = await Promise.allSettled(
            CONNECTIVITY_ENDPOINTS.map(endpoint => this.checkEndpoint(endpoint))
        );
        
        let successCount = 0;
        let totalLatency = 0;
        
        results.forEach((result, index) => {
            const endpoint = CONNECTIVITY_ENDPOINTS[index];
            
            if (result.status === 'fulfilled' && result.value.success) {
                this.endpointStatus[endpoint.name] = {
                    available: true,
                    latency: result.value.latency,
                    lastCheck: new Date()
                };
                successCount++;
                totalLatency += result.value.latency;
            } else {
                this.endpointStatus[endpoint.name] = {
                    available: false,
                    error: result.reason?.message || 'Failed',
                    lastCheck: new Date()
                };
            }
        });
        
        return {
            online: successCount >= 1, // At least 1 endpoint must respond
            successCount,
            totalEndpoints: CONNECTIVITY_ENDPOINTS.length,
            averageLatency: successCount > 0 ? totalLatency / successCount : 0
        };
    }

    /**
     * Check a single endpoint
     */
    async checkEndpoint(endpoint) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), endpoint.timeout);
        
        const startTime = Date.now();
        
        try {
            const response = await fetch(endpoint.url, {
                method: 'HEAD',
                signal: controller.signal,
                headers: {
                    'User-Agent': 'Th3Thirty3-NetworkMonitor/1.0'
                }
            });
            
            clearTimeout(timeoutId);
            
            return {
                success: response.status < 500, // Accept any non-server-error response
                latency: Date.now() - startTime,
                status: response.status
            };
        } catch (error) {
            clearTimeout(timeoutId);
            throw error;
        }
    }

    /**
     * Check local Ollama availability
     */
    async checkOllamaAvailability() {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 2000);
            
            const startTime = Date.now();
            const response = await fetch(OLLAMA_ENDPOINT, {
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            if (response.ok) {
                const data = await response.json();
                return {
                    available: true,
                    modelsCount: data.models?.length || 0,
                    latency: Date.now() - startTime
                };
            }
            
            return { available: false, error: 'Bad response' };
        } catch (error) {
            return { available: false, error: error.message };
        }
    }

    /**
     * Update network state based on thresholds
     */
    updateNetworkState(wasOnline, wasOllamaAvailable) {
        this.previousState = this.state;
        
        // Determine new state
        if (this.isOnline && this.isOllamaAvailable) {
            if (this.consecutiveSuccesses >= this.onlineThreshold || this.state === NetworkState.ONLINE) {
                this.state = NetworkState.ONLINE;
                
                // Recovery event
                if (!wasOnline && this.previousState === NetworkState.OFFLINE) {
                    this.lastOnline = new Date();
                    this.stats.recoveries++;
                    console.log('[NETWORK_FAILOVER] 🟢 RECOVERY: Internet restored, switching to cloud models');
                    this.emit('recovery', { timestamp: this.lastOnline });
                }
            }
        } else if (!this.isOnline && this.isOllamaAvailable) {
            if (this.consecutiveFailures >= this.offlineThreshold || this.state === NetworkState.OFFLINE) {
                this.state = NetworkState.OFFLINE;
                
                // Failover event
                if (wasOnline && this.previousState === NetworkState.ONLINE) {
                    this.lastOffline = new Date();
                    this.stats.failovers++;
                    console.log('[NETWORK_FAILOVER] 🔴 FAILOVER: Internet down, switching to local models');
                    this.emit('failover', { timestamp: this.lastOffline });
                }
            }
        } else if (this.isOnline && !this.isOllamaAvailable) {
            this.state = NetworkState.DEGRADED;
            console.log('[NETWORK_FAILOVER] 🟡 DEGRADED: Online but Ollama unavailable');
        } else {
            // Both offline - critical state
            this.state = NetworkState.OFFLINE;
            console.log('[NETWORK_FAILOVER] ⚠️ CRITICAL: No connectivity, no local models');
        }
    }

    /**
     * Update latency statistics
     */
    updateLatencyStats(latency) {
        this.stats.lastLatencies.push(latency);
        if (this.stats.lastLatencies.length > 100) {
            this.stats.lastLatencies.shift();
        }
        this.stats.averageLatency = 
            this.stats.lastLatencies.reduce((a, b) => a + b, 0) / this.stats.lastLatencies.length;
    }

    /**
     * Get the optimal provider based on current state and mode
     */
    getOptimalProvider() {
        switch (this.mode) {
            case FailoverMode.CLOUD_ONLY:
                return { provider: 'cloud', reason: 'Cloud only mode' };
                
            case FailoverMode.LOCAL_ONLY:
                return { 
                    provider: 'local', 
                    reason: 'Local only mode',
                    model: 'uandinotai/dolphin-uncensored:latest'
                };
                
            case FailoverMode.MANUAL:
                // Return current preference (set externally)
                return { 
                    provider: this.isOnline ? 'cloud' : 'local',
                    reason: 'Manual mode'
                };
                
            case FailoverMode.AUTO:
            default:
                if (this.state === NetworkState.ONLINE) {
                    return { 
                        provider: 'cloud', 
                        reason: 'Internet available',
                        preferredCloud: 'groq' // Fastest cloud provider
                    };
                } else if (this.state === NetworkState.OFFLINE) {
                    return { 
                        provider: 'local', 
                        reason: 'Internet offline - failover active',
                        model: 'uandinotai/dolphin-uncensored:latest',
                        fallbackModel: 'uandinotai/dolphin-uncensored:latest'
                    };
                } else if (this.state === NetworkState.DEGRADED) {
                    return { 
                        provider: 'cloud', 
                        reason: 'Degraded connectivity',
                        useRetry: true
                    };
                } else {
                    return { 
                        provider: 'local', 
                        reason: 'Unknown state - defaulting to local',
                        model: 'uandinotai/dolphin-uncensored:latest'
                    };
                }
        }
    }

    /**
     * Set failover mode
     */
    setMode(mode) {
        if (Object.values(FailoverMode).includes(mode)) {
            this.mode = mode;
            console.log(`[NETWORK_FAILOVER] Mode changed to: ${mode}`);
            this.emit('modeChanged', mode);
        }
    }

    /**
     * Force a specific state (for testing or manual control)
     */
    forceState(state) {
        if (Object.values(NetworkState).includes(state)) {
            this.previousState = this.state;
            this.state = state;
            
            if (state === NetworkState.OFFLINE) {
                this.isOnline = false;
                this.emit('failover', { forced: true, timestamp: new Date() });
            } else if (state === NetworkState.ONLINE) {
                this.isOnline = true;
                this.emit('recovery', { forced: true, timestamp: new Date() });
            }
            
            this.emit('statusUpdate', this.getStatus());
        }
    }

    /**
     * Get current status
     */
    getStatus() {
        return {
            state: this.state,
            mode: this.mode,
            isOnline: this.isOnline,
            isOllamaAvailable: this.isOllamaAvailable,
            lastCheck: this.lastCheck,
            lastOnline: this.lastOnline,
            lastOffline: this.lastOffline,
            consecutiveFailures: this.consecutiveFailures,
            consecutiveSuccesses: this.consecutiveSuccesses,
            optimalProvider: this.getOptimalProvider(),
            endpoints: this.endpointStatus,
            stats: {
                ...this.stats,
                uptime: this.calculateUptime()
            }
        };
    }

    /**
     * Calculate uptime percentage
     */
    calculateUptime() {
        if (this.stats.totalChecks === 0) return 100;
        return Math.round((this.stats.onlineChecks / this.stats.totalChecks) * 100);
    }

    /**
     * Get recommended model based on network state
     */
    getRecommendedModel(domain = 'general') {
        const provider = this.getOptimalProvider();
        
        if (provider.provider === 'local') {
            // Local model recommendations
            const localModels = {
                code: 'uandinotai/dolphin-uncensored:latest',
                general: 'uandinotai/dolphin-uncensored:latest',
                fast: 'uandinotai/dolphin-uncensored:latest',
                embedding: 'nomic-embed-text:latest'
            };
            return {
                model: localModels[domain] || localModels.general,
                provider: 'ollama',
                isLocal: true,
                reason: provider.reason
            };
        } else {
            // Cloud model recommendations (prefer Groq for speed)
            const cloudModels = {
                code: { model: 'llama-3.1-8b-instant', provider: 'groq' },
                general: { model: 'llama-3.3-70b-versatile', provider: 'groq' },
                fast: { model: 'llama-3.1-8b-instant', provider: 'groq' },
                embedding: { model: 'text-embedding-3-small', provider: 'openai' }
            };
            const selected = cloudModels[domain] || cloudModels.general;
            return {
                model: selected.model,
                provider: selected.provider,
                isLocal: false,
                reason: provider.reason
            };
        }
    }
}

// Singleton instance
const networkFailoverService = new NetworkFailoverService();

// Export states and modes for external use
module.exports = {
    networkFailoverService,
    NetworkState,
    FailoverMode
};
