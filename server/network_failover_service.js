/**
 * Network Monitor Service - Cloud Only
 * Monitors internet connectivity and ensures Cloud Models are reachable.
 * Replaces the deprecated Network Failover Service.
 */

const EventEmitter = require('events');

// Endpoints to check for connectivity (must be reachable and fast)
const CONNECTIVITY_ENDPOINTS = [
    { url: 'https://api.groq.com/healthz', name: 'Groq', timeout: 3000 },
    { url: 'https://api.openai.com/v1/models', name: 'OpenAI', timeout: 3000 },
    { url: 'https://www.google.com/generate_204', name: 'Google', timeout: 2000 },
    { url: 'https://cloudflare.com/cdn-cgi/trace', name: 'Cloudflare', timeout: 2000 }
];

// Cloud-Only Mode: No local Ollama endpoint needed
const OLLAMA_ENDPOINT = null;

// Network states
const NetworkState = {
    ONLINE: 'ONLINE',           // Internet available, cloud models active
    OFFLINE: 'OFFLINE',         // Internet down
    CHECKING: 'CHECKING',       // Currently checking connectivity
    UNKNOWN: 'UNKNOWN'          // Initial state
};

// Failover modes - Simplified for Cloud Only
const FailoverMode = {
    AUTO: 'AUTO',               // Automatic switching (Monitor only)
    CLOUD_ONLY: 'CLOUD_ONLY',   // Strict Cloud Mode
    MANUAL: 'MANUAL'            // User-controlled
};

class NetworkFailoverService extends EventEmitter {
    constructor() {
        super();

        this.state = NetworkState.UNKNOWN;
        this.previousState = NetworkState.UNKNOWN;
        this.mode = FailoverMode.CLOUD_ONLY;
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

        console.log('[NETWORK_MONITOR] Service initialized (Cloud-Only)');
    }

    /**
     * Start monitoring network connectivity
     */
    start() {
        if (this.checkInterval) {
            console.log('[NETWORK_MONITOR] Already running');
            return;
        }

        console.log('[NETWORK_MONITOR] Starting connectivity monitoring...');

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
            console.log('[NETWORK_MONITOR] Monitoring stopped');
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

            // Cloud Only Mode - Ollama is irrelevant/unavailable
            const ollamaResult = { available: false };

            const latency = Date.now() - startTime;
            this.updateLatencyStats(latency);

            // Determine new state
            const wasOnline = this.isOnline;

            this.isOnline = internetResults.online;
            this.isOllamaAvailable = false; // Cloud Only Mode

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
            this.updateNetworkState(wasOnline);

            // Emit status update
            this.emit('statusUpdate', this.getStatus());

        } catch (error) {
            console.error('[NETWORK_MONITOR] Check error:', error.message);
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
     * Check local Ollama availability (Disabled for Cloud Only)
     */
    async checkOllamaAvailability() {
        return { available: false, error: 'Cloud Only Mode' };
    }

    /**
     * Update network state based on thresholds
     */
    updateNetworkState(wasOnline) {
        this.previousState = this.state;

        // Cloud Only Logic
        if (this.isOnline) {
            if (this.consecutiveSuccesses >= this.onlineThreshold || this.state === NetworkState.ONLINE) {
                this.state = NetworkState.ONLINE;

                if (!wasOnline && this.previousState === NetworkState.OFFLINE) {
                    this.lastOnline = new Date();
                    this.stats.recoveries++;
                    console.log('[NETWORK_MONITOR] 🟢 CONNECTED: Cloud services reachable');
                    this.emit('recovery', { timestamp: this.lastOnline });
                }
            }
        } else {
            if (this.consecutiveFailures >= this.offlineThreshold || this.state === NetworkState.OFFLINE) {
                this.state = NetworkState.OFFLINE;

                if (wasOnline && this.previousState === NetworkState.ONLINE) {
                    this.lastOffline = new Date();
                    this.stats.failovers++; // Count outage as failover stat for consistency
                    console.log('[NETWORK_MONITOR] 🔴 DISCONNECTED: Cloud services unreachable');
                    this.emit('failover', { timestamp: this.lastOffline });
                }
            }
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
        if (this.state === NetworkState.ONLINE) {
            return {
                provider: 'cloud',
                reason: 'Online (Cloud Mode)',
                preferredCloud: 'gemini'
            };
        } else {
            return {
                provider: 'none',
                reason: 'Offline - Check internet connection'
            };
        }
    }

    /**
     * Set failover mode (No-op in Cloud Only, or limited)
     */
    setMode(mode) {
        if (Object.values(FailoverMode).includes(mode)) {
            this.mode = mode;
            console.log(`[NETWORK_MONITOR] Mode changed to: ${mode}`);
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
        // Always return Cloud Models
        const cloudModels = {
            code: { model: 'gemini-3-pro-preview', provider: 'gemini' },
            general: { model: 'gemini-3-pro-preview', provider: 'gemini' },
            fast: { model: 'gemini-3-flash-preview', provider: 'gemini' },
            embedding: { model: 'text-embedding-3-small', provider: 'openai' }
        };
        const selected = cloudModels[domain] || cloudModels.general;
        return {
            model: selected.model,
            provider: selected.provider,
            isLocal: false,
            reason: 'Cloud Only Mode'
        };
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
