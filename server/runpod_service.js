/**
 * RunPod GPU Cloud Service
 * 
 * Provides access to powerful GPUs for LLM inference:
 * - Serverless endpoints for instant scaling
 * - Pod-based GPUs for dedicated workloads
 * - Cost-effective alternative to local GPUs
 * 
 * Pricing (as of 2024):
 * - RTX 4090: ~$0.44/hr
 * - A100 80GB: ~$1.89/hr
 * - H100: ~$3.99/hr
 * 
 * @author Th3 Thirty3
 */

const EventEmitter = require('events');

class RunPodService extends EventEmitter {
    constructor() {
        super();
        
        this.apiKey = process.env.RUNPOD_API_KEY;
        this.baseUrl = 'https://api.runpod.io/v2';
        
        // Serverless endpoints for instant inference
        this.serverlessEndpoints = {
            // Pre-configured serverless endpoints (you'll need to create these in RunPod)
            llama70b: process.env.RUNPOD_LLAMA70B_ENDPOINT,
            mistral: process.env.RUNPOD_MISTRAL_ENDPOINT,
            qwen: process.env.RUNPOD_QWEN_ENDPOINT,
            vllm: process.env.RUNPOD_VLLM_ENDPOINT  // Generic vLLM endpoint
        };
        
        // Available GPU types for pod creation
        this.availableGPUs = [
            { id: 'NVIDIA RTX 4090', vram: 24, pricePerHour: 0.44, recommended: true },
            { id: 'NVIDIA RTX A5000', vram: 24, pricePerHour: 0.32, recommended: false },
            { id: 'NVIDIA A100 80GB', vram: 80, pricePerHour: 1.89, recommended: true },
            { id: 'NVIDIA H100', vram: 80, pricePerHour: 3.99, recommended: false }
        ];
        
        // Stats tracking
        this.stats = {
            totalRequests: 0,
            successfulRequests: 0,
            failedRequests: 0,
            totalCost: 0,
            avgResponseTime: 0,
            lastUsed: null
        };
        
        // Connection state
        this.isConnected = false;
        this.activePods = [];
        
        if (this.apiKey) {
            console.log('[RUNPOD] Service initialized with API key');
            this.checkConnection();
        } else {
            console.log('[RUNPOD] Service initialized (API key not configured)');
        }
    }
    
    /**
     * Check RunPod API connection
     */
    async checkConnection() {
        if (!this.apiKey) {
            return { connected: false, error: 'API key not configured' };
        }
        
        try {
            const response = await fetch(`${this.baseUrl}/pods`, {
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.ok) {
                this.isConnected = true;
                const data = await response.json();
                this.activePods = data.pods || [];
                console.log(`[RUNPOD] Connected - ${this.activePods.length} active pods`);
                return { connected: true, pods: this.activePods.length };
            } else {
                this.isConnected = false;
                return { connected: false, error: `HTTP ${response.status}` };
            }
        } catch (error) {
            this.isConnected = false;
            console.error('[RUNPOD] Connection check failed:', error.message);
            return { connected: false, error: error.message };
        }
    }
    
    /**
     * Generate response using RunPod Serverless endpoint
     * This is the fastest method - uses pre-warmed GPUs
     */
    async generateServerlessResponse(prompt, modelId = 'llama70b', options = {}) {
        const endpointId = this.serverlessEndpoints[modelId] || this.serverlessEndpoints.vllm;
        
        if (!endpointId) {
            throw new Error(`No serverless endpoint configured for model: ${modelId}`);
        }
        
        const startTime = Date.now();
        this.stats.totalRequests++;
        
        try {
            // RunPod serverless uses async job API
            const runUrl = `${this.baseUrl}/${endpointId}/run`;
            
            const requestBody = {
                input: {
                    prompt: prompt,
                    max_tokens: options.maxTokens || 2048,
                    temperature: options.temperature || 0.7,
                    top_p: options.topP || 0.9,
                    system_prompt: options.systemPrompt || "You are a helpful AI assistant."
                }
            };
            
            // Start the job
            const runResponse = await fetch(runUrl, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(requestBody)
            });
            
            if (!runResponse.ok) {
                throw new Error(`RunPod API error: ${runResponse.status}`);
            }
            
            const runData = await runResponse.json();
            const jobId = runData.id;
            
            // Poll for completion (serverless is usually fast)
            const result = await this.pollJobStatus(endpointId, jobId, options.timeout || 60000);
            
            const responseTime = Date.now() - startTime;
            this.stats.successfulRequests++;
            this.stats.lastUsed = new Date().toISOString();
            this.updateAvgResponseTime(responseTime);
            
            this.emit('response', {
                model: modelId,
                responseTime,
                success: true,
                jobId
            });
            
            return result.output?.text || result.output || JSON.stringify(result);
            
        } catch (error) {
            this.stats.failedRequests++;
            console.error('[RUNPOD] Serverless request failed:', error.message);
            throw error;
        }
    }
    
    /**
     * Poll RunPod job status until completion or timeout
     */
    async pollJobStatus(endpointId, jobId, timeout = 60000) {
        const statusUrl = `${this.baseUrl}/${endpointId}/status/${jobId}`;
        const startTime = Date.now();
        const pollInterval = 1000; // 1 second
        
        while (Date.now() - startTime < timeout) {
            try {
                const response = await fetch(statusUrl, {
                    headers: {
                        'Authorization': `Bearer ${this.apiKey}`
                    }
                });
                
                if (!response.ok) {
                    throw new Error(`Status check failed: ${response.status}`);
                }
                
                const data = await response.json();
                
                if (data.status === 'COMPLETED') {
                    return data;
                } else if (data.status === 'FAILED') {
                    throw new Error(`Job failed: ${data.error || 'Unknown error'}`);
                }
                
                // Still in progress, wait and poll again
                await new Promise(resolve => setTimeout(resolve, pollInterval));
                
            } catch (error) {
                throw error;
            }
        }
        
        throw new Error('Job timed out');
    }
    
    /**
     * Generate response using OpenAI-compatible API (for vLLM endpoints)
     * Many RunPod templates expose an OpenAI-compatible endpoint
     */
    async generateOpenAICompatibleResponse(prompt, options = {}) {
        const endpointUrl = options.endpointUrl || process.env.RUNPOD_OPENAI_ENDPOINT;
        
        if (!endpointUrl) {
            throw new Error('No OpenAI-compatible endpoint configured');
        }
        
        const startTime = Date.now();
        this.stats.totalRequests++;
        
        try {
            const response = await fetch(`${endpointUrl}/v1/chat/completions`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model: options.model || 'default',
                    messages: [
                        { role: 'system', content: options.systemPrompt || 'You are a helpful assistant.' },
                        { role: 'user', content: prompt }
                    ],
                    max_tokens: options.maxTokens || 2048,
                    temperature: options.temperature || 0.7
                })
            });
            
            if (!response.ok) {
                const error = await response.text();
                throw new Error(`OpenAI-compatible API error: ${response.status} - ${error}`);
            }
            
            const data = await response.json();
            const responseTime = Date.now() - startTime;
            
            this.stats.successfulRequests++;
            this.stats.lastUsed = new Date().toISOString();
            this.updateAvgResponseTime(responseTime);
            
            return data.choices[0].message.content;
            
        } catch (error) {
            this.stats.failedRequests++;
            throw error;
        }
    }
    
    /**
     * List available serverless endpoints
     */
    async listServerlessEndpoints() {
        if (!this.apiKey) {
            return { success: false, error: 'API key not configured' };
        }
        
        try {
            const response = await fetch(`${this.baseUrl}/endpoints`, {
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                return { success: true, endpoints: data.endpoints || [] };
            } else {
                return { success: false, error: `HTTP ${response.status}` };
            }
        } catch (error) {
            return { success: false, error: error.message };
        }
    }
    
    /**
     * List active GPU pods
     */
    async listPods() {
        if (!this.apiKey) {
            return { success: false, error: 'API key not configured' };
        }
        
        try {
            const response = await fetch(`${this.baseUrl}/pods`, {
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                this.activePods = data.pods || [];
                return { success: true, pods: this.activePods };
            } else {
                return { success: false, error: `HTTP ${response.status}` };
            }
        } catch (error) {
            return { success: false, error: error.message };
        }
    }
    
    /**
     * Create a new GPU pod for running models
     * Note: This incurs charges!
     */
    async createPod(options = {}) {
        if (!this.apiKey) {
            throw new Error('API key not configured');
        }
        
        const podConfig = {
            cloudType: options.cloudType || 'SECURE',
            gpuTypeId: options.gpuType || 'NVIDIA RTX 4090',
            volumeInGb: options.volumeSize || 50,
            containerDiskInGb: options.containerDisk || 20,
            templateId: options.templateId || 'runpod/pytorch:2.1.0-py3.10-cuda11.8.0-devel-ubuntu22.04',
            name: options.name || `th3-thirty3-${Date.now()}`,
            startSSH: true,
            ports: '8888/http,22/tcp'
        };
        
        console.log('[RUNPOD] Creating pod:', podConfig.name);
        
        try {
            const response = await fetch(`${this.baseUrl}/pods`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(podConfig)
            });
            
            if (response.ok) {
                const data = await response.json();
                console.log('[RUNPOD] Pod created:', data.id);
                this.emit('podCreated', data);
                return { success: true, pod: data };
            } else {
                const error = await response.text();
                throw new Error(`Failed to create pod: ${error}`);
            }
        } catch (error) {
            console.error('[RUNPOD] Pod creation failed:', error.message);
            throw error;
        }
    }
    
    /**
     * Stop a running pod
     */
    async stopPod(podId) {
        if (!this.apiKey) {
            throw new Error('API key not configured');
        }
        
        try {
            const response = await fetch(`${this.baseUrl}/pods/${podId}/stop`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`
                }
            });
            
            if (response.ok) {
                console.log(`[RUNPOD] Pod ${podId} stopped`);
                this.emit('podStopped', podId);
                return { success: true };
            } else {
                throw new Error(`Failed to stop pod: ${response.status}`);
            }
        } catch (error) {
            console.error('[RUNPOD] Failed to stop pod:', error.message);
            throw error;
        }
    }
    
    /**
     * Terminate and delete a pod
     */
    async terminatePod(podId) {
        if (!this.apiKey) {
            throw new Error('API key not configured');
        }
        
        try {
            const response = await fetch(`${this.baseUrl}/pods/${podId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`
                }
            });
            
            if (response.ok) {
                console.log(`[RUNPOD] Pod ${podId} terminated`);
                this.emit('podTerminated', podId);
                return { success: true };
            } else {
                throw new Error(`Failed to terminate pod: ${response.status}`);
            }
        } catch (error) {
            console.error('[RUNPOD] Failed to terminate pod:', error.message);
            throw error;
        }
    }
    
    /**
     * Update average response time
     */
    updateAvgResponseTime(newTime) {
        const total = this.stats.successfulRequests;
        if (total === 1) {
            this.stats.avgResponseTime = newTime;
        } else {
            // Rolling average
            this.stats.avgResponseTime = 
                ((this.stats.avgResponseTime * (total - 1)) + newTime) / total;
        }
    }
    
    /**
     * Get service status
     */
    getStatus() {
        return {
            configured: !!this.apiKey,
            connected: this.isConnected,
            activePods: this.activePods.length,
            serverlessEndpoints: Object.entries(this.serverlessEndpoints)
                .filter(([_, v]) => v)
                .map(([k, _]) => k),
            availableGPUs: this.availableGPUs.filter(g => g.recommended),
            stats: this.stats
        };
    }
    
    /**
     * Get pricing information
     */
    getPricing() {
        return {
            serverless: {
                description: 'Pay per second of GPU usage, no idle costs',
                estimatedCost: '$0.0001-0.0005 per request (depending on model size)'
            },
            pods: this.availableGPUs.map(gpu => ({
                gpu: gpu.id,
                vram: `${gpu.vram}GB`,
                pricePerHour: `$${gpu.pricePerHour.toFixed(2)}`,
                recommended: gpu.recommended
            }))
        };
    }
}

// Singleton instance
const runpodService = new RunPodService();

module.exports = runpodService;
