/**
 * GPU Training Service - Node.js Client
 * Connects to TensorFlow GPU training container
 * Provides GPU-accelerated training and embeddings for Th3 Thirty3
 */

const fetch = require('node-fetch');
const EventEmitter = require('events');

class GpuTrainingService extends EventEmitter {
    constructor() {
        super();
        this.gpuTrainerUrl = process.env.GPU_TRAINER_URL || 'http://localhost:5000';
        this.isConnected = false;
        this.lastHealthCheck = null;
        this.trainingJobs = new Map();

        // Start health check loop
        this.startHealthCheck();

        console.log('[GPU-TRAINING] Service initialized');
        console.log(`[GPU-TRAINING] Trainer URL: ${this.gpuTrainerUrl}`);
    }

    /**
     * Start background health check
     */
    startHealthCheck() {
        setInterval(async () => {
            try {
                await this.checkHealth();
            } catch (error) {
                console.error('[GPU-TRAINING] Health check failed:', error.message);
            }
        }, 30000);

        // Initial check
        this.checkHealth().catch(() => { });
    }

    /**
     * Check GPU trainer health
     */
    async checkHealth() {
        try {
            const response = await fetch(`${this.gpuTrainerUrl}/health`, {
                method: 'GET',
                timeout: 5000
            });

            if (response.ok) {
                this.lastHealthCheck = await response.json();
                this.isConnected = true;
                return this.lastHealthCheck;
            }

            this.isConnected = false;
            return null;
        } catch (error) {
            this.isConnected = false;
            throw error;
        }
    }

    /**
     * Get GPU information
     */
    async getGpuInfo() {
        try {
            const response = await fetch(`${this.gpuTrainerUrl}/api/gpu/info`);
            if (response.ok) {
                return await response.json();
            }
            return { available: false, error: 'Failed to get GPU info' };
        } catch (error) {
            return { available: false, error: error.message };
        }
    }

    /**
     * Start a training job
     */
    async startTraining(options = {}) {
        const {
            jobId = `job_${Date.now()}`,
            category = 'security',
            iterations = 5,
            customData = null
        } = options;

        try {
            const response = await fetch(`${this.gpuTrainerUrl}/api/train/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    job_id: jobId,
                    category,
                    iterations,
                    custom_data: customData
                })
            });

            const result = await response.json();

            if (result.success) {
                this.trainingJobs.set(jobId, {
                    ...result,
                    startedAt: new Date().toISOString()
                });
                this.emit('trainingStarted', { jobId, category, iterations });
            }

            return result;
        } catch (error) {
            console.error('[GPU-TRAINING] Start training error:', error.message);
            return { success: false, error: error.message };
        }
    }

    /**
     * Get training job status
     */
    async getTrainingStatus(jobId) {
        try {
            const response = await fetch(`${this.gpuTrainerUrl}/api/train/status/${jobId}`);
            if (response.ok) {
                return await response.json();
            }
            return null;
        } catch (error) {
            return { error: error.message };
        }
    }

    /**
     * Get all training jobs
     */
    async getAllJobs() {
        try {
            const response = await fetch(`${this.gpuTrainerUrl}/api/train/jobs`);
            if (response.ok) {
                return await response.json();
            }
            return { active: [], history: [] };
        } catch (error) {
            return { active: [], history: [], error: error.message };
        }
    }

    /**
     * Stop a training job
     */
    async stopTraining(jobId) {
        try {
            const response = await fetch(`${this.gpuTrainerUrl}/api/train/stop/${jobId}`, {
                method: 'POST'
            });

            const result = await response.json();

            if (result.success) {
                this.emit('trainingStopped', { jobId });
            }

            return result;
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * Generate GPU-accelerated embeddings
     */
    async generateEmbeddings(texts) {
        if (!Array.isArray(texts)) {
            texts = [texts];
        }

        try {
            const response = await fetch(`${this.gpuTrainerUrl}/api/embeddings`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ texts })
            });

            if (response.ok) {
                return await response.json();
            }

            return { error: 'Failed to generate embeddings' };
        } catch (error) {
            return { error: error.message };
        }
    }

    /**
     * Analyze content for vulnerabilities using GPU model
     */
    async analyzeVulnerability(content, type = 'code') {
        try {
            const response = await fetch(`${this.gpuTrainerUrl}/api/analyze/vulnerability`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content, type })
            });

            if (response.ok) {
                return await response.json();
            }

            return { error: 'Analysis failed' };
        } catch (error) {
            return { error: error.message };
        }
    }

    /**
     * Predict exploits for a vulnerability
     */
    async predictExploit(vulnerability) {
        try {
            const response = await fetch(`${this.gpuTrainerUrl}/api/predict/exploit`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ vulnerability })
            });

            if (response.ok) {
                return await response.json();
            }

            return { error: 'Prediction failed' };
        } catch (error) {
            return { error: error.message };
        }
    }

    /**
     * Train hacking expert on specific topic
     */
    async trainHackingExpert(expertId, topic, iterations = 3) {
        return this.startTraining({
            jobId: `expert_${expertId}_${Date.now()}`,
            category: topic,
            iterations,
            customData: { expertId, topic }
        });
    }

    /**
     * Get service status
     */
    getStatus() {
        return {
            connected: this.isConnected,
            gpuTrainerUrl: this.gpuTrainerUrl,
            lastHealthCheck: this.lastHealthCheck,
            activeJobs: this.trainingJobs.size
        };
    }
}

module.exports = GpuTrainingService;
