/**
 * Docker Management Routes
 * API endpoints for Docker container control
 */

const express = require('express');
const router = express.Router();
const dockerAutoStart = require('./docker_autostart_service');

/**
 * GET /api/docker/status
 * Get status of all managed containers
 */
router.get('/status', async (req, res) => {
    try {
        const status = dockerAutoStart.getStatus();
        
        // Get live status for each container
        for (const name of Object.keys(dockerAutoStart.containers)) {
            const containerStatus = await dockerAutoStart.getContainerStatus(name);
            status.containersStatus[name] = {
                ...status.containersStatus[name],
                ...containerStatus
            };
        }
        
        res.json({
            success: true,
            ...status
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/docker/start-all
 * Start all managed containers
 */
router.post('/start-all', async (req, res) => {
    try {
        console.log('[DOCKER API] Starting all containers...');
        const result = await dockerAutoStart.startAllContainers();
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/docker/stop-all
 * Stop all managed containers
 */
router.post('/stop-all', async (req, res) => {
    try {
        console.log('[DOCKER API] Stopping all containers...');
        await dockerAutoStart.stopAllContainers();
        res.json({ success: true, message: 'All containers stopped' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/docker/start/:container
 * Start a specific container
 */
router.post('/start/:container', async (req, res) => {
    try {
        const { container } = req.params;
        console.log(`[DOCKER API] Starting container: ${container}`);
        
        const started = await dockerAutoStart.startContainer(container);
        
        if (started) {
            res.json({ success: true, message: `Container ${container} started` });
        } else {
            res.status(400).json({ success: false, error: `Failed to start ${container}` });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/docker/stop/:container
 * Stop a specific container
 */
router.post('/stop/:container', async (req, res) => {
    try {
        const { container } = req.params;
        console.log(`[DOCKER API] Stopping container: ${container}`);
        
        const stopped = await dockerAutoStart.stopContainer(container);
        
        if (stopped) {
            res.json({ success: true, message: `Container ${container} stopped` });
        } else {
            res.status(400).json({ success: false, error: `Failed to stop ${container}` });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/docker/health/:container
 * Get health status of a specific container
 */
router.get('/health/:container', async (req, res) => {
    try {
        const { container } = req.params;
        const config = dockerAutoStart.containers[container];
        
        if (!config) {
            return res.status(404).json({ success: false, error: 'Container not managed' });
        }
        
        const containerStatus = await dockerAutoStart.getContainerStatus(container);
        
        let health = { healthy: false };
        if (containerStatus.status === 'running' && config.healthCheck) {
            health = await config.healthCheck();
        }
        
        res.json({
            success: true,
            container,
            status: containerStatus.status,
            health
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/docker/cleanup
 * Clean up stale containers
 */
router.post('/cleanup', async (req, res) => {
    try {
        const cleaned = await dockerAutoStart.cleanupStaleContainers();
        res.json({ success: cleaned, message: 'Cleanup complete' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/docker/is-running
 * Check if Docker Desktop is running
 */
router.get('/is-running', async (req, res) => {
    try {
        const running = await dockerAutoStart.isDockerRunning();
        res.json({ success: true, dockerRunning: running });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;
