/**
 * Docker Container Routes pour Th3 Thirty3
 * API pour gérer les conteneurs et exécuter des outils de sécurité
 */

const express = require('express');
const router = express.Router();
const dockerService = require('./docker_container_service');
const torService = require('./tor_network_service');

// Instancier Tor Service
const TorNetworkService = torService;
const torInstance = new TorNetworkService();

/**
 * GET /api/docker/status
 * Statut de Docker et des conteneurs
 */
router.get('/status', async (req, res) => {
    try {
        const dockerAvailable = await dockerService.checkDockerAvailable();
        const containers = await dockerService.getAllContainersStatus();
        const running = await dockerService.listRunningContainers();

        res.json({
            docker: dockerAvailable,
            containers,
            runningList: running
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/docker/container/:name/start
 * Démarrer un conteneur
 */
router.post('/container/:name/start', async (req, res) => {
    try {
        const result = await dockerService.startContainer(req.params.name);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/docker/container/:name/stop
 * Arrêter un conteneur
 */
router.post('/container/:name/stop', async (req, res) => {
    try {
        const result = await dockerService.stopContainer(req.params.name);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/docker/container/:name/logs
 * Logs d'un conteneur
 */
router.get('/container/:name/logs', async (req, res) => {
    try {
        const lines = parseInt(req.query.lines) || 50;
        const result = await dockerService.getContainerLogs(req.params.name, lines);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/docker/stack/start
 * Démarrer tout le stack Docker
 */
router.post('/stack/start', async (req, res) => {
    try {
        const result = await dockerService.startStack();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/docker/stack/stop
 * Arrêter tout le stack
 */
router.post('/stack/stop', async (req, res) => {
    try {
        const result = await dockerService.stopStack();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== KALI TOOLS ====================

/**
 * POST /api/docker/kali/exec
 * Exécuter une commande dans Kali
 */
router.post('/kali/exec', async (req, res) => {
    try {
        const { command, timeout } = req.body;
        if (!command) {
            return res.status(400).json({ error: 'Command required' });
        }
        const result = await dockerService.execInKali(command, timeout || 60000);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/docker/kali/nmap
 * Scan Nmap
 */
router.post('/kali/nmap', async (req, res) => {
    try {
        const { target, flags } = req.body;
        if (!target) {
            return res.status(400).json({ error: 'Target required' });
        }
        const result = await dockerService.nmapScan(target, { flags });
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/docker/kali/gobuster
 * Gobuster directory scan
 */
router.post('/kali/gobuster', async (req, res) => {
    try {
        const { url, wordlist } = req.body;
        if (!url) {
            return res.status(400).json({ error: 'URL required' });
        }
        const result = await dockerService.gobusterScan(url, wordlist);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/docker/kali/nikto
 * Nikto web scanner
 */
router.post('/kali/nikto', async (req, res) => {
    try {
        const { target } = req.body;
        if (!target) {
            return res.status(400).json({ error: 'Target required' });
        }
        const result = await dockerService.niktoScan(target);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/docker/kali/sqlmap
 * SQLMap injection testing
 */
router.post('/kali/sqlmap', async (req, res) => {
    try {
        const { url, level, risk } = req.body;
        if (!url) {
            return res.status(400).json({ error: 'URL required' });
        }
        const result = await dockerService.sqlmapScan(url, { level, risk });
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== OSINT TOOLS ====================

/**
 * POST /api/docker/osint/sherlock
 * Sherlock username search
 */
router.post('/osint/sherlock', async (req, res) => {
    try {
        const { username } = req.body;
        if (!username) {
            return res.status(400).json({ error: 'Username required' });
        }
        const result = await dockerService.sherlockSearch(username);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/docker/osint/harvester
 * theHarvester domain OSINT
 */
router.post('/osint/harvester', async (req, res) => {
    try {
        const { domain, source } = req.body;
        if (!domain) {
            return res.status(400).json({ error: 'Domain required' });
        }
        const result = await dockerService.theHarvester(domain, source);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/docker/osint/amass
 * Amass subdomain enumeration
 */
router.post('/osint/amass', async (req, res) => {
    try {
        const { domain, passive } = req.body;
        if (!domain) {
            return res.status(400).json({ error: 'Domain required' });
        }
        const result = await dockerService.amassScan(domain, passive !== false);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== TOR TOOLS ====================

/**
 * GET /api/docker/tor/status
 * Statut Tor
 */
router.get('/tor/status', async (req, res) => {
    try {
        const status = await torInstance.checkTorStatus();
        const verification = await torInstance.verifyTorConnection();
        res.json({ ...status, ...verification });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/docker/tor/ip
 * IP Tor actuelle
 */
router.get('/tor/ip', async (req, res) => {
    try {
        const result = await dockerService.checkTorIP();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/docker/tor/new-circuit
 * Changer de circuit Tor
 */
router.post('/tor/new-circuit', async (req, res) => {
    try {
        const result = await torInstance.changeCircuit();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/docker/tor/request
 * Faire une requête via Tor
 */
router.post('/tor/request', async (req, res) => {
    try {
        const { url, method } = req.body;
        if (!url) {
            return res.status(400).json({ error: 'URL required' });
        }
        const result = await dockerService.torRequest(url, method);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/docker/tor/paranoid
 * Mode paranoïa pour Dark Web
 */
router.post('/tor/paranoid', async (req, res) => {
    try {
        const { url } = req.body;
        if (!url || !url.includes('.onion')) {
            return res.status(400).json({ error: 'Onion URL required' });
        }
        const result = await torInstance.paranoidMode(url);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/docker/tor/clear-traces
 * Effacer les traces
 */
router.post('/tor/clear-traces', async (req, res) => {
    try {
        const result = await torInstance.clearTraces();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== STANDBY SERVICE ====================

const toolsStandby = require('./tools_standby_service');

/**
 * GET /api/docker/standby/status
 * Statut des outils en standby
 */
router.get('/standby/status', (req, res) => {
    res.json(toolsStandby.getStatus());
});

/**
 * POST /api/docker/standby/warmup
 * Préchauffer les outils
 */
router.post('/standby/warmup', async (req, res) => {
    try {
        await toolsStandby.warmup();
        res.json({ success: true, message: 'Warmup complete' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/docker/tor/enable
 * Activer Tor MANUELLEMENT
 */
router.post('/tor/enable', async (req, res) => {
    try {
        const result = await toolsStandby.enableTor();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/docker/tor/disable
 * Désactiver Tor
 */
router.post('/tor/disable', async (req, res) => {
    try {
        const result = await toolsStandby.disableTor();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/docker/quick-exec
 * Exécution rapide d'un outil en standby
 */
router.post('/quick-exec', async (req, res) => {
    try {
        const { tool, command, target } = req.body;
        const result = await toolsStandby.quickExec(tool, command, target);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
