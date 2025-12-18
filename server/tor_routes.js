/**
 * Routes API pour le service Tor
 * Connexion anonyme, changement d'IP, accès Dark Web
 */

const express = require('express');
const router = express.Router();
const TorNetworkService = require('./tor_network_service');
const torStartupCheck = require('./tor_startup_check');

const torService = new TorNetworkService();

/**
 * GET /tor/startup-check
 * Vérifie le statut Tor au démarrage et tente de le lancer si nécessaire
 */
router.get('/startup-check', async (req, res) => {
    try {
        const result = await torStartupCheck.performStartupCheck();
        res.json({
            success: true,
            ...result
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /tor/verify
 * Test rapide de connexion Tor réelle
 */
router.get('/verify', async (req, res) => {
    try {
        const verification = await torStartupCheck.verifyTorConnection();
        res.json({
            success: true,
            ...verification,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /tor/start
 * Démarre tor.exe manuellement
 */
router.post('/start', async (req, res) => {
    try {
        await torStartupCheck.startTor();
        const status = torStartupCheck.getStatus();
        res.json({
            success: true,
            message: 'Tor started successfully',
            ...status
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /tor/stop
 * Arrête tor.exe
 */
router.post('/stop', async (req, res) => {
    try {
        await torStartupCheck.stopTor();
        res.json({
            success: true,
            message: 'Tor stopped'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /tor/status
 * Vérifie si Tor est connecté et obtenir l'IP actuelle
 */
router.get('/status', async (req, res) => {
    try {
        const status = await torService.checkTorStatus();
        const verification = await torService.verifyTorConnection();
        const stats = torService.getStats();

        res.json({
            success: true,
            tor: {
                ...status,
                ...verification
            },
            stats
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /tor/ip
 * Obtenir l'IP de sortie Tor actuelle
 */
router.get('/ip', async (req, res) => {
    try {
        const ip = await torService.getCurrentIP();
        res.json({
            success: true,
            ip,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /tor/new-identity
 * Demander un nouveau circuit Tor (nouvelle IP)
 */
router.post('/new-identity', async (req, res) => {
    try {
        const result = await torService.changeCircuit();
        const newIP = await torService.getCurrentIP();
        
        res.json({
            success: true,
            ...result,
            newIP,
            totalChanges: torService.circuitChanges
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            hint: 'Assurez-vous que Tor est installé avec ControlPort activé'
        });
    }
});

/**
 * POST /tor/auto-rotate
 * Activer/désactiver la rotation automatique d'IP
 */
router.post('/auto-rotate', async (req, res) => {
    try {
        const { enabled, intervalSeconds = 300 } = req.body;
        
        if (enabled) {
            const result = torService.startAutoRotation(intervalSeconds * 1000);
            res.json({ success: true, ...result });
        } else {
            const result = torService.stopAutoRotation();
            res.json({ success: true, ...result });
        }
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /tor/fetch
 * Faire une requête HTTP via Tor
 */
router.post('/fetch', async (req, res) => {
    try {
        const { url, method = 'GET', headers = {} } = req.body;
        
        if (!url) {
            return res.status(400).json({
                success: false,
                error: 'URL requise'
            });
        }

        const response = await torService.torFetch(url, {
            method,
            headers: {
                'User-Agent': torService.getRandomUserAgent(),
                ...headers
            }
        });

        const contentType = response.headers.get('content-type') || '';
        let data;
        
        if (contentType.includes('application/json')) {
            data = await response.json();
        } else {
            data = await response.text();
        }

        res.json({
            success: true,
            status: response.status,
            contentType,
            data,
            fetchedVia: 'tor',
            exitIP: torService.currentIP
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /tor/onion/:encodedUrl
 * Accéder à un site .onion
 */
router.get('/onion/:encodedUrl', async (req, res) => {
    try {
        const url = decodeURIComponent(req.params.encodedUrl);
        const result = await torService.fetchOnionSite(url);
        res.json(result);
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /tor/config
 * Obtenir la configuration torrc recommandée
 */
router.get('/config', (req, res) => {
    res.json({
        success: true,
        config: torService.getTorrcConfig(),
        instructions: {
            windows: 'Installez Tor Browser ou Tor Expert Bundle depuis https://www.torproject.org',
            linux: 'sudo apt install tor && sudo systemctl start tor',
            mac: 'brew install tor && brew services start tor'
        },
        ports: {
            socks: torService.torSocksPort,
            control: torService.torControlPort
        }
    });
});

/**
 * GET /tor/stats
 * Obtenir les statistiques du service
 */
router.get('/stats', (req, res) => {
    res.json({
        success: true,
        stats: torService.getStats()
    });
});

module.exports = router;
