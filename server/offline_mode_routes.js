/**
 * Routes API pour Offline Mode Service
 */

const express = require('express');
const router = express.Router();
const OfflineModeService = require('./offline_mode_service');

let offlineService = null;

// Initialiser avec Socket.io
const initWithSocketIO = (io) => {
    offlineService = new OfflineModeService(io);
    return offlineService;
};

/**
 * GET /api/offline-mode/status
 * État actuel du mode offline/online
 */
router.get('/status', (req, res) => {
    if (!offlineService) {
        offlineService = new OfflineModeService();
    }
    res.json({
        success: true,
        ...offlineService.getStatus()
    });
});

/**
 * POST /api/offline-mode/check
 * Forcer une vérification de connexion
 */
router.post('/check', async (req, res) => {
    if (!offlineService) {
        offlineService = new OfflineModeService();
    }

    const isOnline = await offlineService.checkConnection();
    res.json({
        success: true,
        isOnline,
        model: offlineService.getOptimalModel(),
        energyMode: offlineService.config.energyMode
    });
});

/**
 * POST /api/offline-mode/energy
 * Changer le mode énergétique
 */
router.post('/energy', (req, res) => {
    const { mode } = req.body;

    if (!['normal', 'eco', 'ultra-eco'].includes(mode)) {
        return res.status(400).json({
            success: false,
            error: 'Mode invalide. Options: normal, eco, ultra-eco'
        });
    }

    if (!offlineService) {
        offlineService = new OfflineModeService();
    }

    const config = offlineService.setEnergyMode(mode);
    res.json({
        success: true,
        mode,
        config,
        model: offlineService.getOptimalModel()
    });
});

/**
 * POST /api/offline-mode/simulate
 * Simuler mode offline/online (pour tests)
 */
router.post('/simulate', (req, res) => {
    const { online } = req.body;

    if (typeof online !== 'boolean') {
        return res.status(400).json({
            success: false,
            error: 'Paramètre "online" (boolean) requis'
        });
    }

    if (!offlineService) {
        offlineService = new OfflineModeService();
    }

    offlineService.forceMode(online);
    res.json({
        success: true,
        isOnline: offlineService.isOnline,
        model: offlineService.getOptimalModel(),
        energyMode: offlineService.config.energyMode
    });
});

/**
 * GET /api/offline-mode/model
 * Obtenir le modèle optimal actuel
 */
router.get('/model', (req, res) => {
    if (!offlineService) {
        offlineService = new OfflineModeService();
    }

    res.json({
        success: true,
        model: offlineService.getOptimalModel(),
        options: offlineService.getOptimizedOptions(),
        isOnline: offlineService.isOnline,
        energyMode: offlineService.config.energyMode
    });
});

/**
 * GET /api/offline-mode/service/:serviceName
 * Vérifier si un service cloud est disponible
 */
router.get('/service/:serviceName', (req, res) => {
    const { serviceName } = req.params;

    if (!offlineService) {
        offlineService = new OfflineModeService();
    }

    res.json({
        success: true,
        service: serviceName,
        available: offlineService.isServiceAvailable(serviceName),
        isOnline: offlineService.isOnline
    });
});

/**
 * GET /api/offline-mode/provider
 * Obtenir les infos complètes du provider optimal (cloud vs local)
 */
router.get('/provider', (req, res) => {
    if (!offlineService) {
        offlineService = new OfflineModeService();
    }

    res.json({
        success: true,
        ...offlineService.getOptimalProvider(),
        isOnline: offlineService.isOnline,
        energyMode: offlineService.config.energyMode
    });
});

/**
 * POST /api/offline-mode/preference
 * Changer la préférence cloud/local
 * @body {boolean} preferCloud - true pour préférer cloud, false pour local
 */
router.post('/preference', (req, res) => {
    const { preferCloud } = req.body;

    if (typeof preferCloud !== 'boolean') {
        return res.status(400).json({
            success: false,
            error: 'Paramètre "preferCloud" (boolean) requis'
        });
    }

    if (!offlineService) {
        offlineService = new OfflineModeService();
    }

    offlineService.config.preferCloud = preferCloud;
    console.log(`[OFFLINE-MODE] Preference changed to: ${preferCloud ? 'CLOUD' : 'LOCAL'}`);

    res.json({
        success: true,
        preferCloud: offlineService.config.preferCloud,
        ...offlineService.getOptimalProvider()
    });
});

// Exports
router.initWithSocketIO = initWithSocketIO;
router.getService = () => offlineService;

module.exports = router;
