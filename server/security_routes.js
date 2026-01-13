/**
 * Routes API pour le service de sécurité
 * Protection des connexions et monitoring
 */

const express = require('express');
const router = express.Router();
const ConnectionSecurityService = require('./connection_security_service');

const securityService = new ConnectionSecurityService();

/**
 * GET /security/status
 * Obtenir le statut de sécurité
 */
router.get('/status', (req, res) => {
    res.json({
        success: true,
        stats: securityService.getStats()
    });
});

/**
 * GET /security/events
 * Obtenir les événements de sécurité récents
 */
router.get('/events', (req, res) => {
    const count = parseInt(req.query.count) || 50;
    res.json({
        success: true,
        events: securityService.getRecentEvents(count)
    });
});

/**
 * POST /security/block-ip
 * Bloquer une IP
 */
router.post('/block-ip', async (req, res) => {
    try {
        const { ip } = req.body;
        if (!ip) {
            return res.status(400).json({
                success: false,
                error: 'IP required'
            });
        }
        await securityService.blockIP(ip);
        res.json({
            success: true,
            message: `IP ${ip} bloquée`
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /security/unblock-ip
 * Débloquer une IP
 */
router.post('/unblock-ip', async (req, res) => {
    try {
        const { ip } = req.body;
        if (!ip) {
            return res.status(400).json({
                success: false,
                error: 'IP required'
            });
        }
        await securityService.unblockIP(ip);
        res.json({
            success: true,
            message: `IP ${ip} débloquée`
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /security/add-trusted-domain
 * Ajouter un domaine de confiance
 */
router.post('/add-trusted-domain', (req, res) => {
    const { domain } = req.body;
    if (!domain) {
        return res.status(400).json({
            success: false,
            error: 'Domain required'
        });
    }
    securityService.addTrustedDomain(domain);
    res.json({
        success: true,
        message: `Domaine ${domain} ajouté aux domaines de confiance`
    });
});

/**
 * GET /security/config
 * Obtenir la configuration de sécurité
 */
router.get('/config', (req, res) => {
    res.json({
        success: true,
        config: securityService.getSecurityConfig()
    });
});

/**
 * POST /security/validate-key
 * Valider une clé API
 */
router.post('/validate-key', (req, res) => {
    const { key, type } = req.body;
    const result = securityService.validateAPIKey(key, type);
    res.json({
        success: true,
        validation: result
    });
});

/**
 * POST /security/encrypt
 * Chiffrer des données sensibles
 */
router.post('/encrypt', (req, res) => {
    try {
        const { data } = req.body;
        if (!data) {
            return res.status(400).json({
                success: false,
                error: 'Data required'
            });
        }
        
        const encrypted = securityService.encrypt(data);
        res.json({
            success: true,
            encrypted
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /security/middleware
 * Obtenir le middleware de sécurité (pour documentation)
 */
router.get('/middleware-info', (req, res) => {
    res.json({
        success: true,
        info: {
            description: 'Middleware de sécurité actif sur toutes les routes',
            features: [
                'Blocage IP automatique',
                'Rate limiting (100 req/min)',
                'Détection SQL Injection',
                'Détection XSS',
                'Détection Path Traversal',
                'Détection Command Injection',
                'Détection de scanners (sqlmap, nikto, etc.)',
                'Headers de sécurité automatiques'
            ],
            securityHeaders: [
                'X-Content-Type-Options: nosniff',
                'X-Frame-Options: DENY',
                'X-XSS-Protection: 1; mode=block',
                'Strict-Transport-Security',
                'Content-Security-Policy'
            ]
        }
    });
});

// Exporter aussi le service et le middleware pour l'intégration
router.securityService = securityService;
router.middleware = securityService.securityMiddleware();

module.exports = router;
