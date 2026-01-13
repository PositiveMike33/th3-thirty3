/**
 * Nexus33 Security Scanner Routes
 * API endpoints pour le scan de sécurité SaaS
 * 
 * @version 1.0.0
 * @author Th3 Thirty3
 */

const express = require('express');
const router = express.Router();

// Le service sera injecté
let scannerService = null;
let subscriptionService = null;

/**
 * Initialiser les routes avec les services
 */
function initRoutes(scanner, subscription) {
    scannerService = scanner;
    subscriptionService = subscription;
    return router;
}

/**
 * POST /api/security/scan
 * Lancer un nouveau scan de sécurité
 */
router.post('/scan', async (req, res) => {
    try {
        const { domain } = req.body;
        const userId = req.user?.id || 'anonymous';

        if (!domain) {
            return res.status(400).json({
                success: false,
                error: 'Le domaine est requis'
            });
        }

        // Vérifier les limites d'abonnement si le service est disponible
        if (subscriptionService && req.user) {
            const canScan = !subscriptionService.hasReachedLimit(
                req.user,
                'scans_per_month',
                req.user.scansThisMonth || 0
            );

            if (!canScan) {
                return res.status(403).json({
                    success: false,
                    error: 'Limite de scans atteinte pour ce mois',
                    upgrade: true
                });
            }
        }

        const result = await scannerService.startScan(domain, userId);

        res.json({
            success: true,
            message: 'Scan démarré',
            ...result
        });

    } catch (error) {
        console.error('[SECURITY-ROUTES] Scan error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /api/security/scan/:id
 * Obtenir le statut d'un scan
 */
router.get('/scan/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const status = scannerService.getScanStatus(id);

        if (status.error) {
            return res.status(404).json({
                success: false,
                error: status.error
            });
        }

        res.json({
            success: true,
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
 * GET /api/security/history
 * Obtenir l'historique des scans
 */
router.get('/history', async (req, res) => {
    try {
        const userId = req.user?.id || 'anonymous';
        const limit = parseInt(req.query.limit) || 10;

        const history = scannerService.getScanHistory(userId, limit);

        res.json({
            success: true,
            count: history.length,
            scans: history.map(scan => ({
                id: scan.id,
                domain: scan.domain,
                status: scan.status,
                score: scan.results?.score,
                grade: scan.results?.grade,
                startedAt: scan.startedAt,
                completedAt: scan.completedAt
            }))
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /api/security/quick-scan
 * Scan rapide (SSL + Headers seulement)
 */
router.post('/quick-scan', async (req, res) => {
    try {
        const { domain } = req.body;

        if (!domain) {
            return res.status(400).json({
                success: false,
                error: 'Le domaine est requis'
            });
        }

        const normalizedDomain = scannerService.normalizeDomain(domain);

        // Scan rapide: SSL + Headers seulement
        const [ssl, headers] = await Promise.all([
            scannerService.scanSSL(normalizedDomain),
            scannerService.scanHeaders(normalizedDomain)
        ]);

        const quickScore = Math.round((ssl.score * 0.5) + (headers.score * 0.5));

        res.json({
            success: true,
            domain: normalizedDomain,
            quickScore,
            grade: scannerService.scoreToGrade(quickScore),
            ssl: {
                score: ssl.score,
                valid: ssl.valid,
                protocol: ssl.protocol,
                issuesCount: ssl.issues.length
            },
            headers: {
                score: headers.score,
                present: headers.present.length,
                missing: headers.missing.length,
                issuesCount: headers.issues.length
            },
            message: 'Scan complet disponible avec abonnement'
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /api/security/health
 * Vérifier la santé du service
 */
router.get('/health', (req, res) => {
    const health = scannerService.healthCheck();
    res.json({
        success: true,
        service: 'security-scanner',
        ...health
    });
});

/**
 * GET /api/security/pricing
 * Obtenir les tarifs
 */
router.get('/pricing', (req, res) => {
    res.json({
        success: true,
        tiers: {
            starter: {
                name: 'Starter',
                price: 99,
                currency: 'CAD',
                billing: 'monthly',
                features: [
                    '1 domaine surveillé',
                    '4 scans par mois',
                    'Rapport de base',
                    'Alertes email'
                ],
                limits: {
                    domains: 1,
                    scans_per_month: 4
                }
            },
            pro: {
                name: 'Pro',
                price: 199,
                currency: 'CAD',
                billing: 'monthly',
                recommended: true,
                features: [
                    '5 domaines surveillés',
                    'Scans illimités',
                    'Rapport complet avec Loi 25',
                    'Alertes en temps réel',
                    'Support prioritaire'
                ],
                limits: {
                    domains: 5,
                    scans_per_month: -1
                }
            },
            enterprise: {
                name: 'Enterprise',
                price: 499,
                currency: 'CAD',
                billing: 'monthly',
                features: [
                    'Domaines illimités',
                    'Scans illimités',
                    'API access',
                    'Rapport personnalisé',
                    'Conformité Loi 25 complète',
                    'Account manager dédié'
                ],
                limits: {
                    domains: -1,
                    scans_per_month: -1,
                    api_access: true
                }
            }
        }
    });
});

module.exports = { router, initRoutes };
