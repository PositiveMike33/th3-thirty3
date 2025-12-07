// ===============================================
// Subscription Routes - Gestion des Abonnements
// API pour vérifier tier, features, limites
// ===============================================

const express = require('express');
const router = express.Router();
const { authMiddleware, subscriptionService } = require('./middleware/auth');

// Appliquer auth middleware sur toutes les routes subscription
router.use(authMiddleware);

/**
 * GET /api/subscription/status
 * Obtenir le statut d'abonnement de l'utilisateur
 */
router.get('/status', (req, res) => {
    try {
        const status = subscriptionService.getSubscriptionStatus(req.user);
        
        res.json({
            success: true,
            user: {
                username: req.user.username,
                id: req.user.id
            },
            subscription: status
        });
    } catch (error) {
        console.error('[SUBSCRIPTION] Error getting status:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to get subscription status' 
        });
    }
});

/**
 * GET /api/subscription/features
 * Liste toutes les fonctionnalités accessibles pour le tier actuel
 */
router.get('/features', (req, res) => {
    try {
        const accessibleFeatures = subscriptionService.getAccessibleFeatures(req.user.tier);
        const tierInfo = subscriptionService.getTierInfo(req.user);
        
        res.json({
            success: true,
            tier: tierInfo.label,
            features: {
                total: accessibleFeatures.length,
                list: accessibleFeatures
            }
        });
    } catch (error) {
        console.error('[SUBSCRIPTION] Error getting features:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to get features' 
        });
    }
});

/**
 * GET /api/subscription/limits
 * Obtenir les quotas et limites du tier actuel
 */
router.get('/limits', (req, res) => {
    try {
        const tierInfo = subscriptionService.getTierInfo(req.user);
        
        res.json({
            success: true,
            tier: tierInfo.label,
            limits: tierInfo.limits
        });
    } catch (error) {
        console.error('[SUBSCRIPTION] Error getting limits:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to get limits' 
        });
    }
});

/**
 * POST /api/subscription/check-access
 * Vérifier l'accès à une fonctionnalité spécifique
 * Body: { feature: "feature_name" }
 */
router.post('/check-access', (req, res) => {
    try {
        const { feature } = req.body;
        
        if (!feature) {
            return res.status(400).json({
                success: false,
                error: 'Feature name required'
            });
        }

        const hasAccess = subscriptionService.hasAccess(req.user, feature);
        const requiredTier = subscriptionService.FEATURES[feature];
        
        res.json({
            success: true,
            feature,
            access: hasAccess,
            current_tier: subscriptionService.getTierInfo(req.user).label,
            required_tier: requiredTier ? subscriptionService.TIERS[requiredTier].label : 'Unknown'
        });
    } catch (error) {
        console.error('[SUBSCRIPTION] Error checking access:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to check access' 
        });
    }
});

/**
 * GET /api/subscription/tiers
 * Liste tous les tiers disponibles (pour la page pricing)
 */
router.get('/tiers', (req, res) => {
    try {
        const tiers = Object.entries(subscriptionService.TIERS).map(([key, value]) => ({
            key,
            name: value.name,
            label: value.label,
            level: value.level,
            limits: value.limits
        }));
        
        res.json({
            success: true,
            tiers
        });
    } catch (error) {
        console.error('[SUBSCRIPTION] Error getting tiers:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to get tiers' 
        });
    }
});

/**
 * POST /api/subscription/upgrade
 * Demande d'upgrade (futur: intégration paiement Stripe)
 * Body: { target_tier: "operator" }
 */
router.post('/upgrade', (req, res) => {
    try {
        const { target_tier } = req.body;
        
        if (!target_tier || !subscriptionService.TIERS[target_tier]) {
            return res.status(400).json({
                success: false,
                error: 'Valid target tier required (operator, architect)'
            });
        }

        const currentLevel = subscriptionService.TIERS[req.user.tier]?.level ?? -1;
        const targetLevel = subscriptionService.TIERS[target_tier].level;

        if (targetLevel <= currentLevel) {
            return res.status(400).json({
                success: false,
                error: 'Cannot upgrade to same or lower tier'
            });
        }

        // TODO: Intégrer Stripe pour le paiement
        // Pour l'instant, on retourne juste un message
        res.json({
            success: true,
            message: 'Upgrade request received',
            current_tier: subscriptionService.getTierInfo(req.user).label,
            target_tier: subscriptionService.TIERS[target_tier].label,
            payment_required: target_tier !== 'architect', // Architect = propriétaire, pas de paiement
            next_step: 'Contact support for enterprise upgrade'
        });
    } catch (error) {
        console.error('[SUBSCRIPTION] Error processing upgrade:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to process upgrade' 
        });
    }
});

module.exports = router;
