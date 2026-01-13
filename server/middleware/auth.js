const userService = require('../user_service');
const SubscriptionService = require('../subscription_service');
const authService = require('../auth_service');

const subscriptionService = new SubscriptionService();

const authMiddleware = (req, res, next) => {
    // 1. Try JWT Token first (from Frontend AuthContext)
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        try {
            const token = authHeader.split(' ')[1];
            const user = authService.verifyToken(token);
            if (user) {
                // Add tier info if not present (for backward compatibility)
                req.user = {
                    ...user,
                    tier: user.tier || 'initiate'
                };
                return next();
            }
        } catch (err) {
            console.warn('[AUTH] JWT verification failed:', err.message);
            // Continue to try API Key
        }
    }

    // 2. Try API Key (x-api-key header)
    const apiKey = req.headers['x-api-key'];

    if (apiKey) {
        const user = userService.validateKey(apiKey);
        if (user) {
            req.user = user;
            return next();
        }
        return res.status(401).json({ error: "Unauthorized: Invalid API Key" });
    }

    // 3. Fallback: Default to Admin for localhost development
    // This keeps the app working during development without requiring API keys everywhere
    // CRITICAL: Only allowed in development mode
    if (process.env.NODE_ENV === 'development' && process.env.ADMIN_API_KEY) {
        const adminUser = userService.validateKey(process.env.ADMIN_API_KEY);
        if (adminUser) {
            req.user = adminUser;
            return next();
        }
    }

    // 4. FALLBACK FOR LOCAL DEVELOPMENT: Create a default admin user
    // This allows the app to work without explicit authentication during development
    // WARNING: This should be disabled in production
    if (!process.env.NODE_ENV || process.env.NODE_ENV === 'development') {
        console.log('[AUTH] No auth provided, using default admin user for development');
        req.user = {
            id: 'dev-admin',
            username: 'dev-admin',
            tier: 'architect',
            tierConfig: {
                models: ['all'],
                tools: ['all'],
                level: 100
            }
        };
        return next();
    }

    // 5. No valid authentication found (production)
    return res.status(401).json({ error: "Unauthorized: No valid authentication provided" });
};

/**
 * Middleware pour vérifier le tier minimum requis
 * @param {String} minimumTier - Tier minimum requis (initiate, operator, architect)
 * @returns {Function} Middleware Express
 */
const requireTier = (minimumTier) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                error: "Unauthorized",
                message: "Authentication required"
            });
        }

        const userLevel = subscriptionService.TIERS[req.user.tier]?.level ?? -1;
        const requiredLevel = subscriptionService.TIERS[minimumTier]?.level ?? 99;

        if (userLevel < requiredLevel) {
            const requiredTierInfo = subscriptionService.TIERS[minimumTier];
            return res.status(403).json({
                error: "Forbidden",
                message: `This feature requires ${requiredTierInfo.label} subscription`,
                current_tier: subscriptionService.getTierInfo(req.user).label,
                required_tier: requiredTierInfo.label,
                upgrade_available: req.user.tier !== 'architect'
            });
        }

        next();
    };
};

/**
 * Middleware pour vérifier l'accès à une fonctionnalité spécifique
 * @param {String} feature - Nom de la fonctionnalité
 * @returns {Function} Middleware Express
 */
const requireFeature = (feature) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                error: "Unauthorized",
                message: "Authentication required"
            });
        }

        if (!subscriptionService.hasAccess(req.user, feature)) {
            const requiredTier = subscriptionService.FEATURES[feature];
            const requiredTierInfo = subscriptionService.TIERS[requiredTier];

            return res.status(403).json({
                error: "Forbidden",
                message: `Access to "${feature}" requires ${requiredTierInfo.label} subscription`,
                current_tier: subscriptionService.getTierInfo(req.user).label,
                required_tier: requiredTierInfo.label,
                upgrade_available: req.user.tier !== 'architect'
            });
        }

        next();
    };
};

module.exports = {
    authMiddleware,
    requireTier,
    requireFeature,
    subscriptionService
};

