// ===============================================
// Subscription Service - Gestion des Tiers d'Abonnement
// FREE (initiate), PREMIUM (operator), OWNER (architect)
// ===============================================

class SubscriptionService {
    constructor() {
        // Définition des tiers avec niveaux et limites
        this.TIERS = {
            initiate: {
                level: 0,
                name: 'FREE',
                label: '🆓 Gratuit',
                limits: {
                    chat_per_day: 10,
                    google_search_per_day: 5,
                    patterns: 5,
                    agents: 0
                }
            },
            operator: {
                level: 1,
                name: 'PREMIUM',
                label: '⭐ Premium',
                limits: {
                    chat_per_day: -1, // -1 = illimité
                    google_search_per_day: -1,
                    patterns: -1,
                    agents: 10
                }
            },
            enterprise: {
                level: 2,
                name: 'ENTERPRISE',
                label: '🏢 Entreprise',
                limits: {
                    chat_per_day: -1,
                    google_search_per_day: -1,
                    patterns: -1,
                    agents: 25, // Plus d'agents que PREMIUM
                    seats: 10   // 10 utilisateurs par license entreprise
                }
            },
            architect: {
                level: 3,
                name: 'OWNER',
                label: '👑 Propriétaire',
                limits: {} // Aucune limite
            },

            // ========= NEXUS33 SECURITY TIERS =========
            security_starter: {
                level: 1,
                name: 'SECURITY_STARTER',
                label: '🔒 Security Starter',
                limits: {
                    domains: 1,
                    scans_per_month: 4,
                    api_access: false
                }
            },
            security_pro: {
                level: 2,
                name: 'SECURITY_PRO',
                label: '🛡️ Security Pro',
                limits: {
                    domains: 5,
                    scans_per_month: -1, // Illimité
                    api_access: false
                }
            },
            security_enterprise: {
                level: 3,
                name: 'SECURITY_ENTERPRISE',
                label: '🏢 Security Enterprise',
                limits: {
                    domains: -1, // Illimité
                    scans_per_month: -1,
                    api_access: true
                }
            }
        };

        // Matrice d'accès: feature -> tier minimum requis
        this.FEATURES = {
            // Chat & Communication
            'chat_basic': 'initiate',        // 10 messages/jour
            'chat_unlimited': 'operator',     // Illimité
            'chat_cloud_models': 'operator',  // Groq, OpenAI
            'chat_claude': 'architect',       // Claude réservé OWNER

            // Recherche & OSINT
            'google_search_basic': 'initiate',   // 5 recherches/jour
            'google_search_advanced': 'operator', // Illimité
            'osint_basic': 'operator',           // Outils OSINT basiques
            'osint_advanced': 'operator',        // Outils OSINT avancés
            'osint_tor': 'architect',            // OSINT via Tor

            // Hacking & Security
            'hacking_basic': 'operator',         // Outils hacking basiques
            'hacking_advanced': 'architect',     // Outils avancés + Tor
            'cyber_training': 'operator',
            'cyber_training_aikido': 'architect',

            // Data & Analytics
            'patterns_limited': 'initiate',      // 5 patterns
            'patterns_all': 'operator',          // 232 patterns
            'kpi_view': 'operator',
            'kpi_edit': 'architect',

            // Finance & Pro
            'finance': 'architect',              // Kraken - Propriétaire seul
            'vision': 'architect',               // VPO - Propriétaire seul

            // Agents
            'agents_limited': 'operator',        // 10 agents
            'agents_all': 'architect'            // 37 agents
        };

        console.log('[SUBSCRIPTION] Service initialized with 3 tiers');
    }

    /**
     * Vérifier si l'utilisateur a accès à une fonctionnalité
     * @param {Object} user - Objet utilisateur avec propriété 'tier'
     * @param {String} feature - Nom de la fonctionnalité
     * @returns {Boolean} - true si accès autorisé
     */
    hasAccess(user, feature) {
        if (!user || !user.tier) {
            console.log('[SUBSCRIPTION] No user or tier provided');
            return false;
        }

        const requiredTier = this.FEATURES[feature];
        if (!requiredTier) {
            console.log(`[SUBSCRIPTION] Unknown feature: ${feature}`);
            return false;
        }

        const userLevel = this.TIERS[user.tier]?.level ?? -1;
        const requiredLevel = this.TIERS[requiredTier]?.level ?? 99;

        const hasAccess = userLevel >= requiredLevel;

        if (!hasAccess) {
            console.log(`[SUBSCRIPTION] Access denied: ${user.username} (${user.tier}) -> ${feature} (requires ${requiredTier})`);
        }

        return hasAccess;
    }

    /**
     * Obtenir les informations du tier de l'utilisateur
     * @param {Object} user - Objet utilisateur
     * @returns {Object} - Infos du tier
     */
    getTierInfo(user) {
        if (!user || !user.tier) {
            return this.TIERS.initiate; // Par défaut: FREE
        }

        return this.TIERS[user.tier] || this.TIERS.initiate;
    }

    /**
     * Vérifier si l'utilisateur a atteint sa limite d'utilisation
     * @param {Object} user - Objet utilisateur
     * @param {String} limitType - Type de limite (chat_per_day, google_search_per_day, etc.)
     * @param {Number} currentUsage - Utilisation actuelle
     * @returns {Boolean} - true si limite atteinte
     */
    hasReachedLimit(user, limitType, currentUsage) {
        const tierInfo = this.getTierInfo(user);
        const limit = tierInfo.limits[limitType];

        // -1 = illimité
        if (limit === -1 || limit === undefined) {
            return false;
        }

        return currentUsage >= limit;
    }

    /**
     * Obtenir toutes les fonctionnalités accessibles pour un tier
     * @param {String} tierName - Nom du tier
     * @returns {Array} - Liste des features accessibles
     */
    getAccessibleFeatures(tierName) {
        const userLevel = this.TIERS[tierName]?.level ?? -1;

        return Object.entries(this.FEATURES)
            .filter(([feature, requiredTier]) => {
                const requiredLevel = this.TIERS[requiredTier]?.level ?? 99;
                return userLevel >= requiredLevel;
            })
            .map(([feature]) => feature);
    }

    /**
     * Obtenir un résumé du statut d'abonnement
     * @param {Object} user - Objet utilisateur
     * @returns {Object} - Résumé complet
     */
    getSubscriptionStatus(user) {
        const tierInfo = this.getTierInfo(user);
        const accessibleFeatures = this.getAccessibleFeatures(user.tier);

        return {
            tier: {
                key: user.tier || 'initiate',
                name: tierInfo.name,
                label: tierInfo.label,
                level: tierInfo.level
            },
            limits: tierInfo.limits,
            features: {
                total: accessibleFeatures.length,
                list: accessibleFeatures
            },
            upgrade: {
                available: user.tier !== 'architect',
                nextTier: user.tier === 'initiate' ? 'operator' : (user.tier === 'operator' ? 'architect' : null)
            }
        };
    }

    /**
     * Vérifier si un modèle LLM est accessible
     * @param {Object} user - Objet utilisateur
     * @param {String} provider - Provider du modèle (groq, claude, openai, etc.)
     * @returns {Boolean}
     */
    canUseModelProvider(user, provider) {
        const providerMap = {
            'ollama': 'chat_basic',
            'groq': 'chat_cloud_models',
            'openai': 'chat_cloud_models',
            'claude': 'chat_claude',
            'anythingllm': 'chat_basic'
        };

        const feature = providerMap[provider.toLowerCase()];
        if (!feature) return false;

        return this.hasAccess(user, feature);
    }
}

module.exports = SubscriptionService;
