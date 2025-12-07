/**
 * Security Zone Isolation Service
 * Conteneurisation et isolation de chaque partie de l'application
 * Protection des zones critiques (Finance, Auth, Admin) contre les intrusions
 */

const crypto = require('crypto');
const EventEmitter = require('events');

class SecurityZoneService extends EventEmitter {
    constructor() {
        super();

        // Définition des zones de sécurité
        this.zones = {
            // Zone publique - Accès ouvert
            public: {
                level: 0,
                name: 'Public Zone',
                color: 'green',
                routes: ['/health', '/api/status', '/patterns'],
                requiresAuth: false,
                requiresTor: false,
                isolated: false
            },

            // Zone Chat - Accès authentifié
            chat: {
                level: 1,
                name: 'Chat Zone',
                color: 'blue',
                routes: ['/chat', '/sessions', '/feedback'],
                requiresAuth: true,
                requiresTor: false,
                isolated: true,
                maxRequests: 100,
                sessionTimeout: 3600000 // 1h
            },

            // Zone OSINT - Accès sécurisé via Tor
            osint: {
                level: 2,
                name: 'OSINT Zone',
                color: 'cyan',
                routes: ['/api/osint', '/api/hacking-experts', '/api/tor'],
                requiresAuth: true,
                requiresTor: true,
                isolated: true,
                traceClear: true,
                maxRequests: 50
            },

            // Zone Finance - Accès critique, isolation maximale
            finance: {
                level: 3,
                name: 'Finance Zone',
                color: 'gold',
                routes: ['/api/finance', '/api/kraken', '/finance'],
                requiresAuth: true,
                requiresTor: true,  // Recommandé pour crypto
                isolated: true,
                encrypted: true,
                maxRequests: 30,
                cooldownBetweenRequests: 1000, // 1s entre requêtes
                ipWhitelist: true,
                mfaRequired: true,
                auditLog: true
            },

            // Zone Admin - Accès super-restreint
            admin: {
                level: 4,
                name: 'Admin Zone',
                color: 'red',
                routes: ['/api/settings', '/api/security', '/api/users'],
                requiresAuth: true,
                requiresTor: false,
                isolated: true,
                encrypted: true,
                maxRequests: 20,
                ipWhitelist: true,
                mfaRequired: true,
                auditLog: true,
                localOnly: true // Seulement localhost
            }
        };

        // Sessions isolées par zone
        this.zoneSessions = new Map();

        // Audit log
        this.auditLog = [];

        // IP Whitelist par zone
        this.ipWhitelists = {
            finance: new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']),
            admin: new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1'])
        };

        // Stats par zone
        this.zoneStats = {};
        Object.keys(this.zones).forEach(zone => {
            this.zoneStats[zone] = {
                requests: 0,
                blocked: 0,
                breachAttempts: 0,
                lastAccess: null
            };
        });

        console.log('[ISOLATION] Security Zone Service initialized');
        console.log(`[ISOLATION] Zones configured: ${Object.keys(this.zones).join(', ')}`);
    }

    /**
     * Déterminer la zone d'une route
     */
    getZoneForRoute(path) {
        for (const [zoneKey, zone] of Object.entries(this.zones)) {
            if (zone.routes.some(route => path.startsWith(route))) {
                return { key: zoneKey, ...zone };
            }
        }
        return { key: 'public', ...this.zones.public };
    }

    /**
     * Middleware d'isolation de zone
     */
    zoneIsolationMiddleware() {
        return (req, res, next) => {
            const path = req.path;
            const clientIP = req.ip || req.connection.remoteAddress;
            const zone = this.getZoneForRoute(path);
            const zoneKey = zone.key; // Use key for stats access

            // Créer un contexte de zone isolé
            req.securityZone = {
                key: zoneKey,
                name: zone.name,
                level: zone.level,
                isolated: zone.isolated
            };

            this.zoneStats[zoneKey].requests++;
            this.zoneStats[zoneKey].lastAccess = new Date();

            // 1. Vérifier si zone nécessite authentification
            if (zone.requiresAuth && !this.isAuthenticated(req)) {
                this.logBreachAttempt(zoneKey, clientIP, 'UNAUTHENTICATED');
                return res.status(401).json({
                    error: 'Authentication required',
                    zone: zone.name,
                    securityLevel: zone.level
                });
            }

            // 2. Vérifier IP Whitelist pour zones critiques
            if (zone.ipWhitelist && !this.isIPWhitelisted(zoneKey, clientIP)) {
                this.logBreachAttempt(zoneKey, clientIP, 'IP_NOT_WHITELISTED');
                this.zoneStats[zoneKey].blocked++;
                return res.status(403).json({
                    error: 'Access denied - IP not authorized',
                    zone: zone.name
                });
            }

            // 3. Vérifier localOnly pour zone admin
            if (zone.localOnly && !this.isLocalhost(clientIP)) {
                this.logBreachAttempt(zoneKey, clientIP, 'REMOTE_ACCESS_DENIED');
                this.zoneStats[zoneKey].blocked++;
                return res.status(403).json({
                    error: 'Admin zone accessible only from localhost',
                    zone: zone.name
                });
            }

            // 4. Rate limiting par zone
            if (zone.maxRequests && !this.checkZoneRateLimit(zoneKey, clientIP, zone.maxRequests)) {
                this.zoneStats[zoneKey].blocked++;
                return res.status(429).json({
                    error: 'Zone rate limit exceeded',
                    zone: zone.name,
                    retryAfter: 60
                });
            }

            // 5. Ajouter headers d'isolation
            res.setHeader('X-Security-Zone', zone.name);
            res.setHeader('X-Zone-Level', zone.level);
            res.setHeader('X-Zone-Isolated', zone.isolated ? 'true' : 'false');

            // 6. Log d'audit pour zones critiques
            if (zone.auditLog) {
                this.addAuditLog({
                    zone: zone.name,
                    path,
                    ip: clientIP,
                    method: req.method,
                    timestamp: new Date(),
                    user: req.user?.id || 'anonymous'
                });
            }

            next();
        };
    }

    /**
     * Vérifier si la requête est authentifiée
     */
    isAuthenticated(req) {
        // Vérifier le header d'auth ou la session
        return req.headers['x-api-key'] || 
               req.headers['authorization'] || 
               req.user ||
               req.session?.authenticated;
    }

    /**
     * Vérifier si l'IP est dans la whitelist
     */
    isIPWhitelisted(zoneName, ip) {
        const whitelist = this.ipWhitelists[zoneName];
        if (!whitelist) return true;
        
        const normalizedIP = ip.replace('::ffff:', '');
        return whitelist.has(ip) || whitelist.has(normalizedIP);
    }

    /**
     * Vérifier si c'est localhost
     */
    isLocalhost(ip) {
        const localIPs = ['127.0.0.1', '::1', '::ffff:127.0.0.1', 'localhost'];
        const normalizedIP = ip.replace('::ffff:', '');
        return localIPs.includes(ip) || localIPs.includes(normalizedIP);
    }

    /**
     * Rate limiting par zone
     */
    checkZoneRateLimit(zoneName, ip, maxRequests) {
        const key = `${zoneName}:${ip}`;
        const now = Date.now();
        const windowMs = 60000; // 1 minute

        if (!this.zoneSessions.has(key)) {
            this.zoneSessions.set(key, { requests: [], lastCleanup: now });
        }

        const session = this.zoneSessions.get(key);
        session.requests = session.requests.filter(time => time > now - windowMs);
        session.requests.push(now);

        return session.requests.length <= maxRequests;
    }

    /**
     * Logger une tentative de breach
     */
    logBreachAttempt(zoneName, ip, reason) {
        this.zoneStats[zoneName].breachAttempts++;
        
        const event = {
            type: 'BREACH_ATTEMPT',
            zone: zoneName,
            ip,
            reason,
            timestamp: new Date()
        };

        this.auditLog.push(event);
        this.emit('breachAttempt', event);

        console.log(`[ISOLATION] 🚨 BREACH ATTEMPT: ${zoneName} from ${ip} - ${reason}`);
    }

    /**
     * Ajouter au log d'audit
     */
    addAuditLog(entry) {
        this.auditLog.push(entry);
        
        // Garder seulement les 500 dernières entrées
        if (this.auditLog.length > 500) {
            this.auditLog = this.auditLog.slice(-500);
        }
    }

    /**
     * Ajouter une IP à la whitelist d'une zone
     */
    addToWhitelist(zoneName, ip) {
        if (!this.ipWhitelists[zoneName]) {
            this.ipWhitelists[zoneName] = new Set();
        }
        this.ipWhitelists[zoneName].add(ip);
        console.log(`[ISOLATION] ✅ Added ${ip} to ${zoneName} whitelist`);
    }

    /**
     * Retirer une IP de la whitelist
     */
    removeFromWhitelist(zoneName, ip) {
        if (this.ipWhitelists[zoneName]) {
            this.ipWhitelists[zoneName].delete(ip);
            console.log(`[ISOLATION] ❌ Removed ${ip} from ${zoneName} whitelist`);
        }
    }

    /**
     * Générer un token de session isolé pour une zone
     */
    generateZoneToken(zoneName, userId) {
        const token = crypto.randomBytes(32).toString('hex');
        const expiry = Date.now() + (this.zones[zoneName]?.sessionTimeout || 3600000);
        
        this.zoneSessions.set(`token:${token}`, {
            zone: zoneName,
            userId,
            expiry,
            created: new Date()
        });

        return { token, expiry };
    }

    /**
     * Valider un token de zone
     */
    validateZoneToken(token, zoneName) {
        const session = this.zoneSessions.get(`token:${token}`);
        
        if (!session) return { valid: false, reason: 'Token not found' };
        if (session.zone !== zoneName) return { valid: false, reason: 'Token zone mismatch' };
        if (Date.now() > session.expiry) return { valid: false, reason: 'Token expired' };

        return { valid: true, session };
    }

    /**
     * Obtenir les stats de toutes les zones
     */
    getZoneStats() {
        return {
            zones: Object.entries(this.zones).map(([name, config]) => ({
                name,
                level: config.level,
                color: config.color,
                stats: this.zoneStats[name],
                isolated: config.isolated,
                requiresAuth: config.requiresAuth,
                requiresTor: config.requiresTor
            })),
            totalBreachAttempts: Object.values(this.zoneStats).reduce((sum, z) => sum + z.breachAttempts, 0),
            recentAuditLog: this.auditLog.slice(-20)
        };
    }

    /**
     * Obtenir le log d'audit
     */
    getAuditLog(count = 100) {
        return this.auditLog.slice(-count);
    }

    /**
     * Configuration de sécurité recommandée
     */
    getSecurityRecommendations() {
        return {
            isolation: {
                docker: 'Utiliser Docker pour conteneuriser le backend et le frontend séparément',
                network: 'Créer des réseaux Docker isolés pour chaque zone',
                volumes: 'Utiliser des volumes séparés pour les données sensibles'
            },
            zones: {
                public: 'Zone exposée - Minimiser les fonctionnalités',
                chat: 'Zone authentifiée - Session tokens + HTTPS',
                osint: 'Zone spécialisée - Tor obligatoire + Trace clearing',
                finance: 'Zone critique - MFA + IP Whitelist + Encryption + Audit',
                admin: 'Zone super-critique - Localhost only + MFA + Audit complet'
            },
            recommendations: [
                'Activer HTTPS sur toutes les communications',
                'Utiliser des secrets différents par zone',
                'Implémenter MFA pour les zones finance et admin',
                'Logger toutes les actions dans les zones critiques',
                'Effectuer des backups chiffrés réguliers',
                'Segmenter le réseau avec des VLANs si possible',
                'Utiliser un WAF devant l application'
            ]
        };
    }
}

module.exports = SecurityZoneService;
