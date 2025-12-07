/**
 * Connection Security Service pour Th3 Thirty3
 * Protection des connexions Cloud et Locales contre les intrusions
 * Sécurisation des APIs, LLMs, et communications
 */

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const EventEmitter = require('events');

class ConnectionSecurityService extends EventEmitter {
    constructor() {
        super();
        
        this.securityLevel = process.env.SECURITY_LEVEL || 'high';
        this.dataPath = path.join(__dirname, 'data', 'security');
        
        // Règles de sécurité
        this.rules = {
            // IPs bloquées
            blockedIPs: new Set(),
            // Domaines de confiance
            trustedDomains: new Set([
                'localhost',
                '127.0.0.1',
                'api.openai.com',
                'generativelanguage.googleapis.com',
                'api.groq.com',
                'api.kraken.com',
                'api.aikido.dev',
                'ollama.local'
            ]),
            // Headers de sécurité requis
            requiredHeaders: ['x-api-key', 'authorization'],
            // Rate limiting
            rateLimit: {
                maxRequests: 100,
                windowMs: 60000 // 1 minute
            }
        };

        // Tracking des requêtes
        this.requestLog = new Map();
        this.securityEvents = [];
        
        // Stats
        this.stats = {
            requestsAllowed: 0,
            requestsBlocked: 0,
            suspiciousActivities: 0,
            intrusionAttempts: 0
        };

        this.ensureDataFolder();
        this.loadBlocklist();
        
        console.log(`[SECURITY] Service initialized - Level: ${this.securityLevel.toUpperCase()}`);
    }

    async ensureDataFolder() {
        try {
            await fs.mkdir(this.dataPath, { recursive: true });
        } catch (error) {
            // Ignore if exists
        }
    }

    async loadBlocklist() {
        try {
            const blocklistPath = path.join(this.dataPath, 'blocklist.json');
            const data = await fs.readFile(blocklistPath, 'utf8');
            const blocklist = JSON.parse(data);
            blocklist.ips.forEach(ip => this.rules.blockedIPs.add(ip));
            console.log(`[SECURITY] Loaded ${this.rules.blockedIPs.size} blocked IPs`);
        } catch {
            // No blocklist yet
        }
    }

    async saveBlocklist() {
        const blocklistPath = path.join(this.dataPath, 'blocklist.json');
        await fs.writeFile(blocklistPath, JSON.stringify({
            ips: Array.from(this.rules.blockedIPs),
            lastUpdated: new Date().toISOString()
        }, null, 2));
    }

    /**
     * Middleware Express pour sécuriser les requêtes
     */
    securityMiddleware() {
        return (req, res, next) => {
            const clientIP = req.ip || req.connection.remoteAddress;
            const userAgent = req.headers['user-agent'] || '';
            const path = req.path;

            // 1. Vérifier IP bloquée
            if (this.isIPBlocked(clientIP)) {
                this.stats.requestsBlocked++;
                this.logSecurityEvent('BLOCKED_IP', { ip: clientIP, path });
                return res.status(403).json({
                    error: 'Access denied',
                    reason: 'IP blocked'
                });
            }

            // 2. Rate limiting
            if (!this.checkRateLimit(clientIP)) {
                this.stats.requestsBlocked++;
                this.logSecurityEvent('RATE_LIMITED', { ip: clientIP });
                return res.status(429).json({
                    error: 'Too many requests',
                    retryAfter: 60
                });
            }

            // 3. Détection de patterns suspects
            const suspiciousPatterns = this.detectSuspiciousPatterns(req);
            if (suspiciousPatterns.length > 0) {
                this.stats.suspiciousActivities++;
                this.logSecurityEvent('SUSPICIOUS_PATTERN', {
                    ip: clientIP,
                    patterns: suspiciousPatterns,
                    path
                });

                if (this.securityLevel === 'paranoid') {
                    this.blockIP(clientIP);
                    return res.status(403).json({
                        error: 'Suspicious activity detected'
                    });
                }
            }

            // 4. Vérifier les headers de sécurité pour les routes sensibles
            if (this.isSensitiveRoute(path)) {
                const hasAuth = req.headers['x-api-key'] || 
                               req.headers['authorization'];
                if (!hasAuth && this.securityLevel !== 'low') {
                    this.logSecurityEvent('MISSING_AUTH', { ip: clientIP, path });
                }
            }

            // 5. Ajouter headers de sécurité à la réponse
            res.setHeader('X-Content-Type-Options', 'nosniff');
            res.setHeader('X-Frame-Options', 'DENY');
            res.setHeader('X-XSS-Protection', '1; mode=block');
            res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
            res.setHeader('Content-Security-Policy', "default-src 'self'");

            this.stats.requestsAllowed++;
            next();
        };
    }

    /**
     * Vérifier si une IP est bloquée
     */
    isIPBlocked(ip) {
        const normalizedIP = ip.replace('::ffff:', '');
        return this.rules.blockedIPs.has(normalizedIP);
    }

    /**
     * Bloquer une IP
     */
    async blockIP(ip) {
        const normalizedIP = ip.replace('::ffff:', '');
        this.rules.blockedIPs.add(normalizedIP);
        this.logSecurityEvent('IP_BLOCKED', { ip: normalizedIP });
        await this.saveBlocklist();
        console.log(`[SECURITY] 🚫 Blocked IP: ${normalizedIP}`);
    }

    /**
     * Débloquer une IP
     */
    async unblockIP(ip) {
        const normalizedIP = ip.replace('::ffff:', '');
        this.rules.blockedIPs.delete(normalizedIP);
        await this.saveBlocklist();
        console.log(`[SECURITY] ✅ Unblocked IP: ${normalizedIP}`);
    }

    /**
     * Vérifier le rate limit
     */
    checkRateLimit(ip) {
        const now = Date.now();
        const windowStart = now - this.rules.rateLimit.windowMs;
        
        if (!this.requestLog.has(ip)) {
            this.requestLog.set(ip, []);
        }

        const requests = this.requestLog.get(ip);
        const recentRequests = requests.filter(time => time > windowStart);
        recentRequests.push(now);
        this.requestLog.set(ip, recentRequests);

        return recentRequests.length <= this.rules.rateLimit.maxRequests;
    }

    /**
     * Détecter les patterns suspects
     */
    detectSuspiciousPatterns(req) {
        const suspicious = [];
        const body = JSON.stringify(req.body || {});
        const url = req.url;
        const userAgent = req.headers['user-agent'] || '';

        // SQL Injection patterns
        const sqlPatterns = [
            /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
            /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i,
            /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i,
            /(union|select|insert|update|delete|drop|alter|create|exec)/i
        ];

        // XSS patterns
        const xssPatterns = [
            /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
            /javascript:/i,
            /on\w+\s*=/i,
            /<\s*img[^>]+onerror/i
        ];

        // Path traversal
        const pathPatterns = [
            /\.\.\//g,
            /\.\.%2f/gi,
            /\.\.%5c/gi
        ];

        // Command injection
        const cmdPatterns = [
            /[;|`$()]/,
            /\b(exec|system|passthru|shell_exec|popen|proc_open)\s*\(/i
        ];

        const checkPatterns = (patterns, type) => {
            patterns.forEach(pattern => {
                if (pattern.test(body) || pattern.test(url)) {
                    suspicious.push(type);
                }
            });
        };

        checkPatterns(sqlPatterns, 'SQL_INJECTION');
        checkPatterns(xssPatterns, 'XSS');
        checkPatterns(pathPatterns, 'PATH_TRAVERSAL');
        checkPatterns(cmdPatterns, 'COMMAND_INJECTION');

        // Suspicious User-Agents
        const badAgents = ['sqlmap', 'nikto', 'nmap', 'masscan', 'hydra', 'burp'];
        if (badAgents.some(agent => userAgent.toLowerCase().includes(agent))) {
            suspicious.push('SCANNER_DETECTED');
        }

        return [...new Set(suspicious)];
    }

    /**
     * Vérifier si une route est sensible
     */
    isSensitiveRoute(path) {
        const sensitiveRoutes = [
            '/api/finance',
            '/api/kraken',
            '/api/chat',
            '/api/settings',
            '/api/sessions',
            '/api/orchestrator'
        ];
        return sensitiveRoutes.some(route => path.startsWith(route));
    }

    /**
     * Logger un événement de sécurité
     */
    logSecurityEvent(type, details) {
        const event = {
            type,
            details,
            timestamp: new Date().toISOString()
        };
        
        this.securityEvents.push(event);
        
        // Garder seulement les 1000 derniers événements
        if (this.securityEvents.length > 1000) {
            this.securityEvents = this.securityEvents.slice(-1000);
        }

        // Émettre l'événement
        this.emit('securityEvent', event);

        // Log en console pour les événements critiques
        if (['BLOCKED_IP', 'INTRUSION_ATTEMPT', 'SCANNER_DETECTED'].includes(type)) {
            console.log(`[SECURITY] 🚨 ${type}:`, JSON.stringify(details));
        }
    }

    /**
     * Sécuriser une connexion sortante (vers APIs cloud)
     */
    secureOutboundRequest(url, options = {}) {
        const urlObj = new URL(url);
        
        // Vérifier le domaine de confiance
        if (!this.rules.trustedDomains.has(urlObj.hostname)) {
            console.log(`[SECURITY] ⚠️ Untrusted domain: ${urlObj.hostname}`);
            
            if (this.securityLevel === 'paranoid') {
                throw new Error(`Untrusted domain: ${urlObj.hostname}`);
            }
        }

        // Ajouter des headers de sécurité
        const securedOptions = {
            ...options,
            headers: {
                ...options.headers,
                'X-Requested-With': 'Th3Thirty3',
                'Accept': 'application/json'
            }
        };

        // Forcer HTTPS pour les domaines non-locaux
        if (!['localhost', '127.0.0.1'].includes(urlObj.hostname)) {
            if (urlObj.protocol !== 'https:') {
                console.log(`[SECURITY] ⚠️ Non-HTTPS connection to: ${urlObj.hostname}`);
            }
        }

        return securedOptions;
    }

    /**
     * Valider une clé API
     */
    validateAPIKey(key, type = 'generic') {
        if (!key) return { valid: false, reason: 'No key provided' };

        // Vérifications de base
        if (key.length < 16) {
            return { valid: false, reason: 'Key too short' };
        }

        // Vérifier les patterns de clés connus
        const patterns = {
            openai: /^sk-[a-zA-Z0-9]{48,}$/,
            gemini: /^AIza[a-zA-Z0-9\-_]{35}$/,
            groq: /^gsk_[a-zA-Z0-9]{52}$/,
            kraken: /^[a-zA-Z0-9+\/]{56}$/
        };

        if (patterns[type] && !patterns[type].test(key)) {
            return { valid: false, reason: `Invalid ${type} key format` };
        }

        return { valid: true };
    }

    /**
     * Chiffrer des données sensibles
     */
    encrypt(data, key = process.env.ENCRYPTION_KEY) {
        if (!key) {
            key = crypto.randomBytes(32).toString('hex');
            console.log('[SECURITY] ⚠️ No encryption key set, using random key');
        }
        
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key, 'hex'), iv);
        
        let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        const authTag = cipher.getAuthTag();
        
        return {
            encrypted,
            iv: iv.toString('hex'),
            authTag: authTag.toString('hex')
        };
    }

    /**
     * Déchiffrer des données
     */
    decrypt(encryptedData, key = process.env.ENCRYPTION_KEY) {
        if (!key) throw new Error('Encryption key required');
        
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            Buffer.from(key, 'hex'),
            Buffer.from(encryptedData.iv, 'hex')
        );
        
        decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
        
        let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return JSON.parse(decrypted);
    }

    /**
     * Générer une clé de session sécurisée
     */
    generateSessionKey() {
        return crypto.randomBytes(32).toString('hex');
    }

    /**
     * Obtenir les statistiques de sécurité
     */
    getStats() {
        return {
            ...this.stats,
            securityLevel: this.securityLevel,
            blockedIPCount: this.rules.blockedIPs.size,
            trustedDomainsCount: this.rules.trustedDomains.size,
            recentEvents: this.securityEvents.slice(-20),
            rateLimit: this.rules.rateLimit
        };
    }

    /**
     * Obtenir les événements récents
     */
    getRecentEvents(count = 50) {
        return this.securityEvents.slice(-count);
    }

    /**
     * Ajouter un domaine de confiance
     */
    addTrustedDomain(domain) {
        this.rules.trustedDomains.add(domain);
        console.log(`[SECURITY] ✅ Added trusted domain: ${domain}`);
    }

    /**
     * Configuration de sécurité recommandée
     */
    getSecurityConfig() {
        return {
            recommendations: [
                'Utilisez HTTPS pour toutes les connexions cloud',
                'Activez le firewall Windows',
                'Ne partagez jamais vos clés API',
                'Utilisez Tor pour les opérations OSINT sensibles',
                'Changez régulièrement vos mots de passe',
                'Activez 2FA sur tous les comptes'
            ],
            currentSettings: {
                securityLevel: this.securityLevel,
                rateLimit: this.rules.rateLimit,
                trustedDomains: Array.from(this.rules.trustedDomains)
            },
            envVars: {
                SECURITY_LEVEL: 'low | medium | high | paranoid',
                ENCRYPTION_KEY: 'Clé de 64 caractères hex pour le chiffrement'
            }
        };
    }
}

module.exports = ConnectionSecurityService;
