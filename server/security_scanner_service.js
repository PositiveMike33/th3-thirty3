/**
 * Nexus33 Security Scanner Service
 * Service de scan de sécurité automatisé pour PME québécoises
 * 
 * @version 1.0.0
 * @author Th3 Thirty3
 */

const https = require('https');
const http = require('http');
const dns = require('dns').promises;
const tls = require('tls');
const { URL } = require('url');

class SecurityScannerService {
    constructor() {
        this.shodanService = null;
        this.gpuTrainingService = null;

        // Configuration des poids pour le score
        this.SCORE_WEIGHTS = {
            ssl: 0.25,      // 25%
            headers: 0.20,  // 20%
            dns: 0.15,      // 15%
            ports: 0.20,    // 20%
            vulns: 0.20     // 20%
        };

        // Headers de sécurité à vérifier
        this.SECURITY_HEADERS = [
            'strict-transport-security',
            'content-security-policy',
            'x-frame-options',
            'x-content-type-options',
            'x-xss-protection',
            'referrer-policy',
            'permissions-policy'
        ];

        // Ports dangereux
        this.DANGEROUS_PORTS = [21, 23, 25, 110, 143, 445, 3389, 5900];

        // Stockage des scans en cours
        this.activeScans = new Map();
        this.scanHistory = new Map();

        console.log('[SECURITY-SCANNER] Service initialized');
    }

    /**
     * Définir le service Shodan
     */
    setShodanService(shodanService) {
        this.shodanService = shodanService;
        console.log('[SECURITY-SCANNER] Shodan service connected');
    }

    /**
     * Définir le service GPU
     */
    setGpuTrainingService(gpuService) {
        this.gpuTrainingService = gpuService;
        console.log('[SECURITY-SCANNER] GPU training service connected');
    }

    /**
     * Lancer un scan complet
     * @param {string} domain - Domaine à scanner
     * @param {string} userId - ID de l'utilisateur
     * @returns {Object} - Job info avec ID
     */
    async startScan(domain, userId) {
        const scanId = `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        const scanJob = {
            id: scanId,
            domain: this.normalizeDomain(domain),
            userId,
            status: 'starting',
            progress: 0,
            startedAt: new Date().toISOString(),
            results: null,
            error: null
        };

        this.activeScans.set(scanId, scanJob);

        // Lancer le scan en arrière-plan
        this.runFullScan(scanId).catch(err => {
            console.error(`[SECURITY-SCANNER] Scan ${scanId} failed:`, err);
            scanJob.status = 'failed';
            scanJob.error = err.message;
        });

        return {
            success: true,
            scanId,
            domain: scanJob.domain,
            status: scanJob.status
        };
    }

    /**
     * Normaliser le domaine (enlever http://, www., etc.)
     */
    normalizeDomain(domain) {
        let normalized = domain.toLowerCase().trim();
        normalized = normalized.replace(/^https?:\/\//, '');
        normalized = normalized.replace(/^www\./, '');
        normalized = normalized.split('/')[0];
        return normalized;
    }

    /**
     * Exécuter le scan complet
     */
    async runFullScan(scanId) {
        const scan = this.activeScans.get(scanId);
        if (!scan) return;

        scan.status = 'running';
        const results = {};

        try {
            // Étape 1: SSL/TLS (25%)
            scan.progress = 10;
            scan.currentStep = 'ssl';
            results.ssl = await this.scanSSL(scan.domain);
            scan.progress = 25;

            // Étape 2: Headers HTTP (20%)
            scan.currentStep = 'headers';
            results.headers = await this.scanHeaders(scan.domain);
            scan.progress = 45;

            // Étape 3: DNS (15%)
            scan.currentStep = 'dns';
            results.dns = await this.scanDNS(scan.domain);
            scan.progress = 60;

            // Étape 4: Ports via Shodan (20%)
            scan.currentStep = 'ports';
            results.ports = await this.scanWithShodan(scan.domain);
            scan.progress = 80;

            // Étape 5: Analyse vulnérabilités (20%)
            scan.currentStep = 'vulns';
            results.vulnerabilities = await this.analyzeVulnerabilities(results);
            scan.progress = 95;

            // Calculer le score global
            results.score = this.calculateScore(results);
            results.grade = this.scoreToGrade(results.score);

            // Générer les recommandations
            results.recommendations = this.generateRecommendations(results);

            scan.progress = 100;
            scan.status = 'completed';
            scan.results = results;
            scan.completedAt = new Date().toISOString();

            // Sauvegarder dans l'historique
            if (!this.scanHistory.has(scan.userId)) {
                this.scanHistory.set(scan.userId, []);
            }
            this.scanHistory.get(scan.userId).push(scan);

            console.log(`[SECURITY-SCANNER] Scan ${scanId} completed - Score: ${results.score}/100 (${results.grade})`);

        } catch (error) {
            scan.status = 'failed';
            scan.error = error.message;
            console.error(`[SECURITY-SCANNER] Scan ${scanId} error:`, error);
        }

        return scan;
    }

    /**
     * Scanner SSL/TLS
     * @param {string} domain
     * @returns {Object} Résultats SSL
     */
    async scanSSL(domain) {
        const result = {
            score: 0,
            valid: false,
            issuer: null,
            subject: null,
            expiry: null,
            daysUntilExpiry: null,
            protocol: null,
            issues: []
        };

        try {
            const certInfo = await this.getCertificateInfo(domain);

            if (certInfo.error) {
                result.issues.push(certInfo.error);
                result.score = 0;
                return result;
            }

            result.valid = certInfo.valid;
            result.issuer = certInfo.issuer;
            result.subject = certInfo.subject;
            result.expiry = certInfo.expiry;
            result.daysUntilExpiry = certInfo.daysUntilExpiry;
            result.protocol = certInfo.protocol;

            // Calculer le score SSL
            let score = 0;

            // Certificat valide (+40 points)
            if (certInfo.valid) {
                score += 40;
            } else {
                result.issues.push('Certificat SSL invalide');
            }

            // Expiration (+30 points)
            if (certInfo.daysUntilExpiry > 30) {
                score += 30;
            } else if (certInfo.daysUntilExpiry > 7) {
                score += 15;
                result.issues.push('Certificat expire dans moins de 30 jours');
            } else if (certInfo.daysUntilExpiry > 0) {
                score += 5;
                result.issues.push('Certificat expire dans moins de 7 jours - URGENT');
            } else {
                result.issues.push('Certificat expiré!');
            }

            // Protocole TLS moderne (+30 points)
            if (certInfo.protocol === 'TLSv1.3') {
                score += 30;
            } else if (certInfo.protocol === 'TLSv1.2') {
                score += 25;
                result.issues.push('Recommandé: Activer TLS 1.3');
            } else {
                score += 10;
                result.issues.push('Protocole TLS obsolète - Mettre à jour immédiatement');
            }

            result.score = Math.min(100, score);

        } catch (error) {
            result.issues.push(`Erreur SSL: ${error.message}`);
            result.score = 0;
        }

        return result;
    }

    /**
     * Obtenir les informations du certificat
     */
    getCertificateInfo(domain) {
        return new Promise((resolve) => {
            const options = {
                host: domain,
                port: 443,
                method: 'GET',
                rejectUnauthorized: false,
                timeout: 10000
            };

            const req = https.request(options, (res) => {
                const cert = res.socket.getPeerCertificate();
                const protocol = res.socket.getProtocol ? res.socket.getProtocol() : 'unknown';

                if (cert && Object.keys(cert).length > 0) {
                    const expiry = new Date(cert.valid_to);
                    const now = new Date();
                    const daysUntilExpiry = Math.floor((expiry - now) / (1000 * 60 * 60 * 24));

                    resolve({
                        valid: res.socket.authorized !== false,
                        issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown',
                        subject: cert.subject?.CN || domain,
                        expiry: cert.valid_to,
                        daysUntilExpiry,
                        protocol
                    });
                } else {
                    resolve({ error: 'Aucun certificat SSL trouvé' });
                }
            });

            req.on('error', (err) => {
                resolve({ error: `Connexion SSL échouée: ${err.message}` });
            });

            req.on('timeout', () => {
                req.destroy();
                resolve({ error: 'Timeout de connexion SSL' });
            });

            req.end();
        });
    }

    /**
     * Scanner les headers HTTP
     * @param {string} domain
     * @returns {Object} Résultats headers
     */
    async scanHeaders(domain) {
        const result = {
            score: 0,
            present: [],
            missing: [],
            values: {},
            issues: []
        };

        try {
            const headers = await this.fetchHeaders(domain);

            if (headers.error) {
                result.issues.push(headers.error);
                result.missing = [...this.SECURITY_HEADERS];
                return result;
            }

            // Vérifier chaque header de sécurité
            for (const header of this.SECURITY_HEADERS) {
                const value = headers[header];
                if (value) {
                    result.present.push(header);
                    result.values[header] = value;
                } else {
                    result.missing.push(header);
                }
            }

            // Calculer le score (chaque header vaut ~14 points)
            const pointsPerHeader = 100 / this.SECURITY_HEADERS.length;
            let score = result.present.length * pointsPerHeader;

            // Bonus/Malus pour configuration spécifique
            if (result.values['strict-transport-security']) {
                const hsts = result.values['strict-transport-security'].toLowerCase();
                if (hsts.includes('max-age=') && parseInt(hsts.match(/max-age=(\d+)/)?.[1] || 0) >= 31536000) {
                    score += 5; // HSTS avec 1 an minimum
                }
                if (hsts.includes('includesubdomains')) {
                    score += 3;
                }
            }

            if (result.values['content-security-policy']) {
                const csp = result.values['content-security-policy'].toLowerCase();
                if (csp.includes("default-src 'self'") || csp.includes('default-src self')) {
                    score += 5; // CSP restrictif
                }
            }

            // Générer les issues
            if (result.missing.includes('strict-transport-security')) {
                result.issues.push('HSTS manquant - Vulnérable aux attaques downgrade');
            }
            if (result.missing.includes('content-security-policy')) {
                result.issues.push('CSP manquant - Vulnérable aux attaques XSS');
            }
            if (result.missing.includes('x-frame-options')) {
                result.issues.push('X-Frame-Options manquant - Vulnérable au clickjacking');
            }

            result.score = Math.min(100, Math.round(score));

        } catch (error) {
            result.issues.push(`Erreur headers: ${error.message}`);
            result.missing = [...this.SECURITY_HEADERS];
        }

        return result;
    }

    /**
     * Récupérer les headers HTTP d'un domaine
     */
    fetchHeaders(domain) {
        return new Promise((resolve) => {
            const url = `https://${domain}`;

            https.get(url, { timeout: 10000 }, (res) => {
                const headers = {};
                for (const [key, value] of Object.entries(res.headers)) {
                    headers[key.toLowerCase()] = value;
                }
                resolve(headers);
            }).on('error', (err) => {
                // Essayer HTTP si HTTPS échoue
                http.get(`http://${domain}`, { timeout: 10000 }, (res) => {
                    const headers = {};
                    for (const [key, value] of Object.entries(res.headers)) {
                        headers[key.toLowerCase()] = value;
                    }
                    headers['_http_only'] = true;
                    resolve(headers);
                }).on('error', (err2) => {
                    resolve({ error: `Impossible de récupérer les headers: ${err2.message}` });
                });
            }).on('timeout', function () {
                this.destroy();
                resolve({ error: 'Timeout lors de la récupération des headers' });
            });
        });
    }

    /**
     * Scanner les enregistrements DNS
     * @param {string} domain
     * @returns {Object} Résultats DNS
     */
    async scanDNS(domain) {
        // Placeholder - sera implémenté dans micro-objectif 1.4
        return {
            score: 0,
            records: {},
            spf: false,
            dkim: false,
            dmarc: false,
            issues: ['Implementation pending']
        };
    }

    /**
     * Scanner avec Shodan
     * @param {string} domain
     * @returns {Object} Résultats ports
     */
    async scanWithShodan(domain) {
        // Placeholder - sera implémenté dans micro-objectif 1.5
        return {
            score: 100,
            ports: [],
            services: [],
            dangerousPorts: [],
            issues: []
        };
    }

    /**
     * Analyser les vulnérabilités
     * @param {Object} allResults
     * @returns {Object} Vulnérabilités détectées
     */
    async analyzeVulnerabilities(allResults) {
        // Placeholder - sera implémenté après GPU integration
        return {
            score: 100,
            critical: [],
            high: [],
            medium: [],
            low: [],
            total: 0
        };
    }

    /**
     * Calculer le score global
     * @param {Object} results
     * @returns {number} Score 0-100
     */
    calculateScore(results) {
        // Placeholder - sera implémenté dans micro-objectif 1.6
        const scores = {
            ssl: results.ssl?.score || 0,
            headers: results.headers?.score || 0,
            dns: results.dns?.score || 0,
            ports: results.ports?.score || 100,
            vulns: results.vulnerabilities?.score || 100
        };

        let totalScore = 0;
        for (const [key, weight] of Object.entries(this.SCORE_WEIGHTS)) {
            totalScore += (scores[key] || 0) * weight;
        }

        return Math.round(totalScore);
    }

    /**
     * Convertir score en grade
     */
    scoreToGrade(score) {
        if (score >= 90) return 'A+';
        if (score >= 80) return 'A';
        if (score >= 70) return 'B';
        if (score >= 60) return 'C';
        if (score >= 50) return 'D';
        return 'F';
    }

    /**
     * Générer des recommandations
     */
    generateRecommendations(results) {
        const recommendations = [];

        if (results.ssl?.score < 80) {
            recommendations.push({
                priority: 'high',
                category: 'ssl',
                title: 'Améliorer la configuration SSL/TLS',
                description: 'Votre certificat SSL nécessite des améliorations pour une meilleure sécurité.'
            });
        }

        if (results.headers?.missing?.length > 0) {
            recommendations.push({
                priority: 'medium',
                category: 'headers',
                title: 'Ajouter les headers de sécurité manquants',
                description: `Headers manquants: ${results.headers.missing.join(', ')}`
            });
        }

        if (results.ports?.dangerousPorts?.length > 0) {
            recommendations.push({
                priority: 'critical',
                category: 'ports',
                title: 'Fermer les ports dangereux',
                description: `Ports exposés à risque: ${results.ports.dangerousPorts.join(', ')}`
            });
        }

        return recommendations;
    }

    /**
     * Obtenir le statut d'un scan
     */
    getScanStatus(scanId) {
        const scan = this.activeScans.get(scanId);
        if (!scan) {
            return { error: 'Scan not found' };
        }
        return {
            id: scan.id,
            domain: scan.domain,
            status: scan.status,
            progress: scan.progress,
            currentStep: scan.currentStep,
            startedAt: scan.startedAt,
            completedAt: scan.completedAt,
            results: scan.results,
            error: scan.error
        };
    }

    /**
     * Obtenir l'historique des scans d'un utilisateur
     */
    getScanHistory(userId, limit = 10) {
        const history = this.scanHistory.get(userId) || [];
        return history.slice(-limit).reverse();
    }

    /**
     * Test de santé du service
     */
    healthCheck() {
        return {
            status: 'healthy',
            activeScans: this.activeScans.size,
            shodanConnected: !!this.shodanService,
            gpuConnected: !!this.gpuTrainingService
        };
    }
}

module.exports = SecurityScannerService;
