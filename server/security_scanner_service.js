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
        // Placeholder - sera implémenté dans micro-objectif 1.2
        return {
            score: 0,
            valid: false,
            issuer: null,
            expiry: null,
            protocol: null,
            issues: ['Implementation pending']
        };
    }

    /**
     * Scanner les headers HTTP
     * @param {string} domain
     * @returns {Object} Résultats headers
     */
    async scanHeaders(domain) {
        // Placeholder - sera implémenté dans micro-objectif 1.3
        return {
            score: 0,
            present: [],
            missing: this.SECURITY_HEADERS,
            issues: ['Implementation pending']
        };
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
