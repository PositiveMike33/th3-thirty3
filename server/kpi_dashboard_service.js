/**
 * KPI Dashboard Service - Pilier XI du Codex Operandi
 * SOC Personnel : Agrégation des métriques sécu/productivité/bio/conformité
 */

const AikidoSecurityService = require('./aikido_security_service');

class KPIDashboardService {
    constructor() {
        this.aikido = new AikidoSecurityService();
        console.log('[KPI-DASHBOARD] Service initialized');
    }

    /**
     * Obtenir le résumé global du Dashboard
     */
    async getDashboardSummary() {
        const [security, productivity, bio, compliance] = await Promise.all([
            this.getSecurityMetrics(),
            this.getProductivityMetrics(),
            this.getBioMetrics(),
            this.getComplianceMetrics()
        ]);

        // Calculer l'Indice de Souveraineté Global
        const sovereigntyIndex = this.calculateSovereigntyIndex(security, productivity, bio, compliance);

        return {
            success: true,
            timestamp: new Date().toISOString(),
            sovereigntyIndex,
            metrics: {
                security,
                productivity,
                bio,
                compliance
            }
        };
    }

    /**
     * Métriques de Sécurité (Aikido + Alertes)
     */
    async getSecurityMetrics() {
        try {
            const aikidoSummary = await this.aikido.getSecuritySummary();
            
            return {
                status: this.getSecurityStatus(aikidoSummary.stats),
                aikido: {
                    critical: aikidoSummary.stats?.critical || 0,
                    high: aikidoSummary.stats?.high || 0,
                    medium: aikidoSummary.stats?.medium || 0,
                    low: aikidoSummary.stats?.low || 0,
                    total: aikidoSummary.stats?.total || 0,
                    repoCount: aikidoSummary.repoCount || 0
                },
                alerts: {
                    last24h: 0, // À implémenter avec les logs
                    unresolved: 0
                },
                lastScan: new Date().toISOString()
            };
        } catch (error) {
            console.error('[KPI] Security metrics error:', error.message);
            return {
                status: 'unknown',
                aikido: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
                alerts: { last24h: 0, unresolved: 0 },
                error: error.message
            };
        }
    }

    /**
     * Déterminer le status de sécurité global
     */
    getSecurityStatus(stats) {
        if (!stats) return 'unknown';
        if (stats.critical > 0) return 'critical';
        if (stats.high > 0) return 'warning';
        if (stats.medium > 0) return 'caution';
        return 'secure';
    }

    /**
     * Métriques de Productivité
     */
    async getProductivityMetrics() {
        // Ces données peuvent venir de différentes sources
        // Pour l'instant, structure de base
        return {
            status: 'active',
            tasksCompleted: {
                today: 0,
                week: 0
            },
            focusTime: {
                today: 0, // minutes
                target: 240 // 4 heures objectif
            },
            commits: {
                today: 0,
                week: 0
            },
            // Ratio temps proactif vs réactif
            proactiveRatio: 0.7
        };
    }

    /**
     * Métriques Bio-Optimisation
     */
    async getBioMetrics() {
        // Structure pour le tracking biologique (Pilier bio du Codex)
        return {
            status: 'optimal',
            stack: {
                // Stack de suppléments du jour (à remplir manuellement ou via API)
                items: [],
                completed: false
            },
            sleep: {
                lastNight: null, // heures
                quality: null, // 1-10
                target: 7.5
            },
            energy: {
                current: null, // 1-10
                trend: 'stable' // up/stable/down
            },
            mentalClarity: {
                current: null, // 1-10
                fogReported: false
            }
        };
    }

    /**
     * Métriques de Conformité (Loi 25, Fiscalité)
     */
    async getComplianceMetrics() {
        const now = new Date();
        
        return {
            status: 'compliant',
            loi25: {
                nextDeadline: null,
                tasksRemaining: 0
            },
            fiscal: {
                tpsDeadline: this.getNextQuarterEnd(now),
                tvqDeadline: this.getNextQuarterEnd(now),
                daysRemaining: this.getDaysToQuarterEnd(now)
            },
            contracts: {
                active: 0,
                pendingSignature: 0
            }
        };
    }

    /**
     * Calculer l'Indice de Souveraineté Global (0-100)
     */
    calculateSovereigntyIndex(security, productivity, bio, compliance) {
        let score = 100;

        // Pénalités sécurité
        if (security.status === 'critical') score -= 40;
        else if (security.status === 'warning') score -= 20;
        else if (security.status === 'caution') score -= 10;

        // Bonus productivité
        if (productivity.proactiveRatio >= 0.7) score += 5;

        // Pénalités conformité
        if (compliance.status !== 'compliant') score -= 15;

        // Pénalités bio
        if (bio.mentalClarity?.fogReported) score -= 10;

        return Math.max(0, Math.min(100, score));
    }

    /**
     * Prochaine fin de trimestre fiscal
     */
    getNextQuarterEnd(date) {
        const quarter = Math.floor(date.getMonth() / 3);
        const nextQuarterEnd = new Date(date.getFullYear(), (quarter + 1) * 3, 0);
        return nextQuarterEnd.toISOString().split('T')[0];
    }

    getDaysToQuarterEnd(date) {
        const quarterEnd = new Date(this.getNextQuarterEnd(date));
        const diffTime = quarterEnd.getTime() - date.getTime();
        return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    }

    /**
     * Mettre à jour les métriques Bio manuellement
     */
    async updateBioMetrics(data) {
        // Stocker dans un fichier JSON local ou DB
        const fs = require('fs').promises;
        const bioPath = './data/bio_metrics.json';
        
        try {
            let existing = {};
            try {
                const content = await fs.readFile(bioPath, 'utf-8');
                existing = JSON.parse(content);
            } catch {}

            const updated = {
                ...existing,
                ...data,
                lastUpdated: new Date().toISOString()
            };

            await fs.writeFile(bioPath, JSON.stringify(updated, null, 2));
            return { success: true, data: updated };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * Générer le rapport OODA pour la revue hebdomadaire (Pilier XVIII)
     */
    async generateWeeklyReport() {
        const summary = await this.getDashboardSummary();

        return {
            period: 'weekly',
            generatedAt: new Date().toISOString(),
            sovereigntyIndex: summary.sovereigntyIndex,
            sections: {
                observe: {
                    securityAlerts: summary.metrics.security.alerts,
                    aikidoStats: summary.metrics.security.aikido,
                    productivityTrend: summary.metrics.productivity.proactiveRatio
                },
                orient: {
                    threats: this.identifyThreats(summary.metrics),
                    opportunities: this.identifyOpportunities(summary.metrics)
                },
                decide: {
                    priorityActions: this.generatePriorityActions(summary.metrics)
                },
                act: {
                    nextWeekFocus: []
                }
            },
            questions: [
                "Ai-je résolu les alertes critiques de sécurité?",
                "Mon ratio proactif/réactif est-il satisfaisant?",
                "Ai-je maintenu la fréquence vibratoire cible?"
            ]
        };
    }

    identifyThreats(metrics) {
        const threats = [];
        if (metrics.security.aikido.critical > 0) {
            threats.push('Vulnérabilités critiques non-résolues');
        }
        if (metrics.compliance.fiscal.daysRemaining < 30) {
            threats.push('Deadline fiscale proche');
        }
        return threats;
    }

    identifyOpportunities(metrics) {
        const opportunities = [];
        if (metrics.productivity.proactiveRatio > 0.8) {
            opportunities.push('Haute productivité - augmenter la charge');
        }
        return opportunities;
    }

    generatePriorityActions(metrics) {
        const actions = [];
        if (metrics.security.status !== 'secure') {
            actions.push({
                priority: 1,
                action: 'Résoudre les vulnérabilités Aikido',
                deadline: 'Immédiat'
            });
        }
        return actions;
    }
}

module.exports = KPIDashboardService;
