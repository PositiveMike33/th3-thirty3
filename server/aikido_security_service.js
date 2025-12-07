/**
 * Aikido Security Service - Intégration API pour le scan de vulnérabilités
 * Documentation: https://apidocs.aikido.dev
 */

class AikidoSecurityService {
    constructor() {
        // Utiliser le token IDE fourni
        this.apiToken = process.env.AIKIDO_API_TOKEN;
        this.apiUrl = 'https://app.aikido.dev/api/public/v1';
        this.ideApiUrl = 'https://ide.aikido.dev';
        
        // Région extraite du token (eu)
        this.region = 'eu';
        
        console.log('[AIKIDO] Service initialized with IDE token');
    }

    /**
     * Requête API authentifiée avec le token IDE
     */
    async apiRequest(endpoint, method = 'GET', body = null, useIdeApi = false) {
        const baseUrl = useIdeApi ? this.ideApiUrl : this.apiUrl;
        
        const options = {
            method,
            headers: {
                'Authorization': `Bearer ${this.apiToken}`,
                'Content-Type': 'application/json'
            }
        };

        if (body) {
            options.body = JSON.stringify(body);
        }

        try {
            const response = await fetch(`${baseUrl}${endpoint}`, options);
            
            if (!response.ok) {
                const errorText = await response.text();
                console.error(`[AIKIDO] API error ${response.status}:`, errorText);
                throw new Error(`API error ${response.status}: ${errorText}`);
            }

            return response.json();
        } catch (error) {
            console.error('[AIKIDO] Request error:', error.message);
            throw error;
        }
    }

    /**
     * Récupérer les infos du workspace
     */
    async getWorkspaceInfo() {
        try {
            return await this.apiRequest('/workspace');
        } catch (error) {
            console.error('[AIKIDO] Workspace info error:', error.message);
            return { error: error.message };
        }
    }

    /**
     * Lister tous les issues de sécurité ouverts
     */
    async getOpenIssues(page = 0, pageSize = 25) {
        try {
            const params = new URLSearchParams({
                page: page.toString(),
                page_size: pageSize.toString()
            });
            return await this.apiRequest(`/issues/groups?${params}`);
        } catch (error) {
            console.error('[AIKIDO] Get issues error:', error.message);
            return { issues: [], error: error.message };
        }
    }

    /**
     * Récupérer les détails d'un groupe d'issues
     */
    async getIssueDetails(issueGroupId) {
        try {
            return await this.apiRequest(`/issues/groups/${issueGroupId}`);
        } catch (error) {
            console.error('[AIKIDO] Issue details error:', error.message);
            return { error: error.message };
        }
    }

    /**
     * Exporter tous les issues (CSV/JSON)
     */
    async exportIssues(format = 'json') {
        try {
            return await this.apiRequest(`/issues/export?format=${format}`);
        } catch (error) {
            console.error('[AIKIDO] Export issues error:', error.message);
            return { error: error.message };
        }
    }

    /**
     * Lister les repositories scannés
     */
    async getRepositories() {
        try {
            return await this.apiRequest('/code_repos');
        } catch (error) {
            console.error('[AIKIDO] Get repos error:', error.message);
            return { repositories: [], error: error.message };
        }
    }

    /**
     * Obtenir le SBOM (Software Bill of Materials) d'un repo
     */
    async getSBOM(repoId) {
        try {
            return await this.apiRequest(`/code_repos/${repoId}/sbom`);
        } catch (error) {
            console.error('[AIKIDO] SBOM error:', error.message);
            return { error: error.message };
        }
    }

    /**
     * Lister les scans CI/CD récents
     */
    async getCIScans(page = 0) {
        try {
            return await this.apiRequest(`/reports/ci_scans?page=${page}`);
        } catch (error) {
            console.error('[AIKIDO] CI scans error:', error.message);
            return { scans: [], error: error.message };
        }
    }

    /**
     * Obtenir le statut de conformité SOC2
     */
    async getSOC2Compliance() {
        try {
            return await this.apiRequest('/compliance/soc2');
        } catch (error) {
            console.error('[AIKIDO] SOC2 compliance error:', error.message);
            return { error: error.message };
        }
    }

    /**
     * Obtenir le statut de conformité ISO 27001
     */
    async getISO27001Compliance() {
        try {
            return await this.apiRequest('/compliance/iso27001');
        } catch (error) {
            console.error('[AIKIDO] ISO 27001 compliance error:', error.message);
            return { error: error.message };
        }
    }

    /**
     * Lister les équipes
     */
    async getTeams() {
        try {
            return await this.apiRequest('/teams');
        } catch (error) {
            console.error('[AIKIDO] Get teams error:', error.message);
            return { teams: [], error: error.message };
        }
    }

    /**
     * Générer un rapport PDF
     */
    async generateReport() {
        try {
            return await this.apiRequest('/reports/pdf');
        } catch (error) {
            console.error('[AIKIDO] Generate report error:', error.message);
            return { error: error.message };
        }
    }

    /**
     * Résumé de sécurité pour le dashboard
     */
    async getSecuritySummary() {
        try {
            const [workspace, issues, repos] = await Promise.all([
                this.getWorkspaceInfo(),
                this.getOpenIssues(0, 100),
                this.getRepositories()
            ]);

            // Calculer les stats par sévérité
            const issueList = issues.groups || issues.issues || [];
            const stats = {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                total: issueList.length
            };

            issueList.forEach(issue => {
                const severity = (issue.severity || '').toLowerCase();
                if (stats[severity] !== undefined) {
                    stats[severity]++;
                }
            });

            return {
                success: true,
                workspace: workspace.name || 'positivemike33',
                stats,
                repoCount: (repos.repositories || repos.code_repos || []).length,
                recentIssues: issueList.slice(0, 5)
            };

        } catch (error) {
            console.error('[AIKIDO] Security summary error:', error.message);
            return { 
                success: false, 
                error: error.message,
                stats: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
                repoCount: 0,
                recentIssues: []
            };
        }
    }
}

module.exports = AikidoSecurityService;
