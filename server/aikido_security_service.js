/**
 * Aikido Security Service - Intégration API pour le scan de vulnérabilités
 * Documentation: https://apidocs.aikido.dev
 */

class AikidoSecurityService {
    constructor() {
        this.apiUrl = 'https://app.aikido.dev/api/public/v1';
        this.clientId = process.env.AIKIDO_CLIENT_ID;
        this.clientSecret = process.env.AIKIDO_CLIENT_SECRET;
        this.accessToken = null;
        this.tokenExpiry = null;
        
        console.log('[AIKIDO] Service initialized');
    }

    /**
     * Obtenir un access token OAuth2
     */
    async getAccessToken() {
        // Si on a un token valide, le réutiliser
        if (this.accessToken && this.tokenExpiry && Date.now() < this.tokenExpiry) {
            return this.accessToken;
        }

        try {
            const response = await fetch(`${this.apiUrl}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    grant_type: 'client_credentials',
                    client_id: this.clientId,
                    client_secret: this.clientSecret
                })
            });

            if (!response.ok) {
                throw new Error(`Auth failed: ${response.status}`);
            }

            const data = await response.json();
            this.accessToken = data.access_token;
            // Token valide 1h, on refresh 5min avant
            this.tokenExpiry = Date.now() + (data.expires_in - 300) * 1000;
            
            console.log('[AIKIDO] Access token obtained');
            return this.accessToken;

        } catch (error) {
            console.error('[AIKIDO] Auth error:', error.message);
            throw error;
        }
    }

    /**
     * Requête API authentifiée
     */
    async apiRequest(endpoint, method = 'GET', body = null) {
        const token = await this.getAccessToken();
        
        const options = {
            method,
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        };

        if (body) {
            options.body = JSON.stringify(body);
        }

        const response = await fetch(`${this.apiUrl}${endpoint}`, options);
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`API error ${response.status}: ${errorText}`);
        }

        return response.json();
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
