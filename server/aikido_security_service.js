/**
 * Aikido Security Service - Intégration API pour le scan de vulnérabilités
 * Documentation: https://apidocs.aikido.dev
 * 
 * TEMPORARILY DISABLED - Token needs to be updated
 */

class AikidoSecurityService {
    constructor() {
        this.apiToken = process.env.AIKIDO_API_TOKEN;
        this.apiUrl = 'https://app.aikido.dev/api/public/v1';
        this.ideApiUrl = 'https://ide.aikido.dev';
        this.region = 'eu';
        
        // Check if token is valid (basic check)
        this.enabled = !!(this.apiToken && this.apiToken.length > 20);
        
        if (this.enabled) {
            console.log('[AIKIDO] Service initialized with IDE token');
        } else {
            console.log('[AIKIDO] Service DISABLED - No valid token configured');
        }
    }

    /**
     * Requête API authentifiée avec le token IDE
     */
    async apiRequest(endpoint, method = 'GET', body = null, useIdeApi = false) {
        // Skip if disabled
        if (!this.enabled) {
            return { disabled: true, message: 'Aikido temporarily disabled' };
        }
        
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
                // Silent fail on 401 - token invalid
                if (response.status === 401) {
                    this.enabled = false;
                    console.log('[AIKIDO] Token invalid - Service now disabled');
                    return { disabled: true, message: 'Token invalid' };
                }
                throw new Error(`API error ${response.status}: ${errorText}`);
            }

            return response.json();
        } catch (error) {
            // Silent fail
            return { error: error.message };
        }
    }

    async getWorkspaceInfo() {
        if (!this.enabled) return { disabled: true };
        try {
            return await this.apiRequest('/workspace');
        } catch (error) {
            return { error: error.message };
        }
    }

    async getOpenIssues(page = 0, pageSize = 25) {
        if (!this.enabled) return { issues: [], disabled: true };
        try {
            const params = new URLSearchParams({
                page: page.toString(),
                page_size: pageSize.toString()
            });
            return await this.apiRequest(`/issues/groups?${params}`);
        } catch (error) {
            return { issues: [], error: error.message };
        }
    }

    async getIssueDetails(issueGroupId) {
        if (!this.enabled) return { disabled: true };
        try {
            return await this.apiRequest(`/issues/groups/${issueGroupId}`);
        } catch (error) {
            return { error: error.message };
        }
    }

    async exportIssues(format = 'json') {
        if (!this.enabled) return { disabled: true };
        try {
            return await this.apiRequest(`/issues/export?format=${format}`);
        } catch (error) {
            return { error: error.message };
        }
    }

    async getRepositories() {
        if (!this.enabled) return { repositories: [], disabled: true };
        try {
            return await this.apiRequest('/code_repos');
        } catch (error) {
            return { repositories: [], error: error.message };
        }
    }

    async getSBOM(repoId) {
        if (!this.enabled) return { disabled: true };
        try {
            return await this.apiRequest(`/code_repos/${repoId}/sbom`);
        } catch (error) {
            return { error: error.message };
        }
    }

    async getCIScans(page = 0) {
        if (!this.enabled) return { scans: [], disabled: true };
        try {
            return await this.apiRequest(`/reports/ci_scans?page=${page}`);
        } catch (error) {
            return { scans: [], error: error.message };
        }
    }

    async getSOC2Compliance() {
        if (!this.enabled) return { disabled: true };
        try {
            return await this.apiRequest('/compliance/soc2');
        } catch (error) {
            return { error: error.message };
        }
    }

    async getISO27001Compliance() {
        if (!this.enabled) return { disabled: true };
        try {
            return await this.apiRequest('/compliance/iso27001');
        } catch (error) {
            return { error: error.message };
        }
    }

    async getTeams() {
        if (!this.enabled) return { teams: [], disabled: true };
        try {
            return await this.apiRequest('/teams');
        } catch (error) {
            return { teams: [], error: error.message };
        }
    }

    async generateReport() {
        if (!this.enabled) return { disabled: true };
        try {
            return await this.apiRequest('/reports/pdf');
        } catch (error) {
            return { error: error.message };
        }
    }

    async getSecuritySummary() {
        if (!this.enabled) {
            return { 
                success: false, 
                disabled: true,
                message: 'Aikido temporarily disabled - update token in .env',
                stats: { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
                repoCount: 0,
                recentIssues: []
            };
        }
        
        try {
            const [workspace, issues, repos] = await Promise.all([
                this.getWorkspaceInfo(),
                this.getOpenIssues(0, 100),
                this.getRepositories()
            ]);

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
