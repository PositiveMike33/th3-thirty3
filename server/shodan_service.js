/**
 * Shodan Integration Service
 * Provides real-world cybersecurity data for AI model training
 * Integrates with Shodan API for OSINT, vulnerability scanning, and threat intelligence
 */

const EventEmitter = require('events');

class ShodanService extends EventEmitter {
    constructor() {
        super();
        // API Key from environment or direct config
        this.apiKey = process.env.SHODAN_API_KEY || 'x46zkt0GTF76rJV2lgSrwIVVRkPb0io8';
        this.baseUrl = 'https://api.shodan.io';
        this.cache = new Map();
        this.cacheExpiry = 15 * 60 * 1000; // 15 minutes
        
        // Training data categories
        this.trainingCategories = {
            vulnerability_analysis: [],
            network_reconnaissance: [],
            service_identification: [],
            threat_intelligence: [],
            exploit_research: []
        };
        
        console.log('[SHODAN] Service initialized');
    }

    /**
     * Make API request to Shodan
     */
    async makeRequest(endpoint, params = {}) {
        const url = new URL(`${this.baseUrl}${endpoint}`);
        url.searchParams.append('key', this.apiKey);
        
        for (const [key, value] of Object.entries(params)) {
            url.searchParams.append(key, value);
        }

        try {
            const response = await fetch(url.toString());
            if (!response.ok) {
                const error = await response.text();
                throw new Error(`Shodan API Error: ${response.status} - ${error}`);
            }
            return await response.json();
        } catch (error) {
            console.error('[SHODAN] API Request failed:', error.message);
            throw error;
        }
    }

    /**
     * Get account info and API credits
     */
    async getAccountInfo() {
        const cacheKey = 'account_info';
        if (this.cache.has(cacheKey)) {
            const cached = this.cache.get(cacheKey);
            if (Date.now() - cached.timestamp < this.cacheExpiry) {
                return cached.data;
            }
        }

        const data = await this.makeRequest('/api-info');
        this.cache.set(cacheKey, { data, timestamp: Date.now() });
        return data;
    }

    /**
     * Search Shodan for hosts
     */
    async search(query, page = 1) {
        return await this.makeRequest('/shodan/host/search', { query, page });
    }

    /**
     * Get host information by IP
     */
    async getHost(ip) {
        return await this.makeRequest(`/shodan/host/${ip}`);
    }

    /**
     * Get DNS information for a domain
     */
    async getDnsResolve(hostnames) {
        const hosts = Array.isArray(hostnames) ? hostnames.join(',') : hostnames;
        return await this.makeRequest('/dns/resolve', { hostnames: hosts });
    }

    /**
     * Reverse DNS lookup
     */
    async getReverseDns(ips) {
        const ipList = Array.isArray(ips) ? ips.join(',') : ips;
        return await this.makeRequest('/dns/reverse', { ips: ipList });
    }

    /**
     * Get my public IP
     */
    async getMyIp() {
        return await this.makeRequest('/tools/myip');
    }

    /**
     * Search for exploits
     */
    async searchExploits(query) {
        const url = `https://exploits.shodan.io/api/search?query=${encodeURIComponent(query)}&key=${this.apiKey}`;
        const response = await fetch(url);
        return await response.json();
    }

    /**
     * Get known vulnerabilities for a specific CVE
     */
    async getCVE(cve) {
        try {
            // Search for hosts affected by this CVE
            const results = await this.search(`vuln:${cve}`);
            return {
                cve,
                affectedHosts: results.total || 0,
                matches: results.matches?.slice(0, 10) || []
            };
        } catch (error) {
            return { cve, error: error.message };
        }
    }

    // ==========================================
    // AI TRAINING DATA GENERATION
    // ==========================================

    /**
     * Generate training scenarios from Shodan data
     */
    async generateTrainingData(category = 'all') {
        console.log(`[SHODAN] Generating training data for category: ${category}`);
        
        const trainingData = [];

        try {
            // Get some real-world vulnerable hosts (for analysis, not exploitation)
            const vulnerableHosts = await this.search('vuln:CVE-2021-44228', 1); // Log4j
            const exposedServices = await this.search('port:22 country:US', 1);
            const webcams = await this.search('webcam has_screenshot:true', 1);

            // Generate vulnerability analysis scenarios
            if (category === 'all' || category === 'vulnerability_analysis') {
                if (vulnerableHosts.matches) {
                    for (const host of vulnerableHosts.matches.slice(0, 5)) {
                        trainingData.push({
                            category: 'vulnerability_analysis',
                            type: 'analysis_prompt',
                            prompt: this.createVulnerabilityPrompt(host),
                            context: this.sanitizeHostData(host),
                            expectedSkills: ['analysis', 'security', 'logic']
                        });
                    }
                }
            }

            // Generate network reconnaissance scenarios
            if (category === 'all' || category === 'network_reconnaissance') {
                if (exposedServices.matches) {
                    for (const host of exposedServices.matches.slice(0, 5)) {
                        trainingData.push({
                            category: 'network_reconnaissance',
                            type: 'recon_prompt',
                            prompt: this.createReconPrompt(host),
                            context: this.sanitizeHostData(host),
                            expectedSkills: ['osint', 'analysis', 'security']
                        });
                    }
                }
            }

            // Generate threat intelligence scenarios
            if (category === 'all' || category === 'threat_intelligence') {
                trainingData.push({
                    category: 'threat_intelligence',
                    type: 'threat_analysis',
                    prompt: this.createThreatIntelPrompt(vulnerableHosts.total || 0),
                    context: { totalVulnerableHosts: vulnerableHosts.total },
                    expectedSkills: ['intelligence', 'analysis', 'writing']
                });
            }

            console.log(`[SHODAN] Generated ${trainingData.length} training scenarios`);
            return trainingData;

        } catch (error) {
            console.error('[SHODAN] Error generating training data:', error.message);
            return this.getFallbackTrainingData();
        }
    }

    /**
     * Create vulnerability analysis prompt from host data
     */
    createVulnerabilityPrompt(host) {
        const vulns = host.vulns || [];
        const ports = host.data?.map(d => d.port) || [host.port];
        const services = host.data?.map(d => d.product).filter(Boolean) || [];

        return `Analyze the following system exposure:
- Open ports: ${ports.join(', ')}
- Services detected: ${services.join(', ') || 'Unknown'}
- Known vulnerabilities: ${vulns.slice(0, 5).join(', ') || 'None detected'}
- Organization: ${host.org || 'Unknown'}
- ISP: ${host.isp || 'Unknown'}

Tasks:
1. Identify the most critical security risks
2. Explain potential attack vectors
3. Recommend immediate security measures
4. Assess the urgency level (Critical/High/Medium/Low)

Provide a professional security assessment report.`;
    }

    /**
     * Create reconnaissance analysis prompt
     */
    createReconPrompt(host) {
        return `You are conducting authorized security research. Analyze this target profile:
- IP: [REDACTED for training]
- Country: ${host.country_name || 'Unknown'}
- Organization: ${host.org || 'Unknown'}
- Ports: ${host.ports?.join(', ') || host.port}
- OS: ${host.os || 'Unknown'}
- Last update: ${host.last_update || 'Unknown'}

Based on this information:
1. What additional reconnaissance steps would you take?
2. What services might be running based on the open ports?
3. What OSINT sources would you check for more information?
4. How would you map the attack surface?

Respond as a professional penetration tester.`;
    }

    /**
     * Create threat intelligence prompt
     */
    createThreatIntelPrompt(totalVulnerable) {
        return `As a threat intelligence analyst, analyze the following findings:

Current Internet Exposure Statistics:
- Hosts vulnerable to Log4j (CVE-2021-44228): ${totalVulnerable.toLocaleString()}
- This vulnerability allows Remote Code Execution

Your analysis should include:
1. Why does this vulnerability remain widespread despite having patches available?
2. What industries are most likely affected?
3. What threat actors are known to exploit this vulnerability?
4. What indicators of compromise (IoCs) should organizations monitor?
5. Provide a threat briefing suitable for C-level executives.

Format your response as a professional threat intelligence report.`;
    }

    /**
     * Sanitize host data for training (remove sensitive info)
     */
    sanitizeHostData(host) {
        return {
            ports: host.ports || [host.port],
            org: host.org,
            country: host.country_name,
            os: host.os,
            vulns: (host.vulns || []).slice(0, 5),
            services: host.data?.slice(0, 3).map(d => ({
                port: d.port,
                product: d.product,
                version: d.version
            })) || []
        };
    }

    /**
     * Fallback training data when API is unavailable
     */
    getFallbackTrainingData() {
        return [
            {
                category: 'vulnerability_analysis',
                type: 'fallback',
                prompt: 'Analyze a system with ports 22, 80, 443, 3306 open. The web server is running Apache 2.4.29 and MySQL 5.7. What vulnerabilities should be checked?',
                expectedSkills: ['analysis', 'security']
            },
            {
                category: 'network_reconnaissance',
                type: 'fallback',
                prompt: 'You discovered an organization running SSH on port 22222 instead of 22, and HTTP on port 8080. What does this tell you about their security posture?',
                expectedSkills: ['osint', 'analysis']
            },
            {
                category: 'threat_intelligence',
                type: 'fallback',
                prompt: 'Write a threat briefing about the risks of exposed RDP (port 3389) services on the internet.',
                expectedSkills: ['intelligence', 'writing']
            }
        ];
    }

    // ==========================================
    // REAL-TIME TRAINING INTEGRATION
    // ==========================================

    /**
     * Create a training session with real Shodan data
     */
    async createTrainingSession(modelName, realTrainingService) {
        console.log(`[SHODAN] Creating training session for ${modelName}`);
        
        const trainingData = await this.generateTrainingData();
        
        // Add Shodan scenarios to the training service
        const shodanScenarios = {
            shodan_vuln: trainingData
                .filter(d => d.category === 'vulnerability_analysis')
                .map(d => d.prompt),
            shodan_recon: trainingData
                .filter(d => d.category === 'network_reconnaissance')
                .map(d => d.prompt),
            shodan_intel: trainingData
                .filter(d => d.category === 'threat_intelligence')
                .map(d => d.prompt)
        };

        return {
            success: true,
            modelName,
            scenarios: shodanScenarios,
            totalPrompts: trainingData.length
        };
    }

    /**
     * Run a single Shodan-powered training iteration
     */
    async runShodanTrainingIteration(modelName, llmService, category = 'vulnerability_analysis') {
        const trainingData = await this.generateTrainingData(category);
        
        if (trainingData.length === 0) {
            return { success: false, error: 'No training data available' };
        }

        const scenario = trainingData[Math.floor(Math.random() * trainingData.length)];
        const startTime = Date.now();

        try {
            const systemPrompt = this.getSystemPromptForCategory(category);
            
            const response = await llmService.generateOllamaResponse(
                scenario.prompt,
                null,
                modelName,
                systemPrompt
            );

            const responseTime = Date.now() - startTime;
            const score = this.evaluateShodanResponse(category, response, responseTime);

            return {
                success: true,
                category,
                prompt: scenario.prompt.substring(0, 100) + '...',
                score,
                responseTime,
                responseLength: response?.length || 0
            };

        } catch (error) {
            return {
                success: false,
                category,
                error: error.message
            };
        }
    }

    /**
     * Get system prompt for category
     */
    getSystemPromptForCategory(category) {
        const prompts = {
            vulnerability_analysis: `You are an expert cybersecurity analyst specializing in vulnerability assessment. 
Provide detailed, professional security analysis. Consider CVSS scores, exploit availability, 
and real-world impact. Your analysis should be actionable and suitable for security teams.`,
            
            network_reconnaissance: `You are an experienced penetration tester conducting authorized security assessments.
Provide methodical reconnaissance strategies. Explain your thought process and prioritize 
based on risk. Always emphasize ethical and legal considerations.`,
            
            threat_intelligence: `You are a senior threat intelligence analyst at a security operations center.
Produce clear, executive-ready threat briefings. Include context about threat actors,
TTPs (Tactics, Techniques, Procedures), and actionable recommendations.`,
            
            service_identification: `You are a network security specialist skilled in service fingerprinting.
Identify services, versions, and potential misconfigurations. Provide security implications
for each finding.`,
            
            exploit_research: `You are a security researcher studying vulnerabilities for defensive purposes.
Explain exploitation techniques conceptually to help defenders understand and prevent attacks.
Focus on detection and mitigation strategies.`
        };
        
        return prompts[category] || prompts.vulnerability_analysis;
    }

    /**
     * Evaluate response quality for Shodan training
     */
    evaluateShodanResponse(category, response, responseTime) {
        if (!response) return 0;

        let score = 40;

        // Length evaluation
        if (response.length > 200) score += 10;
        if (response.length > 500) score += 10;
        if (response.length > 1000) score += 5;
        if (response.length > 2000) score -= 5; // Too verbose

        // Response time (faster is better for cybersecurity contexts)
        if (responseTime < 5000) score += 10;
        else if (responseTime < 10000) score += 5;
        else if (responseTime > 30000) score -= 10;

        // Category-specific keywords
        const keywords = {
            vulnerability_analysis: ['vulnerability', 'CVE', 'patch', 'exploit', 'risk', 'critical', 'remediation', 'CVSS'],
            network_reconnaissance: ['port', 'service', 'scan', 'fingerprint', 'enumeration', 'target', 'network'],
            threat_intelligence: ['threat', 'actor', 'IOC', 'indicator', 'TTP', 'campaign', 'APT', 'briefing'],
            service_identification: ['version', 'banner', 'protocol', 'configuration', 'default', 'exposure'],
            exploit_research: ['payload', 'vector', 'mitigation', 'detection', 'defense', 'prevention']
        };

        const categoryKeywords = keywords[category] || keywords.vulnerability_analysis;
        let keywordMatches = 0;
        
        for (const keyword of categoryKeywords) {
            if (response.toLowerCase().includes(keyword.toLowerCase())) {
                keywordMatches++;
            }
        }

        score += Math.min(20, keywordMatches * 3);

        // Professional formatting bonus
        if (response.includes('##') || response.includes('**') || response.includes('1.')) {
            score += 5;
        }

        return Math.max(0, Math.min(100, score));
    }

    // ==========================================
    // PERIODIC DATA REFRESH
    // ==========================================

    /**
     * Start periodic refresh of training data
     */
    startPeriodicRefresh(intervalMinutes = 60) {
        console.log(`[SHODAN] Starting periodic data refresh every ${intervalMinutes} minutes`);
        
        this.refreshInterval = setInterval(async () => {
            try {
                await this.generateTrainingData('all');
                console.log('[SHODAN] Training data refreshed');
            } catch (error) {
                console.error('[SHODAN] Refresh failed:', error.message);
            }
        }, intervalMinutes * 60 * 1000);
    }

    /**
     * Stop periodic refresh
     */
    stopPeriodicRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
            console.log('[SHODAN] Stopped periodic refresh');
        }
    }

    /**
     * Get service status and stats
     */
    async getStatus() {
        try {
            const accountInfo = await this.getAccountInfo();
            return {
                status: 'connected',
                credits: accountInfo.query_credits,
                scanCredits: accountInfo.scan_credits,
                plan: accountInfo.plan,
                cacheSize: this.cache.size
            };
        } catch (error) {
            return {
                status: 'error',
                error: error.message
            };
        }
    }
}

module.exports = ShodanService;
