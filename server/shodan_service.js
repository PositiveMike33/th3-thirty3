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
     * ENHANCED: Analyze IP with deep intelligence context
     * Returns precise, professional-grade analysis
     */
    async analyzeHostIntelligence(ip) {
        try {
            const host = await this.getHost(ip);
            return this.buildIntelligenceReport(host);
        } catch (error) {
            return {
                success: false,
                error: error.message,
                ip,
                recommendation: 'Unable to retrieve Shodan data. IP may be private, blocked, or not indexed.'
            };
        }
    }

    /**
     * Build comprehensive intelligence report from Shodan data
     */
    buildIntelligenceReport(host) {
        // System Classification
        const classification = this.classifySystem(host);
        
        // Vulnerability Assessment
        const vulnerabilities = this.extractVulnerabilities(host);
        
        // Service Analysis
        const services = this.analyzeServices(host.data || []);
        
        // Risk Score Calculation
        const riskScore = this.calculateRiskScore(host, vulnerabilities, services);
        
        // Build enriched report
        return {
            success: true,
            summary: {
                ip: host.ip_str,
                country: host.country_name,
                city: host.city,
                organization: host.org,
                isp: host.isp,
                asn: host.asn,
                lastUpdate: host.last_update
            },
            classification: classification,
            networkProfile: {
                openPorts: host.ports || [],
                totalPorts: (host.ports || []).length,
                os: host.os || 'Unknown',
                hostnames: host.hostnames || [],
                domains: host.domains || []
            },
            services: services,
            vulnerabilities: vulnerabilities,
            riskAssessment: riskScore,
            recommendations: this.generateRecommendations(classification, vulnerabilities, riskScore)
        };
    }

    /**
     * Classify the system type based on ports and services
     */
    classifySystem(host) {
        const ports = host.ports || [];
        const data = host.data || [];
        const products = data.map(d => d.product?.toLowerCase() || '').filter(Boolean);
        const allText = JSON.stringify(host).toLowerCase();
        
        // ICS/SCADA Detection
        const icsSignatures = {
            'Modbus': { ports: [502], keywords: ['modbus', 'plc', 'schneider', 'siemens', 'rockwell', 'allen-bradley'] },
            'BACnet': { ports: [47808], keywords: ['bacnet', 'hvac', 'building automation', 'johnson controls'] },
            'DNP3': { ports: [20000], keywords: ['dnp3', 'scada', 'power grid'] },
            'EtherNet/IP': { ports: [44818], keywords: ['ethernet/ip', 'cip', 'industrial'] },
            'S7comm': { ports: [102], keywords: ['s7', 'siemens', 'simatic'] },
            'Niagara Fox': { ports: [1911, 4911], keywords: ['niagara', 'tridium', 'fox'] }
        };

        for (const [protocol, config] of Object.entries(icsSignatures)) {
            const hasPort = config.ports.some(p => ports.includes(p));
            const hasKeyword = config.keywords.some(k => allText.includes(k));
            if (hasPort || hasKeyword) {
                return {
                    type: 'ICS/SCADA',
                    protocol: protocol,
                    sector: this.identifySector(host, products),
                    criticality: 'CRITICAL',
                    warning: '⚠️ Industrial Control System detected - DO NOT SCAN ACTIVELY',
                    context: 'This system likely controls physical processes. Unauthorized interaction could cause real-world damage.',
                    realWorldRisk: this.getICSRealWorldRisk(protocol)
                };
            }
        }

        // IoT Detection
        const iotKeywords = ['camera', 'webcam', 'dvr', 'nvr', 'hikvision', 'dahua', 'smart', 'iot', 'embedded'];
        if (iotKeywords.some(k => allText.includes(k))) {
            return {
                type: 'IoT Device',
                subtype: this.identifyIoTType(allText),
                criticality: 'HIGH',
                warning: 'IoT devices often have weak security and default credentials',
                context: 'Check for default passwords, outdated firmware, and unencrypted protocols'
            };
        }

        // Database Detection
        const dbPorts = { 3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL', 27017: 'MongoDB', 6379: 'Redis' };
        for (const [port, db] of Object.entries(dbPorts)) {
            if (ports.includes(parseInt(port))) {
                return {
                    type: 'Database Server',
                    database: db,
                    criticality: 'HIGH',
                    warning: `Exposed ${db} database - verify authentication is enforced`,
                    context: 'Exposed databases are prime targets for data theft and ransomware'
                };
            }
        }

        // Web Server Detection
        if (ports.includes(80) || ports.includes(443) || ports.includes(8080)) {
            const webServer = products.find(p => p.includes('apache') || p.includes('nginx') || p.includes('iis'));
            return {
                type: 'Web Server',
                server: webServer || 'Unknown',
                criticality: 'MEDIUM',
                context: 'Standard web infrastructure'
            };
        }

        return {
            type: 'General Purpose Server',
            criticality: 'MEDIUM',
            context: 'Standard infrastructure endpoint'
        };
    }

    /**
     * Identify industry sector from context
     */
    identifySector(host, products) {
        const allText = (JSON.stringify(host) + products.join(' ')).toLowerCase();
        
        if (allText.includes('water') || allText.includes('pump') || allText.includes('treatment')) {
            return 'Water/Utilities';
        }
        if (allText.includes('power') || allText.includes('energy') || allText.includes('grid')) {
            return 'Energy/Power';
        }
        if (allText.includes('hospital') || allText.includes('medical') || allText.includes('health')) {
            return 'Healthcare';
        }
        if (allText.includes('manufacturing') || allText.includes('factory')) {
            return 'Manufacturing';
        }
        if (allText.includes('hotel') || allText.includes('building') || allText.includes('hvac')) {
            return 'Building Automation';
        }
        return 'Industrial/Unknown';
    }

    /**
     * Get real-world ICS risk examples
     */
    getICSRealWorldRisk(protocol) {
        const cases = {
            'Modbus': 'Oldsmar FL Water Plant (2021) - Attacker attempted to poison water supply via Modbus',
            'BACnet': 'Target HVAC Breach (2013) - BACnet used as initial access vector',
            'S7comm': 'Stuxnet (2010) - Destroyed centrifuges via S7 protocol manipulation',
            'DNP3': 'Ukraine Power Grid Attack (2015) - SCADA manipulation via DNP3'
        };
        return cases[protocol] || 'Multiple documented attacks on this protocol';
    }

    /**
     * Identify IoT device type
     */
    identifyIoTType(text) {
        if (text.includes('camera') || text.includes('webcam') || text.includes('dvr')) return 'Surveillance/Camera';
        if (text.includes('router') || text.includes('gateway')) return 'Network Equipment';
        if (text.includes('printer') || text.includes('mfp')) return 'Printer/MFP';
        if (text.includes('nas') || text.includes('storage')) return 'NAS/Storage';
        return 'Generic IoT';
    }

    /**
     * Extract and enrich vulnerability data
     */
    extractVulnerabilities(host) {
        const vulns = host.vulns || [];
        if (vulns.length === 0) {
            return { count: 0, critical: 0, high: 0, medium: 0, low: 0, list: [] };
        }

        const enriched = vulns.slice(0, 10).map(cve => ({
            cve,
            estimatedSeverity: this.estimateCVESeverity(cve),
            exploitAvailable: this.checkExploitAvailability(cve)
        }));

        return {
            count: vulns.length,
            critical: enriched.filter(v => v.estimatedSeverity === 'CRITICAL').length,
            high: enriched.filter(v => v.estimatedSeverity === 'HIGH').length,
            medium: enriched.filter(v => v.estimatedSeverity === 'MEDIUM').length,
            low: enriched.filter(v => v.estimatedSeverity === 'LOW').length,
            list: enriched
        };
    }

    /**
     * Estimate CVE severity from ID pattern (known critical CVEs)
     */
    estimateCVESeverity(cve) {
        const criticalCVEs = ['CVE-2021-44228', 'CVE-2021-27065', 'CVE-2020-1472', 'CVE-2019-0708', 'CVE-2017-0144'];
        const highCVEs = ['CVE-2021', 'CVE-2022', 'CVE-2023', 'CVE-2024'];
        
        if (criticalCVEs.some(c => cve.includes(c))) return 'CRITICAL';
        if (highCVEs.some(y => cve.startsWith(y))) return 'HIGH';
        return 'MEDIUM';
    }

    /**
     * Check if exploit is likely available
     */
    checkExploitAvailability(cve) {
        const knownExploited = ['CVE-2021-44228', 'CVE-2019-0708', 'CVE-2017-0144', 'CVE-2020-1472'];
        return knownExploited.some(c => cve.includes(c)) ? 'Public Exploit Available' : 'Unknown';
    }

    /**
     * Analyze detected services
     */
    analyzeServices(data) {
        return data.slice(0, 10).map(service => ({
            port: service.port,
            protocol: service.transport || 'tcp',
            product: service.product || 'Unknown',
            version: service.version || 'Unknown',
            banner: service.data?.substring(0, 200) || '',
            cpe: service.cpe || [],
            securityNotes: this.getServiceSecurityNotes(service)
        }));
    }

    /**
     * Get security notes for a service
     */
    getServiceSecurityNotes(service) {
        const notes = [];
        const port = service.port;
        const product = (service.product || '').toLowerCase();
        const version = service.version || '';

        // Check for concerning configurations
        if (port === 21) notes.push('FTP - Check for anonymous access');
        if (port === 22 && product.includes('openssh')) notes.push(`OpenSSH ${version} - Verify patched`);
        if (port === 23) notes.push('⚠️ Telnet - Unencrypted, replace with SSH');
        if (port === 25 || port === 587) notes.push('SMTP - Check for open relay');
        if (port === 445) notes.push('SMB - Check for EternalBlue, disable SMBv1');
        if (port === 3389) notes.push('RDP - Major attack surface, use VPN/NLA');
        if (port === 5900) notes.push('VNC - Often weak auth, tunnel via SSH');
        
        return notes.length > 0 ? notes : ['Standard service configuration'];
    }

    /**
     * Calculate overall risk score
     */
    calculateRiskScore(host, vulnerabilities, services) {
        let score = 0;
        let factors = [];

        // Vulnerability impact
        score += vulnerabilities.critical * 25;
        score += vulnerabilities.high * 15;
        score += vulnerabilities.medium * 5;
        if (vulnerabilities.critical > 0) factors.push(`${vulnerabilities.critical} critical CVEs`);

        // Exposed services risk
        const riskyPorts = [21, 23, 445, 3389, 5900, 502, 102, 47808];
        const exposedRisky = (host.ports || []).filter(p => riskyPorts.includes(p));
        score += exposedRisky.length * 10;
        if (exposedRisky.length > 0) factors.push(`${exposedRisky.length} high-risk services exposed`);

        // Port count (more exposure = more risk)
        if ((host.ports || []).length > 10) {
            score += 10;
            factors.push('Large attack surface (10+ ports)');
        }

        // Cap score at 100
        score = Math.min(100, score);

        let level = 'LOW';
        let color = '🟢';
        if (score >= 75) { level = 'CRITICAL'; color = '🔴'; }
        else if (score >= 50) { level = 'HIGH'; color = '🟠'; }
        else if (score >= 25) { level = 'MEDIUM'; color = '🟡'; }

        return {
            score,
            level,
            color,
            factors,
            summary: `${color} Risk Level: ${level} (${score}/100)`
        };
    }

    /**
     * Generate actionable recommendations
     */
    generateRecommendations(classification, vulnerabilities, riskScore) {
        const recs = [];

        if (classification.type === 'ICS/SCADA') {
            recs.push('🚨 IMMEDIATE: Verify network segmentation from IT network');
            recs.push('Implement ICS-specific firewall rules');
            recs.push('Enable protocol-aware monitoring (Modbus/BACnet inspection)');
            recs.push('Conduct authorized passive assessment only');
        }

        if (vulnerabilities.critical > 0) {
            recs.push('🔴 URGENT: Patch critical CVEs immediately');
            recs.push('Isolate system until patched if exposed to internet');
        }

        if (riskScore.score >= 50) {
            recs.push('Conduct full penetration test');
            recs.push('Review firewall rules and reduce attack surface');
            recs.push('Enable IDS/IPS monitoring');
        }

        if (recs.length === 0) {
            recs.push('Continue routine security monitoring');
            recs.push('Ensure timely patching schedule');
        }

        return recs;
    }

    /**
     * Get system prompt for category
     */
    getSystemPromptForCategory(category) {
        const prompts = {
            vulnerability_analysis: `Tu es un expert en cybersécurité spécialisé dans l'analyse de vulnérabilités et les systèmes industriels (ICS/SCADA).

RÈGLES D'ANALYSE CRITIQUE:
1. Identifie PRÉCISÉMENT le type de système: ICS/SCADA, IoT, serveur web, base de données, etc.
2. Pour les systèmes industriels, mentionne TOUJOURS le protocole (Modbus, BACnet, S7comm, DNP3)
3. Fournis le contexte métier: Est-ce un PLC? Un système HVAC? Une caméra?
4. Évalue la criticité avec les niveaux: CRITICAL/HIGH/MEDIUM/LOW
5. Mentionne des cas réels similaires (Oldsmar, Stuxnet, Ukraine Power Grid)
6. Donne des recommandations ACTIONNABLES et spécifiques

FORMAT DE RÉPONSE:
## Classification du Système
- Type: [ICS/SCADA, IoT, Serveur, etc.]
- Protocole/Produit: [Modbus, Schneider, etc.]
- Secteur: [Énergie, Eau, Santé, etc.]

## Analyse des Risques
- Score de Risque: X/100
- Vulnérabilités détectées: [Liste CVE]
- Vecteurs d'attaque potentiels: [Liste]

## Contexte Opérationnel
- Ce système contrôle: [Description des fonctions physiques]
- Impact potentiel: [Conséquences d'une attaque]

## Recommandations
1. [Action immédiate]
2. [Action à court terme]
3. [Action à long terme]`,
            
            network_reconnaissance: `Tu es un pentester expérimenté conduisant des évaluations de sécurité autorisées.
Fournis des stratégies de reconnaissance méthodiques. Explique ton processus de réflexion et priorise selon le risque.
Souligne toujours les considérations éthiques et légales.

Pour chaque cible:
1. Identifie les services critiques et leur fonction probable
2. Liste les outils appropriés (nmap, masscan, etc.)
3. Suggère les prochaines étapes de reconnaissance
4. Évalue la surface d'attaque`,
            
            threat_intelligence: `Tu es un analyste senior en threat intelligence dans un SOC.
Produis des briefings clairs et prêts pour les dirigeants.
Inclus le contexte sur les acteurs de menace, les TTPs (Tactics, Techniques, Procedures), et des recommandations actionnables.

Structure ton analyse:
1. Résumé exécutif (1-2 phrases)
2. Analyse technique détaillée
3. Attribution des menaces (si applicable)
4. Indicateurs de compromission (IoCs)
5. Recommandations de mitigation`,
            
            service_identification: `Tu es un spécialiste en sécurité réseau expert en fingerprinting de services.
Identifie les services, versions, et potentielles mauvaises configurations.
Fournis les implications de sécurité pour chaque découverte.

Pour chaque service détecté:
- Nom et version exacte
- Configuration standard vs non-standard
- Vulnérabilités connues pour cette version
- Recommandations de hardening`,
            
            exploit_research: `Tu es un chercheur en sécurité étudiant les vulnérabilités à des fins défensives.
Explique les techniques d'exploitation conceptuellement pour aider les défenseurs à comprendre et prévenir les attaques.
Focus sur les stratégies de détection et mitigation.`
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
