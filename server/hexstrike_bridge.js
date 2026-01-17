/**
 * HexStrike AI Bridge - Connect th3-thirty3 to HexStrike security tools
 * 
 * This bridge provides access to 150+ professional security tools through
 * the HexStrike AI server running on port 8888.
 */

const HEXSTRIKE_URL = process.env.HEXSTRIKE_URL || 'http://hexstrike:8888';

class HexStrikeBridge {
    constructor() {
        this.baseUrl = HEXSTRIKE_URL;
        this.timeout = 300000; // 5 minutes for long scans
        this.isOnline = false;
        this.lastHealthCheck = null;

        console.log(`[HEXSTRIKE] Bridge initialized: ${this.baseUrl}`);
    }

    /**
     * Check HexStrike server health
     */
    async checkHealth() {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000);

            const response = await fetch(`${this.baseUrl}/health`, {
                signal: controller.signal
            });
            clearTimeout(timeoutId);

            // Handle both text ("OK") and JSON responses
            const text = await response.text();
            let data;
            try {
                data = JSON.parse(text);
            } catch {
                // Simple "OK" response
                data = { status: text.trim() === 'OK' ? 'healthy' : text };
            }

            this.isOnline = true;
            this.lastHealthCheck = new Date();

            console.log('[HEXSTRIKE] ✅ Server online:', data);
            return { status: 'online', ...data };
        } catch (error) {
            this.isOnline = false;
            console.log('[HEXSTRIKE] ❌ Server offline:', error.message);
            return { status: 'offline', error: error.message };
        }
    }

    /**
     * Make an API request to HexStrike
     */
    async apiRequest(endpoint, method = 'GET', body = null) {
        const options = {
            method,
            headers: { 'Content-Type': 'application/json' },
        };

        if (body) {
            options.body = JSON.stringify(body);
        }

        const response = await fetch(`${this.baseUrl}${endpoint}`, options);

        if (!response.ok) {
            throw new Error(`HexStrike API error: ${response.status} ${response.statusText}`);
        }

        return await response.json();
    }

    /**
     * Execute a security tool via HexStrike
     */
    async executeTool(toolName, params = {}) {
        console.log(`[HEXSTRIKE] 🔧 Executing tool: ${toolName}`, params);

        try {
            const result = await this.apiRequest('/api/command', 'POST', {
                tool: toolName,
                params: params,
                use_cache: true
            });

            console.log(`[HEXSTRIKE] ✅ Tool ${toolName} completed`);
            return result;
        } catch (error) {
            console.error(`[HEXSTRIKE] ❌ Tool ${toolName} failed:`, error.message);
            throw error;
        }
    }

    // ============================================================================
    // NETWORK & RECONNAISSANCE TOOLS
    // ============================================================================

    /**
     * Nmap scan with advanced options
     */
    async nmapScan(target, options = {}) {
        return this.executeTool('nmap_scan', {
            target,
            scan_type: options.scanType || '-sV',
            ports: options.ports || '',
            additional_args: options.additionalArgs || ''
        });
    }

    /**
     * RustScan - Ultra-fast port scanning
     */
    async rustscanScan(target, options = {}) {
        return this.executeTool('rustscan_scan', {
            target,
            ports: options.ports || '',
            additional_args: options.additionalArgs || ''
        });
    }

    /**
     * Masscan - High-speed port scanning
     */
    async masscanScan(target, options = {}) {
        return this.executeTool('masscan_scan', {
            target,
            ports: options.ports || '1-65535',
            rate: options.rate || '1000'
        });
    }

    /**
     * Amass - Subdomain enumeration
     */
    async amassEnum(domain, options = {}) {
        return this.executeTool('amass_enum', {
            domain,
            active: options.active || false,
            additional_args: options.additionalArgs || ''
        });
    }

    /**
     * Subfinder - Fast passive subdomain discovery
     */
    async subfinderScan(domain, options = {}) {
        return this.executeTool('subfinder_scan', {
            domain,
            all: options.all || false,
            additional_args: options.additionalArgs || ''
        });
    }

    // ============================================================================
    // WEB APPLICATION SECURITY TOOLS
    // ============================================================================

    /**
     * Nuclei - Vulnerability scanning with templates
     */
    async nucleiScan(target, options = {}) {
        return this.executeTool('nuclei_scan', {
            target,
            severity: options.severity || 'high,critical',
            tags: options.tags || '',
            template: options.template || '',
            additional_args: options.additionalArgs || ''
        });
    }

    /**
     * Gobuster - Directory/file enumeration
     */
    async gobusterScan(url, options = {}) {
        return this.executeTool('gobuster_scan', {
            url,
            mode: options.mode || 'dir',
            wordlist: options.wordlist || '/usr/share/wordlists/dirb/common.txt',
            additional_args: options.additionalArgs || ''
        });
    }

    /**
     * Feroxbuster - Recursive content discovery
     */
    async feroxbusterScan(url, options = {}) {
        return this.executeTool('feroxbuster_scan', {
            url,
            wordlist: options.wordlist || '/usr/share/wordlists/dirb/common.txt',
            additional_args: options.additionalArgs || ''
        });
    }

    /**
     * FFuf - Fast web fuzzing
     */
    async ffufScan(url, options = {}) {
        return this.executeTool('ffuf_scan', {
            url,
            wordlist: options.wordlist || '/usr/share/wordlists/dirb/common.txt',
            additional_args: options.additionalArgs || ''
        });
    }

    /**
     * SQLMap - SQL injection testing
     */
    async sqlmapScan(url, options = {}) {
        return this.executeTool('sqlmap_scan', {
            url,
            level: options.level || 1,
            risk: options.risk || 1,
            additional_args: options.additionalArgs || ''
        });
    }

    /**
     * Nikto - Web server vulnerability scanner
     */
    async niktoScan(target, options = {}) {
        return this.executeTool('nikto_scan', {
            target,
            additional_args: options.additionalArgs || ''
        });
    }

    /**
     * WPScan - WordPress security scanner
     */
    async wpscanScan(url, options = {}) {
        return this.executeTool('wpscan_scan', {
            url,
            enumerate: options.enumerate || 'vp,vt,u',
            additional_args: options.additionalArgs || ''
        });
    }

    /**
     * Dalfox - XSS vulnerability scanner
     */
    async dalfoxScan(url, options = {}) {
        return this.executeTool('dalfox_scan', {
            url,
            additional_args: options.additionalArgs || ''
        });
    }

    /**
     * HTTPx - HTTP probing and tech detection
     */
    async httpxProbe(targets, options = {}) {
        return this.executeTool('httpx_probe', {
            targets,
            tech_detect: options.techDetect !== false,
            additional_args: options.additionalArgs || ''
        });
    }

    /**
     * Katana - Web crawling
     */
    async katanaCrawl(url, options = {}) {
        return this.executeTool('katana_crawl', {
            url,
            depth: options.depth || 3,
            additional_args: options.additionalArgs || ''
        });
    }

    // ============================================================================
    // CLOUD SECURITY TOOLS
    // ============================================================================

    /**
     * Prowler - AWS/Azure/GCP security assessment
     */
    async prowlerScan(options = {}) {
        return this.executeTool('prowler_scan', {
            provider: options.provider || 'aws',
            profile: options.profile || 'default',
            region: options.region || '',
            checks: options.checks || '',
            output_dir: options.outputDir || '/tmp/prowler_output',
            output_format: options.outputFormat || 'json'
        });
    }

    /**
     * Trivy - Container vulnerability scanning
     */
    async trivyScan(target, options = {}) {
        return this.executeTool('trivy_scan', {
            scan_type: options.scanType || 'image',
            target,
            severity: options.severity || '',
            output_format: options.outputFormat || 'json'
        });
    }

    /**
     * Kube-hunter - Kubernetes penetration testing
     */
    async kubeHunterScan(options = {}) {
        return this.executeTool('kube_hunter_scan', {
            target: options.target || '',
            remote: options.remote || '',
            active: options.active || false,
            report: options.report || 'json'
        });
    }

    /**
     * Kube-bench - CIS Kubernetes benchmark
     */
    async kubeBenchCIS(options = {}) {
        return this.executeTool('kube_bench_cis', {
            targets: options.targets || '',
            output_format: options.outputFormat || 'json'
        });
    }

    // ============================================================================
    // BINARY ANALYSIS & REVERSE ENGINEERING
    // ============================================================================

    /**
     * Ghidra - Software reverse engineering
     */
    async ghidraAnalyze(binaryPath, options = {}) {
        return this.executeTool('ghidra_analyze', {
            binary_path: binaryPath,
            script: options.script || '',
            additional_args: options.additionalArgs || ''
        });
    }

    /**
     * Radare2 - Advanced reverse engineering
     */
    async radare2Analyze(binaryPath, options = {}) {
        return this.executeTool('radare2_analyze', {
            binary_path: binaryPath,
            commands: options.commands || 'aaa;afl',
            additional_args: options.additionalArgs || ''
        });
    }

    /**
     * Binwalk - Firmware analysis
     */
    async binwalkAnalyze(filePath, options = {}) {
        return this.executeTool('binwalk_analyze', {
            file_path: filePath,
            extract: options.extract || false,
            additional_args: options.additionalArgs || ''
        });
    }

    /**
     * Checksec - Binary security properties
     */
    async checksecCheck(binaryPath) {
        return this.executeTool('checksec_check', {
            binary_path: binaryPath
        });
    }

    // ============================================================================
    // PASSWORD & AUTHENTICATION TOOLS
    // ============================================================================

    /**
     * Hydra - Network login cracker
     */
    async hydraAttack(target, options = {}) {
        return this.executeTool('hydra_attack', {
            target,
            service: options.service || 'ssh',
            username: options.username || '',
            userlist: options.userlist || '',
            password: options.password || '',
            passlist: options.passlist || '',
            additional_args: options.additionalArgs || ''
        });
    }

    /**
     * John the Ripper - Password cracking
     */
    async johnCrack(hashFile, options = {}) {
        return this.executeTool('john_crack', {
            hash_file: hashFile,
            wordlist: options.wordlist || '',
            format: options.format || '',
            additional_args: options.additionalArgs || ''
        });
    }

    /**
     * Hashcat - GPU-accelerated cracking
     */
    async hashcatCrack(hashFile, options = {}) {
        return this.executeTool('hashcat_crack', {
            hash_file: hashFile,
            mode: options.mode || 0,
            wordlist: options.wordlist || '',
            additional_args: options.additionalArgs || ''
        });
    }

    // ============================================================================
    // OSINT TOOLS
    // ============================================================================

    /**
     * Sherlock - Username investigation
     */
    async sherlockSearch(username, options = {}) {
        return this.executeTool('sherlock_search', {
            username,
            additional_args: options.additionalArgs || ''
        });
    }

    /**
     * TheHarvester - Email and subdomain harvesting
     */
    async theHarvesterSearch(domain, options = {}) {
        return this.executeTool('theharvester_search', {
            domain,
            source: options.source || 'all',
            additional_args: options.additionalArgs || ''
        });
    }

    // ============================================================================
    // AI INTELLIGENCE ENDPOINTS
    // ============================================================================

    /**
     * AI-powered target analysis
     */
    async analyzeTarget(target, analysisType = 'comprehensive') {
        return this.apiRequest('/api/intelligence/analyze-target', 'POST', {
            target,
            analysis_type: analysisType
        });
    }

    /**
     * Get AI-recommended tools for a target
     */
    async selectTools(target, objectives = ['vulnerability_assessment']) {
        return this.apiRequest('/api/intelligence/select-tools', 'POST', {
            target,
            objectives
        });
    }

    /**
     * Optimize parameters for a tool
     */
    async optimizeParameters(tool, target, context = {}) {
        return this.apiRequest('/api/intelligence/optimize-parameters', 'POST', {
            tool,
            target,
            context
        });
    }

    // ============================================================================
    // PROCESS MANAGEMENT
    // ============================================================================

    /**
     * List running processes
     */
    async listProcesses() {
        return this.apiRequest('/api/processes/list');
    }

    /**
     * Get process status
     */
    async getProcessStatus(pid) {
        return this.apiRequest(`/api/processes/status/${pid}`);
    }

    /**
     * Terminate a process
     */
    async terminateProcess(pid) {
        return this.apiRequest(`/api/processes/terminate/${pid}`, 'POST');
    }

    /**
     * Get process dashboard
     */
    async getProcessDashboard() {
        return this.apiRequest('/api/processes/dashboard');
    }

    // ============================================================================
    // CACHE & TELEMETRY
    // ============================================================================

    /**
     * Get cache statistics
     */
    async getCacheStats() {
        return this.apiRequest('/api/cache/stats');
    }

    /**
     * Get telemetry data
     */
    async getTelemetry() {
        return this.apiRequest('/api/telemetry');
    }

    /**
     * List all available tools
     */
    async listTools() {
        return this.apiRequest('/api/tools');
    }
}

// Export singleton instance
module.exports = new HexStrikeBridge();
