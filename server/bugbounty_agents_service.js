/**
 * BUG BOUNTY AGENTS SERVICE
 * 
 * Service pour orchestrer les 10 agents Bug Bounty autonomes
 * Intègre red teaming, best practices, et HackerAI
 */

const fs = require('fs');
const path = require('path');
const { spawn, exec } = require('child_process');
const { getHackerAIService } = require('./hackerai_service');

class BugBountyAgentsService {
    constructor() {
        this.configPath = path.join(__dirname, 'config', 'bugbounty_agents.json');
        this.config = this.loadConfig();
        this.activeAgents = new Map();
        this.missionLogs = [];
        this.hackerAI = null;
        
        console.log('[BUGBOUNTY] Bug Bounty Agents Service initialized');
        console.log(`[BUGBOUNTY] Loaded ${this.config.agents?.length || 0} agents`);
    }

    /**
     * Load agents configuration
     */
    loadConfig() {
        try {
            if (fs.existsSync(this.configPath)) {
                const data = fs.readFileSync(this.configPath, 'utf8');
                return JSON.parse(data);
            }
        } catch (error) {
            console.error('[BUGBOUNTY] Error loading config:', error.message);
        }
        return { agents: [], global_config: {} };
    }

    /**
     * Get all agents
     */
    getAgents() {
        return this.config.agents || [];
    }

    /**
     * Get agent by ID
     */
    getAgent(agentId) {
        return this.config.agents?.find(a => a.id === agentId);
    }

    /**
     * Get global configuration
     */
    getGlobalConfig() {
        return this.config.global_config || {};
    }

    /**
     * Initialize HackerAI connection
     */
    initHackerAI() {
        try {
            this.hackerAI = getHackerAIService();
            return { success: true, status: this.hackerAI.getStatus() };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * Start a mission with specific agents
     */
    async startMission(options = {}) {
        const {
            name = 'Bug Bounty Mission',
            target,
            scope = [],
            agents = ['recon_agent', 'scan_agent'],
            autonomyLevel = this.config.global_config?.autonomy_level || 'medium'
        } = options;

        if (!target) {
            throw new Error('Target is required for mission');
        }

        const missionId = `mission_${Date.now()}`;
        const mission = {
            id: missionId,
            name,
            target,
            scope,
            agents: agents.map(id => this.getAgent(id)).filter(Boolean),
            autonomyLevel,
            status: 'active',
            startTime: new Date().toISOString(),
            logs: [],
            findings: []
        };

        // Validate scope/legal
        const legalCheck = await this.runLegalCheck(target, scope);
        if (!legalCheck.approved) {
            mission.status = 'blocked';
            mission.logs.push({ type: 'error', msg: 'Legal check failed: ' + legalCheck.reason });
            return { success: false, mission, reason: legalCheck.reason };
        }

        this.activeAgents.set(missionId, mission);
        mission.logs.push({ type: 'info', msg: `Mission started with ${mission.agents.length} agents` });

        // If HackerAI is available, use it for command execution
        if (this.hackerAI?.getStatus()?.running) {
            mission.logs.push({ type: 'info', msg: 'HackerAI agent connected for command execution' });
        }

        return { success: true, mission };
    }

    /**
     * Run legal/scope check before mission
     */
    async runLegalCheck(target, scope) {
        const legalAgent = this.getAgent('legal_agent');
        if (!legalAgent) {
            return { approved: true, warning: 'No legal agent configured' };
        }

        // Basic checks
        const checks = {
            hasExplicitPermission: scope.length > 0,
            targetInScope: scope.includes(target) || scope.some(s => target.includes(s)),
            notBlacklisted: !this.isBlacklisted(target)
        };

        if (!checks.notBlacklisted) {
            return { approved: false, reason: 'Target is blacklisted' };
        }

        if (!checks.hasExplicitPermission) {
            return { approved: true, warning: 'No explicit scope defined - proceed with caution' };
        }

        return { approved: true, checks };
    }

    /**
     * Check if target is blacklisted
     */
    isBlacklisted(target) {
        const blacklist = [
            'gov', 'mil', 'edu',
            'bank', 'hospital', 'emergency'
        ];
        return blacklist.some(bl => target.toLowerCase().includes(bl));
    }

    /**
     * Execute agent tool
     */
    async executeAgentTool(agentId, toolName, params = {}) {
        const agent = this.getAgent(agentId);
        if (!agent) {
            throw new Error(`Agent ${agentId} not found`);
        }

        const tool = agent.tools?.find(t => t.name === toolName);
        if (!tool) {
            throw new Error(`Tool ${toolName} not found in agent ${agentId}`);
        }

        // Build command with parameters
        let command = tool.command;
        for (const [key, value] of Object.entries(params)) {
            command = command.replace(`{${key}}`, value);
        }

        // Check for injection attempts (red teaming defense)
        if (this.config.global_config?.red_teaming_enabled) {
            const injectionCheck = this.checkInjection(command, params);
            if (injectionCheck.detected) {
                this.missionLogs.push({
                    type: 'red_team_alert',
                    agent: agentId,
                    tool: toolName,
                    threat: injectionCheck.threat,
                    time: new Date().toISOString()
                });
                throw new Error(`Injection attempt detected: ${injectionCheck.threat}`);
            }
        }

        // Log the execution
        const execution = {
            agent: agentId,
            tool: toolName,
            command,
            params,
            startTime: new Date().toISOString(),
            status: 'running'
        };

        // Execute via HackerAI if available, otherwise locally
        try {
            if (this.hackerAI?.getStatus()?.running) {
                // HackerAI will execute via web interface
                execution.executor = 'hackerai';
                execution.status = 'queued_hackerai';
                execution.message = 'Command queued for HackerAI execution. Check hackerai.co/hackergpt';
            } else {
                // Local execution simulation
                execution.executor = 'local';
                execution.output = await this.executeLocal(command);
                execution.status = 'completed';
            }
        } catch (error) {
            execution.status = 'error';
            execution.error = error.message;
        }

        execution.endTime = new Date().toISOString();
        return execution;
    }

    /**
     * Check for injection attempts
     */
    checkInjection(command, params) {
        const dangerousPatterns = [
            /;\s*rm\s+-rf/i,
            /;\s*dd\s+if=/i,
            /\|\s*bash/i,
            /`.*`/,
            /\$\(.*\)/,
            /&&\s*(rm|dd|mkfs|format)/i,
            /'.*--/,
            /union\s+select/i,
            /<script>/i
        ];

        for (const pattern of dangerousPatterns) {
            const checkValue = command + ' ' + Object.values(params).join(' ');
            if (pattern.test(checkValue)) {
                return { detected: true, threat: pattern.toString() };
            }
        }

        return { detected: false };
    }

    /**
     * Execute command locally (simulation for safe commands)
     */
    async executeLocal(command) {
        return new Promise((resolve, reject) => {
            // For safety, only simulate certain commands
            const safeCommands = ['echo', 'ping', 'nslookup', 'whois', 'curl -I'];
            const isSafe = safeCommands.some(sc => command.startsWith(sc));

            if (!isSafe) {
                resolve({
                    simulated: true,
                    message: 'Command queued for manual review or HackerAI execution',
                    command
                });
                return;
            }

            exec(command, { timeout: 30000 }, (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                } else {
                    resolve({ stdout, stderr });
                }
            });
        });
    }

    /**
     * Get red teaming prompts for an agent
     */
    getRedTeamingPrompts(agentId) {
        const agent = this.getAgent(agentId);
        return agent?.red_teaming_prompts || [];
    }

    /**
     * Get best practices for an agent
     */
    getBestPractices(agentId) {
        const agent = this.getAgent(agentId);
        return agent?.best_practices || [];
    }

    /**
     * Get pitfalls to avoid for an agent
     */
    getPitfalls(agentId) {
        const agent = this.getAgent(agentId);
        return agent?.pitfalls || [];
    }

    /**
     * Get active missions
     */
    getActiveMissions() {
        return Array.from(this.activeAgents.values());
    }

    /**
     * Get mission by ID
     */
    getMission(missionId) {
        return this.activeAgents.get(missionId);
    }

    /**
     * Stop a mission
     */
    stopMission(missionId) {
        const mission = this.activeAgents.get(missionId);
        if (mission) {
            mission.status = 'stopped';
            mission.endTime = new Date().toISOString();
            return { success: true, mission };
        }
        return { success: false, error: 'Mission not found' };
    }

    /**
     * Add finding to mission
     */
    addFinding(missionId, finding) {
        const mission = this.activeAgents.get(missionId);
        if (mission) {
            finding.id = `finding_${Date.now()}`;
            finding.timestamp = new Date().toISOString();
            mission.findings.push(finding);
            return { success: true, finding };
        }
        return { success: false, error: 'Mission not found' };
    }

    /**
     * Generate report for mission
     */
    generateReport(missionId) {
        const mission = this.getMission(missionId);
        if (!mission) {
            return { success: false, error: 'Mission not found' };
        }

        const report = {
            title: `Bug Bounty Report: ${mission.name}`,
            target: mission.target,
            scope: mission.scope,
            duration: this.calculateDuration(mission.startTime, mission.endTime),
            agents_used: mission.agents.map(a => a.name),
            findings: mission.findings.map(f => ({
                ...f,
                cvss: f.cvss || 'N/A',
                severity: this.calculateSeverity(f.cvss)
            })),
            summary: {
                total_findings: mission.findings.length,
                critical: mission.findings.filter(f => f.severity === 'critical').length,
                high: mission.findings.filter(f => f.severity === 'high').length,
                medium: mission.findings.filter(f => f.severity === 'medium').length,
                low: mission.findings.filter(f => f.severity === 'low').length
            },
            generated_at: new Date().toISOString()
        };

        return { success: true, report };
    }

    /**
     * Calculate mission duration
     */
    calculateDuration(start, end) {
        const startDate = new Date(start);
        const endDate = end ? new Date(end) : new Date();
        const diff = endDate - startDate;
        const hours = Math.floor(diff / 3600000);
        const minutes = Math.floor((diff % 3600000) / 60000);
        return `${hours}h ${minutes}m`;
    }

    /**
     * Calculate severity from CVSS
     */
    calculateSeverity(cvss) {
        if (!cvss || cvss === 'N/A') return 'unknown';
        const score = parseFloat(cvss);
        if (score >= 9.0) return 'critical';
        if (score >= 7.0) return 'high';
        if (score >= 4.0) return 'medium';
        return 'low';
    }

    /**
     * Get service status
     */
    getStatus() {
        return {
            initialized: true,
            agentsCount: this.config.agents?.length || 0,
            activeMissions: this.activeAgents.size,
            globalConfig: this.config.global_config,
            hackerAIConnected: this.hackerAI?.getStatus()?.running || false,
            redTeamingEnabled: this.config.global_config?.red_teaming_enabled || false
        };
    }
}

// Singleton
let instance = null;

function getBugBountyService() {
    if (!instance) {
        instance = new BugBountyAgentsService();
    }
    return instance;
}

module.exports = { BugBountyAgentsService, getBugBountyService };
