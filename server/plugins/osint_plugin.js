/**
 * OSINT Expert Team 2025 - AnythingLLM Plugin
 * ============================================
 * Plugin custom pour AnythingLLM permettant d'exécuter
 * des investigations OSINT automatisées.
 * 
 * Équipe:
 * - qwen2.5-coder:7b (Analyste technique)
 * - mistral:7b-instruct (Stratège de renseignement)
 * 
 * Commandes:
 * - !osint <target> - Lancer une investigation complète
 * - !osint-step <step> <target> - Exécuter une étape spécifique
 * - !osint-tools - Lister les outils disponibles
 * - !osint-team - Afficher l'équipe
 */

const fs = require('fs');
const path = require('path');
const { exec, spawn } = require('child_process');

// Configuration
const CONFIG = {
    name: "OSINT_Expert_Team_2025",
    version: "1.0.0",
    
    // Paths
    pipelineScript: path.join(__dirname, 'scripts', 'osint_pipeline.py'),
    resultsDir: path.join(__dirname, 'osint_results'),
    teamConfig: path.join(__dirname, 'knowledge', 'osint_expert_team.json'),
    
    // Ollama
    ollamaUrl: process.env.OLLAMA_URL || 'http://localhost:11434',
    technicalModel: 'qwen2.5-coder:7b',
    strategistModel: 'mistral:7b-instruct',
    fallbackModel: 'qwen2.5:3b'
};

// Ensure directories exist
if (!fs.existsSync(CONFIG.resultsDir)) {
    fs.mkdirSync(CONFIG.resultsDir, { recursive: true });
}

/**
 * OSINT Expert Team Plugin for AnythingLLM
 */
class OSINTPlugin {
    constructor() {
        this.name = CONFIG.name;
        this.version = CONFIG.version;
        this.teamConfig = this.loadTeamConfig();
        this.activeInvestigations = new Map();
        
        console.log(`[${this.name}] Plugin v${this.version} loaded`);
    }

    /**
     * Load team configuration
     */
    loadTeamConfig() {
        try {
            if (fs.existsSync(CONFIG.teamConfig)) {
                return JSON.parse(fs.readFileSync(CONFIG.teamConfig, 'utf-8'));
            }
        } catch (error) {
            console.error(`[${this.name}] Failed to load team config:`, error.message);
        }
        return null;
    }

    /**
     * Plugin startup
     */
    startup() {
        console.log(`[${this.name}] Agent OSINT Expert Team Ready`);
        console.log(`[${this.name}] Team: ${this.teamConfig?.team?.length || 0} agents`);
        console.log(`[${this.name}] Tools: ${this.teamConfig?.tools?.length || 0} available`);
        
        return {
            success: true,
            message: `${this.name} initialized with ${this.teamConfig?.tools?.length || 0} OSINT tools`
        };
    }

    /**
     * Get plugin info
     */
    getInfo() {
        return {
            name: this.name,
            version: this.version,
            description: this.teamConfig?.description || "OSINT Expert Team for automated investigations",
            team: this.teamConfig?.team?.map(m => ({
                role: m.role,
                model: m.model_name,
                tools: m.tools_assigned
            })) || [],
            tools: this.teamConfig?.tools?.map(t => t.name) || [],
            commands: [
                { command: '!osint <target>', description: 'Start full OSINT investigation' },
                { command: '!osint-step <1-4> <target>', description: 'Execute specific workflow step' },
                { command: '!osint-tools', description: 'List available tools' },
                { command: '!osint-team', description: 'Show team members' },
                { command: '!osint-status', description: 'Check investigation status' }
            ]
        };
    }

    /**
     * Execute Ollama query
     */
    async queryOllama(model, prompt, options = {}) {
        const fetch = (await import('node-fetch')).default;
        
        try {
            const response = await fetch(`${CONFIG.ollamaUrl}/api/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: model,
                    prompt: prompt,
                    stream: false,
                    options: {
                        temperature: options.temperature || 0.4,
                        num_predict: options.maxTokens || 2000
                    }
                })
            });

            if (response.ok) {
                const data = await response.json();
                return { success: true, response: data.response };
            } else {
                // Try fallback model
                const fallbackResponse = await fetch(`${CONFIG.ollamaUrl}/api/generate`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        model: CONFIG.fallbackModel,
                        prompt: prompt,
                        stream: false
                    })
                });
                const data = await fallbackResponse.json();
                return { success: true, response: data.response, fallback: true };
            }
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * Run OSINT tool via command line
     */
    runTool(toolName, target) {
        return new Promise((resolve) => {
            const toolCommands = {
                'theHarvester': `theHarvester -d ${target} -l 100 -b google,bing`,
                'amass': `amass enum -passive -d ${target}`,
                'shodan': `shodan search "hostname:${target}"`,
                'nmap': `nmap -sV --top-ports 100 ${target}`,
                'whois': `whois ${target}`,
                'dig': `dig ${target} ANY +noall +answer`
            };

            const cmd = toolCommands[toolName];
            if (!cmd) {
                resolve({ success: false, error: `Unknown tool: ${toolName}` });
                return;
            }

            exec(cmd, { timeout: 120000 }, (error, stdout, stderr) => {
                resolve({
                    success: !error,
                    tool: toolName,
                    target: target,
                    output: stdout || stderr,
                    error: error?.message
                });
            });
        });
    }

    /**
     * Run Python pipeline
     */
    runPipeline(target, options = {}) {
        return new Promise((resolve) => {
            const investigationId = `inv_${Date.now()}`;
            
            let args = [CONFIG.pipelineScript, target];
            if (options.type) args.push('--type', options.type);
            if (options.step) args.push('--step', options.step);
            if (options.noAnalysis) args.push('--no-analysis');

            const process = spawn('python3', args, {
                cwd: path.dirname(CONFIG.pipelineScript)
            });

            let output = '';
            let error = '';

            process.stdout.on('data', (data) => {
                output += data.toString();
            });

            process.stderr.on('data', (data) => {
                error += data.toString();
            });

            process.on('close', (code) => {
                this.activeInvestigations.delete(investigationId);
                resolve({
                    success: code === 0,
                    investigationId,
                    target,
                    output,
                    error: code !== 0 ? error : null
                });
            });

            this.activeInvestigations.set(investigationId, {
                target,
                startTime: new Date().toISOString(),
                process
            });

            // Auto-timeout after 30 minutes
            setTimeout(() => {
                if (this.activeInvestigations.has(investigationId)) {
                    process.kill();
                    this.activeInvestigations.delete(investigationId);
                }
            }, 30 * 60 * 1000);
        });
    }

    /**
     * Main command handler for AnythingLLM
     */
    async handleCommand(command, args, context = {}) {
        const cmd = command.toLowerCase();

        switch (cmd) {
            case 'osint':
                return this.handleOsintCommand(args);
            
            case 'osint-step':
                return this.handleStepCommand(args);
            
            case 'osint-tools':
                return this.handleToolsCommand();
            
            case 'osint-team':
                return this.handleTeamCommand();
            
            case 'osint-status':
                return this.handleStatusCommand();
            
            case 'osint-analyze':
                return this.handleAnalyzeCommand(args);
            
            default:
                return {
                    success: false,
                    message: `Unknown command: ${cmd}. Use !osint-help for available commands.`
                };
        }
    }

    /**
     * Handle !osint command
     */
    async handleOsintCommand(args) {
        const target = args[0];
        if (!target) {
            return {
                success: false,
                message: "❌ Please provide a target. Example: `!osint example.com`"
            };
        }

        // Determine target type
        let targetType = 'domain';
        if (target.includes('@')) targetType = 'email';
        else if (/^\d+\.\d+\.\d+\.\d+$/.test(target)) targetType = 'ip';
        else if (!target.includes('.')) targetType = 'username';

        // Start investigation
        console.log(`[${this.name}] Starting investigation: ${target} (${targetType})`);

        // Quick reconnaissance with basic tools
        const quickResults = await this.quickRecon(target, targetType);

        // LLM Analysis
        const analysis = await this.analyzewithLLM(target, targetType, quickResults);

        return {
            success: true,
            message: this.formatInvestigationReport(target, targetType, quickResults, analysis)
        };
    }

    /**
     * Quick reconnaissance with available tools
     */
    async quickRecon(target, targetType) {
        const results = {
            target,
            targetType,
            timestamp: new Date().toISOString(),
            findings: {}
        };

        // Run quick checks based on target type
        if (targetType === 'domain') {
            // WHOIS
            const whois = await this.runTool('whois', target);
            if (whois.success) results.findings.whois = whois.output.substring(0, 1000);

            // DNS
            const dns = await this.runTool('dig', target);
            if (dns.success) results.findings.dns = dns.output;
        }

        return results;
    }

    /**
     * Analyze results with LLM
     */
    async analyzewithLLM(target, targetType, results) {
        const prompt = `## OSINT Investigation Analysis

Target: ${target}
Type: ${targetType}

Findings:
\`\`\`json
${JSON.stringify(results.findings, null, 2).substring(0, 3000)}
\`\`\`

As an OSINT expert, analyze these findings and provide:
1. Key information discovered
2. Potential attack vectors
3. Recommendations for deeper investigation
4. Risk assessment

Respond in French.`;

        const llmResult = await this.queryOllama(CONFIG.strategistModel, prompt);
        return llmResult.success ? llmResult.response : "Analyse LLM non disponible";
    }

    /**
     * Format investigation report
     */
    formatInvestigationReport(target, targetType, results, analysis) {
        return `
# 🔍 OSINT Investigation Report

## Target Information
- **Target:** \`${target}\`
- **Type:** ${targetType}
- **Timestamp:** ${results.timestamp}

## Quick Reconnaissance Results
${Object.entries(results.findings).map(([tool, output]) => `
### ${tool.toUpperCase()}
\`\`\`
${output.substring(0, 500)}${output.length > 500 ? '...' : ''}
\`\`\`
`).join('\n')}

## 🎯 AI Analysis
${analysis}

---
*Report generated by OSINT Expert Team 2025*
`;
    }

    /**
     * Handle !osint-step command
     */
    async handleStepCommand(args) {
        const step = parseInt(args[0]);
        const target = args[1];

        if (!step || !target || step < 1 || step > 4) {
            return {
                success: false,
                message: "❌ Usage: `!osint-step <1-4> <target>`"
            };
        }

        const stepNames = {
            1: "Recherche initiale (emails/domaines)",
            2: "Énumération passive et active",
            3: "Analyse de surface d'attaque",
            4: "Validation et corrélation"
        };

        return {
            success: true,
            message: `📋 Executing Step ${step}: ${stepNames[step]} for ${target}...`
        };
    }

    /**
     * Handle !osint-tools command
     */
    handleToolsCommand() {
        const tools = this.teamConfig?.tools || [];
        
        const toolsList = tools.map(t => 
            `- **${t.name}** (${t.category}): ${t.type}`
        ).join('\n');

        return {
            success: true,
            message: `
# 🛠️ Available OSINT Tools

${toolsList}

*Total: ${tools.length} tools*
`
        };
    }

    /**
     * Handle !osint-team command
     */
    handleTeamCommand() {
        const team = this.teamConfig?.team || [];
        
        const teamList = team.map(m => `
## ${m.emoji || '👤'} ${m.role}
- **Model:** \`${m.model_name}\`
- **Skills:** ${m.skills.join(', ')}
- **Tools:** ${m.tools_assigned.join(', ')}
`).join('\n');

        return {
            success: true,
            message: `
# 👥 OSINT Expert Team 2025

${teamList}
`
        };
    }

    /**
     * Handle !osint-status command
     */
    handleStatusCommand() {
        const active = Array.from(this.activeInvestigations.entries());
        
        if (active.length === 0) {
            return {
                success: true,
                message: "📊 No active investigations."
            };
        }

        const statusList = active.map(([id, inv]) => 
            `- **${id}**: ${inv.target} (started: ${inv.startTime})`
        ).join('\n');

        return {
            success: true,
            message: `
# 📊 Active Investigations

${statusList}
`
        };
    }

    /**
     * Handle !osint-analyze command - Analyze provided data
     */
    async handleAnalyzeCommand(args) {
        const data = args.join(' ');
        
        if (!data) {
            return {
                success: false,
                message: "❌ Please provide data to analyze."
            };
        }

        const prompt = `Analyze this OSINT data and provide insights:

${data}

Provide:
1. Key findings
2. Potential connections
3. Recommendations`;

        const result = await this.queryOllama(CONFIG.strategistModel, prompt);
        
        return {
            success: result.success,
            message: result.response || result.error
        };
    }
}

// Export for AnythingLLM
const osintPlugin = new OSINTPlugin();

module.exports = {
    name: osintPlugin.name,
    version: osintPlugin.version,
    description: "OSINT Expert Team 2025 - Automated OSINT Investigation Plugin",
    
    startup: () => osintPlugin.startup(),
    getInfo: () => osintPlugin.getInfo(),
    
    commands: {
        osint: (input) => osintPlugin.handleCommand('osint', input.split(' ')),
        'osint-step': (input) => osintPlugin.handleCommand('osint-step', input.split(' ')),
        'osint-tools': () => osintPlugin.handleCommand('osint-tools', []),
        'osint-team': () => osintPlugin.handleCommand('osint-team', []),
        'osint-status': () => osintPlugin.handleCommand('osint-status', []),
        'osint-analyze': (input) => osintPlugin.handleCommand('osint-analyze', input.split(' '))
    },
    
    // Direct access to plugin instance
    plugin: osintPlugin
};
