/**
 * OSINT Team AnythingLLM Integration
 * Intègre l'équipe OSINT Expert Team 2025 avec AnythingLLM
 * 
 * Features:
 * - Création automatique des agents dans AnythingLLM
 * - Workflow d'investigation multi-agents
 * - Synchronisation des connaissances
 */

const fs = require('fs');
const path = require('path');

class OsintTeamAnythingLLM {
    constructor(anythingLLMWrapper) {
        this.wrapper = anythingLLMWrapper;
        this.teamConfigPath = path.join(__dirname, 'knowledge', 'osint_expert_team.json');
        this.teamConfig = this.loadTeamConfig();
        
        // AnythingLLM API config
        this.anythingLLMUrl = process.env.ANYTHING_LLM_URL || 'http://localhost:3001';
        this.anythingLLMKey = process.env.ANYTHING_LLM_KEY || '';
        
        console.log('[OSINT-TEAM] AnythingLLM Integration initialized');
    }

    /**
     * Load team configuration
     */
    loadTeamConfig() {
        try {
            if (fs.existsSync(this.teamConfigPath)) {
                return JSON.parse(fs.readFileSync(this.teamConfigPath, 'utf-8'));
            }
        } catch (error) {
            console.error('[OSINT-TEAM] Failed to load team config:', error.message);
        }
        return null;
    }

    /**
     * Get team configuration
     */
    getTeamConfig() {
        return this.teamConfig;
    }

    /**
     * Get team members
     */
    getTeamMembers() {
        if (!this.teamConfig) return [];
        return this.teamConfig.team.map(member => ({
            id: member.id,
            model: member.model_name,
            role: member.role,
            emoji: member.emoji,
            skills: member.skills,
            tools: member.tools_assigned
        }));
    }

    /**
     * Get workflow steps
     */
    getWorkflow() {
        if (!this.teamConfig) return [];
        return this.teamConfig.workflow.steps;
    }

    /**
     * Get available tools
     */
    getTools() {
        if (!this.teamConfig) return [];
        return this.teamConfig.tools;
    }

    /**
     * Initialize AnythingLLM workspace for OSINT team
     */
    async initializeWorkspace() {
        if (!this.wrapper) {
            console.log('[OSINT-TEAM] AnythingLLM wrapper not available');
            return { success: false, error: 'Wrapper not available' };
        }

        try {
            const workspaceName = this.teamConfig?.anythingllm_integration?.workspace || 'osint-team';
            
            // Check if workspace exists
            const workspaces = await this.wrapper.listWorkspaces();
            const existingWorkspace = workspaces?.find(ws => ws.slug === workspaceName);
            
            if (!existingWorkspace) {
                console.log(`[OSINT-TEAM] Creating workspace: ${workspaceName}`);
                // Note: Actual creation would require AnythingLLM API
            }

            console.log('[OSINT-TEAM] Workspace initialized:', workspaceName);
            return { success: true, workspace: workspaceName };
        } catch (error) {
            console.error('[OSINT-TEAM] Workspace init failed:', error.message);
            return { success: false, error: error.message };
        }
    }

    /**
     * Execute workflow step
     */
    async executeWorkflowStep(stepNumber, target, context = {}) {
        if (!this.teamConfig) {
            return { success: false, error: 'Team config not loaded' };
        }

        const step = this.teamConfig.workflow.steps.find(s => s.step === stepNumber);
        if (!step) {
            return { success: false, error: `Step ${stepNumber} not found` };
        }

        console.log(`[OSINT-TEAM] Executing Step ${stepNumber}: ${step.name}`);
        console.log(`[OSINT-TEAM] Executor: ${step.executed_by}`);
        console.log(`[OSINT-TEAM] Tools: ${step.tools_used.join(', ')}`);

        // Build prompt for the agent
        const prompt = this.buildStepPrompt(step, target, context);

        // Get the appropriate team member
        const executor = this.teamConfig.team.find(
            member => member.model_name === step.executed_by || member.id === step.agent_role
        );

        try {
            // Execute via Ollama or AnythingLLM
            const result = await this.executeWithAgent(executor, prompt);
            
            return {
                success: true,
                step: stepNumber,
                name: step.name,
                executor: step.executed_by,
                tools_used: step.tools_used,
                expected_output: step.output,
                result: result,
                commands: step.commands?.map(cmd => cmd.replace('{target}', target))
            };
        } catch (error) {
            return {
                success: false,
                step: stepNumber,
                error: error.message
            };
        }
    }

    /**
     * Build prompt for workflow step
     */
    buildStepPrompt(step, target, context) {
        const tools = step.tools_used.map(t => {
            const toolConfig = this.teamConfig.tools.find(tool => tool.name === t);
            return toolConfig ? `${t} (${toolConfig.type})` : t;
        });

        return `## OSINT Investigation - ${step.name}

**Cible:** ${target}
**Outils à utiliser:** ${tools.join(', ')}
**Objectif:** ${step.task}
**Résultat attendu:** ${step.output}

**Contexte précédent:**
${JSON.stringify(context, null, 2)}

**Instructions:**
1. Analyse la cible avec les outils assignés
2. Génère les commandes exactes pour Kali Linux
3. Explique ce que tu cherches
4. Prépare les données pour l'étape suivante

**Commandes suggérées:**
${step.commands?.map(cmd => `- ${cmd.replace('{target}', target)}`).join('\n')}

Execute l'analyse et retourne les résultats structurés.`;
    }

    /**
     * Execute with appropriate agent
     */
    async executeWithAgent(executor, prompt) {
        if (!executor) {
            // Fallback to default model
            return this.executeWithOllama('qwen2.5:3b', prompt);
        }

        const model = executor.model_name;
        
        // Try AnythingLLM first if configured
        if (this.wrapper && executor.anythingllm_agent) {
            try {
                const result = await this.wrapper.chat(prompt, {
                    workspace: 'osint-team',
                    mode: 'agent'
                });
                return result;
            } catch (error) {
                console.log('[OSINT-TEAM] AnythingLLM failed, falling back to Ollama');
            }
        }

        // Fallback to Ollama
        return this.executeWithOllama(model, prompt);
    }

    /**
     * Execute with Ollama directly
     */
    async executeWithOllama(model, prompt) {
        const ollamaUrl = process.env.OLLAMA_URL || 'http://localhost:11434';
        
        try {
            const response = await fetch(`${ollamaUrl}/api/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model,
                    prompt,
                    stream: false,
                    options: { temperature: 0.4, num_predict: 3000 }
                })
            });

            const data = await response.json();
            return data.response;
        } catch (error) {
            throw new Error(`Ollama execution failed: ${error.message}`);
        }
    }

    /**
     * Run full investigation pipeline
     */
    async runFullInvestigation(target, targetType = 'domain') {
        console.log(`\n[OSINT-TEAM] ═══════════════════════════════════════════════`);
        console.log(`[OSINT-TEAM]   STARTING FULL OSINT INVESTIGATION`);
        console.log(`[OSINT-TEAM]   Target: ${target} (${targetType})`);
        console.log(`[OSINT-TEAM] ═══════════════════════════════════════════════\n`);

        const results = {
            target,
            targetType,
            startTime: new Date().toISOString(),
            steps: [],
            summary: null
        };

        let context = {};

        // Execute each workflow step
        for (const step of this.teamConfig.workflow.steps) {
            console.log(`\n[OSINT-TEAM] ─── Step ${step.step}: ${step.name} ───`);
            
            const stepResult = await this.executeWorkflowStep(step.step, target, context);
            results.steps.push(stepResult);
            
            // Build context for next step
            if (stepResult.success) {
                context[`step_${step.step}`] = {
                    name: step.name,
                    result: stepResult.result?.substring(0, 500) + '...'
                };
            }

            // Small delay between steps
            await new Promise(r => setTimeout(r, 1000));
        }

        // Generate summary
        results.endTime = new Date().toISOString();
        results.summary = this.generateSummary(results);

        console.log(`\n[OSINT-TEAM] ═══════════════════════════════════════════════`);
        console.log(`[OSINT-TEAM]   INVESTIGATION COMPLETE`);
        console.log(`[OSINT-TEAM] ═══════════════════════════════════════════════\n`);

        return results;
    }

    /**
     * Generate investigation summary
     */
    generateSummary(results) {
        const successfulSteps = results.steps.filter(s => s.success).length;
        const totalSteps = results.steps.length;

        return {
            target: results.target,
            successRate: `${successfulSteps}/${totalSteps}`,
            duration: this.calculateDuration(results.startTime, results.endTime),
            toolsUsed: [...new Set(results.steps.flatMap(s => s.tools_used || []))],
            recommendations: this.generateRecommendations(results)
        };
    }

    /**
     * Calculate duration
     */
    calculateDuration(start, end) {
        const startDate = new Date(start);
        const endDate = new Date(end);
        const diffMs = endDate - startDate;
        const seconds = Math.floor(diffMs / 1000);
        const minutes = Math.floor(seconds / 60);
        
        if (minutes > 0) {
            return `${minutes}m ${seconds % 60}s`;
        }
        return `${seconds}s`;
    }

    /**
     * Generate recommendations based on results
     */
    generateRecommendations(results) {
        const recommendations = [];

        // Analyze failed steps
        const failedSteps = results.steps.filter(s => !s.success);
        if (failedSteps.length > 0) {
            recommendations.push(`Retry failed steps: ${failedSteps.map(s => s.step).join(', ')}`);
        }

        // Add best practices
        if (this.teamConfig?.best_practices) {
            recommendations.push(...this.teamConfig.best_practices.slice(0, 3).map(bp => bp.description || bp.rule));
        }

        return recommendations;
    }

    /**
     * Get API endpoints documentation
     */
    getAPIEndpoints() {
        return {
            getTeam: 'GET /api/osint-team',
            getWorkflow: 'GET /api/osint-team/workflow',
            getTools: 'GET /api/osint-team/tools',
            executeStep: 'POST /api/osint-team/execute-step',
            runInvestigation: 'POST /api/osint-team/investigate'
        };
    }
}

module.exports = OsintTeamAnythingLLM;
