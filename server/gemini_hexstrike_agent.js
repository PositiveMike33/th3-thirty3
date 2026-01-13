/**
 * Gemini 3 HexStrike Agent
 * 
 * Utilises Gemini (via Tor Proxy) to orchestrate 150+ HexStrike security tools.
 * Bypasses geo-restrictions using TorNetworkService.
 */

const { GoogleGenerativeAI } = require('@google/generative-ai');
const hexstrikeBridge = require('./hexstrike_bridge');
const settingsService = require('./settings_service');
const TorNetworkService = require('./tor_network_service');

class GeminiHexStrikeAgent {
    constructor() {
        this.initialized = false;
        this.apiKey = null;
        this.modelName = 'gemini-3-pro-preview'; // Explicitly requested by user.
        this.chatHistory = [];
        this.toolsUsed = [];
        this.torService = new TorNetworkService();
        this.useTor = true;

        // Initialize immediately if possible
        this.initialize();
    }

    async initialize(apiKeyOverride = null) {
        try {
            const settings = settingsService.getSettings();
            this.apiKey = apiKeyOverride || process.env.GEMINI_API_KEY || settings.apiKeys?.gemini || settings.apiKeys?.google;

            if (!this.apiKey) {
                console.warn('[GEMINI-HEXSTRIKE] ⚠️ GEMINI_API_KEY not found - Agent disabled');
                return false;
            }

            // Verify Tor Status
            const torStatus = await this.torService.checkTorStatus();
            if (torStatus.running) {
                console.log(`[GEMINI-HEXSTRIKE] 🛡️ Tor Proxy detected on port ${torStatus.port}`);
                this.useTor = true;
            } else {
                console.warn('[GEMINI-HEXSTRIKE] ⚠️ Tor not detected. Requests will likely fail (Geo-IP block).');
                // We'll keep useTor=true to try forcing it, or fallback logic could be added here.
            }

            this.initialized = true;
            console.log(`[GEMINI-HEXSTRIKE] ✅ Agent initialized with ${this.modelName}`);
            return true;
        } catch (error) {
            console.error('[GEMINI-HEXSTRIKE] ❌ Initialization failed:', error.message);
            return false;
        }
    }

    getSystemPrompt() {
        return `# HexStrike AI Security Agent

You are HexStrike AI, an elite cybersecurity automation agent with access to 150+ professional security tools. You help security researchers, pentesters, and bug bounty hunters perform authorized security assessments.

## 🔧 Available Tool Categories (Subset for Context)

### Network
- \`nmap_scan\`: Port scanning
- \`rustscan_scan\`: Fast scanning
- \`masscan_scan\`: Mass scanning

### Web
- \`nuclei_scan\`: Vulnerability scanning
- \`gobuster_scan\`: Directory enumeration
- \`ffuf_scan\`: Fuzzing
- \`sqlmap_scan\`: SQL injection
- \`wpscan_scan\`: WordPress

### Binary & Cloud
- \`ghidra_analyze\`, \`radare2_analyze\`
- \`prowler_scan\`, \`trivy_scan\`

## 🎯 Execution Protocol

1. **Analyze**: Understand the target.
2. **Plan**: Select tools.
3. **Execute**: Respond with JSON:
\`\`\`json
{
    "action": "execute_tool",
    "tool": "tool_name",
    "params": { "param1": "value" },
    "reason": "Why"
}
\`\`\`
4. **Analyze Results**: Interpret findings.

## 🚨 Risk Ratings
CRITICAL, HIGH, MEDIUM, LOW, INFO

## ⚖️ Ethics
ONLY test authorized targets.
`;
    }

    isReady() {
        return this.initialized && this.apiKey;
    }

    async callGeminiApi(contents, systemInstruction) {
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${this.modelName}:generateContent?key=${this.apiKey}`;

        const payload = {
            contents: contents,
            systemInstruction: { parts: [{ text: systemInstruction }] },
            generationConfig: {
                temperature: 0.7,
                maxOutputTokens: 8192
            }
        };

        const options = {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        };

        let response;
        if (this.useTor) {
            try {
                // Try using Tor Service
                response = await this.torService.torFetch(url, options);
            } catch (e) {
                console.warn('[GEMINI-HEXSTRIKE] Tor fetch failed, trying direct:', e.message);
                response = await fetch(url, options);
            }
        } else {
            response = await fetch(url, options);
        }

        if (!response.ok) {
            const errText = await response.text();
            throw new Error(`Gemini API Error (${response.status}): ${errText}`);
        }

        return await response.json();
    }

    async processRequest(userPrompt, context = {}) {
        if (!this.isReady()) {
            return { success: false, error: 'Agent not initialized (Check API Key)' };
        }

        // Check HexStrike Health
        const health = await hexstrikeBridge.checkHealth();
        if (health.status === 'offline') {
            return {
                success: false,
                error: `HexStrike server offline. Start with: python hexstrike_server.py`
            };
        }

        try {
            console.log('[GEMINI-HEXSTRIKE] 📨 Processing request:', userPrompt.substring(0, 100));

            // Prepare Chat History
            // If context.history is provided, use it, otherwise use local history
            let currentHistory = context.history || this.chatHistory;

            // Add User Prompt
            const newHistory = [...currentHistory, { role: 'user', parts: [{ text: userPrompt }] }];

            // Context enhancement
            const systemPrompt = this.getSystemPrompt() + (context.includeToolContext ? `\n\n[System] Current Tools: 150+ Available via HexStrike API.` : "");

            // Call API
            const apiResponse = await this.callGeminiApi(newHistory, systemPrompt);

            // Extract text
            let responseText = apiResponse.candidates?.[0]?.content?.parts?.[0]?.text || "";
            if (!responseText) {
                throw new Error('No response text from Gemini');
            }

            // Execute Tools
            const toolResults = await this.executeToolsFromResponse(responseText, newHistory, systemPrompt);

            // Update History
            this.chatHistory = [
                ...newHistory,
                { role: 'model', parts: [{ text: responseText }] }
            ];

            // If tools were executed and we have a final response from the tool analysis loop
            if (toolResults.finalResponse && toolResults.finalResponse !== responseText) {
                this.chatHistory.push({ role: 'model', parts: [{ text: toolResults.finalResponse }] });
                responseText = toolResults.finalResponse;
            }

            // Trim history
            if (this.chatHistory.length > 40) this.chatHistory = this.chatHistory.slice(-40);

            return {
                success: true,
                response: responseText,
                toolsExecuted: toolResults.toolsExecuted,
                findings: toolResults.findings,
                history: this.chatHistory
            };

        } catch (error) {
            console.error('[GEMINI-HEXSTRIKE] ❌ Error:', error.message);
            return { success: false, error: error.message };
        }
    }

    async executeToolsFromResponse(response, history, systemPrompt) {
        const toolExecutions = [];
        const findings = [];
        let finalResponse = response;

        // Find JSON blocks
        const toolMatches = response.matchAll(/```json\s*({[\s\S]*?})\s*```/g);

        for (const match of toolMatches) {
            try {
                const toolRequest = JSON.parse(match[1]);

                if (toolRequest.action === 'execute_tool' && toolRequest.tool) {
                    console.log(`[GEMINI-HEXSTRIKE] 🔧 Executing: ${toolRequest.tool}`);

                    const startTime = Date.now();
                    const result = await hexstrikeBridge.executeTool(
                        toolRequest.tool,
                        toolRequest.params || {}
                    );
                    const duration = Date.now() - startTime;

                    toolExecutions.push({
                        tool: toolRequest.tool,
                        params: toolRequest.params,
                        reason: toolRequest.reason,
                        duration: duration,
                        success: !result.error
                    });

                    this.toolsUsed.push(toolRequest.tool);

                    // Re-feed result to Gemini
                    const analysisPrompt = `
Tool: ${toolRequest.tool}
Execution Time: ${duration}ms
Results:
\`\`\`
${JSON.stringify(result, null, 2).substring(0, 10000)}
\`\`\`

Analyze these results. Identify findings, vulnerabilities, and next steps.`;

                    // Add tool result as user message (simulating feedback loop)
                    const analysisHistory = [
                        ...history,
                        { role: 'model', parts: [{ text: response }] },
                        { role: 'user', parts: [{ text: analysisPrompt }] }
                    ];

                    const analysisApiRes = await this.callGeminiApi(analysisHistory, systemPrompt);
                    const analysisText = analysisApiRes.candidates?.[0]?.content?.parts?.[0]?.text || "Analysis failed.";

                    findings.push({
                        tool: toolRequest.tool,
                        analysis: analysisText,
                        rawResult: result
                    });

                    finalResponse = analysisText;
                }
            } catch (err) {
                console.warn('[GEMINI-HEXSTRIKE] Tool execution error:', err.message);
            }
        }

        return {
            toolsExecuted: toolExecutions,
            findings,
            finalResponse
        };
    }

    // Convenience methods
    async quickScan(target) {
        return this.processRequest(`Perform a quick security reconnaissance on: ${target}`, { includeToolContext: true });
    }

    async fullPentest(target, scope = 'web') {
        return this.processRequest(`Conduct a comprehensive penetration test on: ${target} (Scope: ${scope})`, { includeToolContext: true });
    }

    async bugBountyRecon(target) {
        return this.processRequest(`Start bug bounty reconnaissance for: ${target}`, { includeToolContext: true });
    }

    async cloudAudit(provider = 'aws', profile = 'default') {
        return this.processRequest(`Perform cloud security audit for ${provider} (Profile: ${profile})`, { includeToolContext: true });
    }

    async webAppTest(url) {
        return this.processRequest(`Perform web application security testing on: ${url}`, { includeToolContext: true });
    }

    getHistory() { return this.chatHistory; }
    clearHistory() { this.chatHistory = []; this.toolsUsed = []; }
    getStats() {
        return {
            initialized: this.initialized,
            historyLength: this.chatHistory.length,
            toolsUsed: this.toolsUsed,
            torEnabled: this.useTor
        };
    }
}

module.exports = new GeminiHexStrikeAgent();
