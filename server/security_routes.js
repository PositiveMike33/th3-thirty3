/**
 * Security Research API Routes
 * =============================
 * API endpoints for defensive cybersecurity operations
 * All queries use professional system prompts with ethical context
 */

const express = require('express');
const router = express.Router();
const { SECURITY_RESEARCH_PROMPTS, getSecurityPrompt, buildSecurityQuery } = require('./security_research_prompts');

let llmService = null;

// Setter for dependency injection
router.setLLMService = (service) => {
    llmService = service;
    console.log('[SECURITY_ROUTES] LLM Service connected');
};

/**
 * GET /api/security/roles
 * List all available security research roles
 */
router.get('/roles', (req, res) => {
    res.json({
        success: true,
        roles: [
            { 
                id: 'reverseEngineer', 
                name: 'Reverse Engineer', 
                model: 'qwen2.5-coder:7b', 
                description: 'Analyse de binaires, malware, décompilation, Ghidra/IDA Pro',
                expertise: ['Binary Analysis', 'Malware Analysis', 'Decompilation', 'Protocol Reverse Engineering']
            },
            { 
                id: 'pentester', 
                name: 'Penetration Tester', 
                model: 'qwen2.5-coder:7b', 
                description: 'Tests de pénétration autorisés, exploitation, post-exploitation',
                expertise: ['Metasploit', 'Burp Suite', 'Network Pentesting', 'Web Application Testing']
            },
            { 
                id: 'vulnResearcher', 
                name: 'Vulnerability Researcher', 
                model: 'qwen2.5-coder:7b', 
                description: 'Recherche de CVE, fuzzing, bug bounty',
                expertise: ['CVE Analysis', 'Fuzzing', 'PoC Development', 'Responsible Disclosure']
            },
            { 
                id: 'networkAnalyst', 
                name: 'Network Security Analyst', 
                model: 'mistral:7b-instruct', 
                description: 'Analyse de trafic, forensics réseau, SOC',
                expertise: ['Wireshark', 'Snort/Suricata', 'Traffic Analysis', 'Incident Response']
            },
            { 
                id: 'osintInvestigator', 
                name: 'OSINT Investigator', 
                model: 'mistral:7b-instruct', 
                description: 'Renseignement en sources ouvertes, reconnaissance',
                expertise: ['theHarvester', 'Maltego', 'Shodan', 'Social Media Investigation']
            }
        ],
        disclaimer: 'All queries are processed in defensive security research context for authorized systems only.'
    });
});

/**
 * POST /api/security/query
 * Execute a security research query with professional context
 * 
 * Body: {
 *   query: "How do I analyze this suspicious binary?",
 *   role: "reverseEngineer",        // Optional, defaults to 'pentester'
 *   provider: "local",              // Optional
 *   model: "qwen2.5-coder:7b"       // Optional, uses role default
 * }
 */
router.post('/query', async (req, res) => {
    if (!llmService) {
        return res.status(503).json({ 
            error: 'LLM Service not initialized',
            suggestion: 'Ensure the server is fully started'
        });
    }
    
    const { query, role = 'pentester', provider = 'local', model = null } = req.body;
    
    if (!query || query.trim().length === 0) {
        return res.status(400).json({ error: 'Query is required and cannot be empty' });
    }
    
    // Validate role
    const validRoles = Object.keys(SECURITY_RESEARCH_PROMPTS);
    if (!validRoles.includes(role)) {
        return res.status(400).json({ 
            error: `Invalid role "${role}"`,
            validRoles 
        });
    }
    
    try {
        console.log(`[SECURITY_ROUTES] Query received - Role: ${role}, Provider: ${provider}`);
        
        const startTime = Date.now();
        const response = await llmService.generateSecurityResponse(query, role, provider, model);
        const responseTime = Date.now() - startTime;
        
        res.json({
            success: true,
            role,
            context: 'defensive_security_research',
            provider,
            model: model || getSecurityPrompt(role).model,
            responseTime: `${responseTime}ms`,
            response
        });
        
    } catch (error) {
        console.error('[SECURITY_ROUTES] Error:', error.message);
        res.status(500).json({
            success: false,
            error: error.message,
            suggestion: 'Check if Ollama is running and the model is available'
        });
    }
});

/**
 * POST /api/security/analyze
 * Analyze a specific artifact (code, log, traffic dump)
 * 
 * Body: {
 *   artifact: "code/log/pcap content...",
 *   artifactType: "code" | "log" | "network" | "binary",
 *   question: "What vulnerabilities exist here?",
 *   role: "vulnResearcher"
 * }
 */
router.post('/analyze', async (req, res) => {
    if (!llmService) {
        return res.status(503).json({ error: 'LLM Service not initialized' });
    }
    
    const { artifact, artifactType = 'code', question = 'Analyze this artifact', role = 'vulnResearcher' } = req.body;
    
    if (!artifact) {
        return res.status(400).json({ error: 'Artifact content is required' });
    }
    
    // Build analysis prompt
    const analysisPrompt = `
=== ARTIFACT ANALYSIS REQUEST ===
Type: ${artifactType.toUpperCase()}
Question: ${question}

--- ARTIFACT START ---
${artifact.substring(0, 10000)}
--- ARTIFACT END ---

Provide a detailed security analysis of this artifact. 
Identify vulnerabilities, suspicious patterns, and recommend mitigations.
`;

    try {
        const response = await llmService.generateSecurityResponse(analysisPrompt, role);
        res.json({
            success: true,
            artifactType,
            role,
            analysis: response
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /api/security/prompts
 * Get the raw system prompts (for transparency)
 */
router.get('/prompts', (req, res) => {
    const prompts = {};
    for (const [role, config] of Object.entries(SECURITY_RESEARCH_PROMPTS)) {
        prompts[role] = {
            model: config.model,
            systemPromptPreview: config.systemPrompt.substring(0, 200) + '...'
        };
    }
    res.json({
        success: true,
        note: 'These are professional security research prompts for defensive purposes',
        prompts
    });
});

module.exports = router;
