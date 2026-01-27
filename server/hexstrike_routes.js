/**
 * HexStrike AI Routes
 * 
 * API endpoints for HexStrike security tools integration
 * Provides access to 150+ security tools through Gemini 3
 */

const express = require('express');
const router = express.Router();
const hexstrikeBridge = require('./hexstrike_bridge');
const geminiHexStrikeAgent = require('./gemini_hexstrike_agent');

// ============================================================================
// HEALTH & STATUS
// ============================================================================

/**
 * GET /api/hexstrike/health
 * Check HexStrike server status
 */
router.get('/health', async (req, res) => {
    try {
        const health = await hexstrikeBridge.checkHealth();
        res.json(health);
    } catch (error) {
        res.status(500).json({ status: 'error', error: error.message });
    }
});

/**
 * GET /api/hexstrike/tools
 * List all available security tools
 */
router.get('/tools', async (req, res) => {
    try {
        const tools = await hexstrikeBridge.listTools();
        res.json(tools);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/hexstrike/stats
 * Get agent statistics
 */
router.get('/stats', (req, res) => {
    try {
        const stats = geminiHexStrikeAgent.getStats();
        res.json({
            agent: stats,
            bridge: {
                baseUrl: hexstrikeBridge.baseUrl,
                isOnline: hexstrikeBridge.isOnline,
                lastHealthCheck: hexstrikeBridge.lastHealthCheck
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================================
// GEMINI-POWERED SECURITY AGENT
// ============================================================================

/**
 * POST /api/hexstrike/chat
 * Chat with Gemini HexStrike Agent (natural language security commands)
 */
router.post('/chat', async (req, res) => {
    try {
        const { message, context } = req.body;

        if (!message) {
            return res.status(400).json({ error: 'Message required' });
        }

        console.log('[HEXSTRIKE-API] Chat request:', message.substring(0, 100));

        const result = await geminiHexStrikeAgent.processRequest(message, context || {});

        res.json(result);
    } catch (error) {
        console.error('[HEXSTRIKE-API] Chat error:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /api/hexstrike/quick-scan
 * Quick security scan of a target
 */
router.post('/quick-scan', async (req, res) => {
    try {
        const { target } = req.body;

        if (!target) {
            return res.status(400).json({ error: 'Target required' });
        }

        console.log('[HEXSTRIKE-API] Quick scan:', target);

        const result = await geminiHexStrikeAgent.quickScan(target);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hexstrike/full-pentest
 * Full penetration test workflow
 */
router.post('/full-pentest', async (req, res) => {
    try {
        const { target, scope } = req.body;

        if (!target) {
            return res.status(400).json({ error: 'Target required' });
        }

        console.log('[HEXSTRIKE-API] Full pentest:', target, 'Scope:', scope);

        const result = await geminiHexStrikeAgent.fullPentest(target, scope || 'web');
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hexstrike/bug-bounty
 * Bug bounty reconnaissance workflow
 */
router.post('/bug-bounty', async (req, res) => {
    try {
        const { target } = req.body;

        if (!target) {
            return res.status(400).json({ error: 'Target required' });
        }

        console.log('[HEXSTRIKE-API] Bug bounty recon:', target);

        const result = await geminiHexStrikeAgent.bugBountyRecon(target);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hexstrike/cloud-audit
 * Cloud security audit
 */
router.post('/cloud-audit', async (req, res) => {
    try {
        const { provider, profile } = req.body;

        console.log('[HEXSTRIKE-API] Cloud audit:', provider || 'aws');

        const result = await geminiHexStrikeAgent.cloudAudit(
            provider || 'aws',
            profile || 'default'
        );
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hexstrike/web-test
 * Web application security test
 */
router.post('/web-test', async (req, res) => {
    try {
        const { url } = req.body;

        if (!url) {
            return res.status(400).json({ error: 'URL required' });
        }

        console.log('[HEXSTRIKE-API] Web app test:', url);

        const result = await geminiHexStrikeAgent.webAppTest(url);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * DELETE /api/hexstrike/history
 * Clear agent chat history
 */
router.delete('/history', (req, res) => {
    try {
        geminiHexStrikeAgent.clearHistory();
        res.json({ success: true, message: 'History cleared' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================================
// DIRECT TOOL EXECUTION
// ============================================================================

/**
 * POST /api/hexstrike/execute
 * Execute a specific security tool directly
 */
router.post('/execute', async (req, res) => {
    try {
        const { tool, params } = req.body;

        if (!tool) {
            return res.status(400).json({ error: 'Tool name required' });
        }

        console.log('[HEXSTRIKE-API] Direct execution:', tool);

        const result = await hexstrikeBridge.executeTool(tool, params || {});
        res.json({
            success: true,
            tool,
            result
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================================================
// NETWORK & RECONNAISSANCE
// ============================================================================

/**
 * POST /api/hexstrike/nmap
 * Nmap port scanning
 */
router.post('/nmap', async (req, res) => {
    try {
        const { target, scanType, ports, additionalArgs } = req.body;

        if (!target) {
            return res.status(400).json({ error: 'Target required' });
        }

        const result = await hexstrikeBridge.nmapScan(target, {
            scanType,
            ports,
            additionalArgs
        });
        res.json({ success: true, result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hexstrike/scan
 * Async Nmap scan with Redis Queue (returns job_id immediately)
 */
router.post('/scan', async (req, res) => {
    try {
        const { target, options } = req.body;

        if (!target) {
            return res.status(400).json({ error: 'Target required' });
        }

        console.log('[HEXSTRIKE-API] Async scan request:', target, options);

        // Forward to HexStrike container
        const hexstrikeUrl = process.env.HEXSTRIKE_URL || 'http://localhost:8888';
        const response = await fetch(`${hexstrikeUrl}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, options: options || '-F' })
        });

        const data = await response.json();
        res.json(data);
    } catch (error) {
        console.error('[HEXSTRIKE-API] Scan error:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/hexstrike/result/:jobId
 * Get async scan result by job ID
 */
router.get('/result/:jobId', async (req, res) => {
    try {
        const { jobId } = req.params;

        console.log('[HEXSTRIKE-API] Fetching result for job:', jobId);

        // Forward to HexStrike container
        const hexstrikeUrl = process.env.HEXSTRIKE_URL || 'http://localhost:8888';
        const response = await fetch(`${hexstrikeUrl}/result/${jobId}`);
        const data = await response.json();
        res.json(data);
    } catch (error) {
        console.error('[HEXSTRIKE-API] Result fetch error:', error);
        res.status(500).json({ status: 'error', error: error.message });
    }
});

/**
 * POST /api/hexstrike/amass
 * Subdomain enumeration
 */
router.post('/amass', async (req, res) => {
    try {
        const { domain, active } = req.body;

        if (!domain) {
            return res.status(400).json({ error: 'Domain required' });
        }

        const result = await hexstrikeBridge.amassEnum(domain, { active });
        res.json({ success: true, result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================================================
// WEB APPLICATION SECURITY
// ============================================================================

/**
 * POST /api/hexstrike/nuclei
 * Vulnerability scanning with Nuclei
 */
router.post('/nuclei', async (req, res) => {
    try {
        const { target, severity, tags, template } = req.body;

        if (!target) {
            return res.status(400).json({ error: 'Target required' });
        }

        const result = await hexstrikeBridge.nucleiScan(target, {
            severity,
            tags,
            template
        });
        res.json({ success: true, result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hexstrike/gobuster
 * Directory enumeration
 */
router.post('/gobuster', async (req, res) => {
    try {
        const { url, mode, wordlist } = req.body;

        if (!url) {
            return res.status(400).json({ error: 'URL required' });
        }

        const result = await hexstrikeBridge.gobusterScan(url, { mode, wordlist });
        res.json({ success: true, result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hexstrike/sqlmap
 * SQL injection testing
 */
router.post('/sqlmap', async (req, res) => {
    try {
        const { url, level, risk } = req.body;

        if (!url) {
            return res.status(400).json({ error: 'URL required' });
        }

        const result = await hexstrikeBridge.sqlmapScan(url, { level, risk });
        res.json({ success: true, result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================================================
// OSINT
// ============================================================================

/**
 * POST /api/hexstrike/sherlock
 * Username investigation across social networks
 */
router.post('/sherlock', async (req, res) => {
    try {
        const { username } = req.body;

        if (!username) {
            return res.status(400).json({ error: 'Username required' });
        }

        const result = await hexstrikeBridge.sherlockSearch(username);
        res.json({ success: true, result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================================================
// AI INTELLIGENCE
// ============================================================================

/**
 * POST /api/hexstrike/analyze-target
 * AI-powered target analysis
 */
router.post('/analyze-target', async (req, res) => {
    try {
        const { target, analysisType } = req.body;

        if (!target) {
            return res.status(400).json({ error: 'Target required' });
        }

        const result = await hexstrikeBridge.analyzeTarget(
            target,
            analysisType || 'comprehensive'
        );
        res.json({ success: true, result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hexstrike/select-tools
 * Get AI-recommended tools for a target
 */
router.post('/select-tools', async (req, res) => {
    try {
        const { target, objectives } = req.body;

        if (!target) {
            return res.status(400).json({ error: 'Target required' });
        }

        const result = await hexstrikeBridge.selectTools(
            target,
            objectives || ['vulnerability_assessment']
        );
        res.json({ success: true, result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================================================
// PROCESS MANAGEMENT
// ============================================================================

/**
 * GET /api/hexstrike/processes
 * List running processes
 */
router.get('/processes', async (req, res) => {
    try {
        const processes = await hexstrikeBridge.listProcesses();
        res.json(processes);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/hexstrike/processes/dashboard
 * Get process dashboard
 */
router.get('/processes/dashboard', async (req, res) => {
    try {
        const dashboard = await hexstrikeBridge.getProcessDashboard();
        res.json(dashboard);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/hexstrike/processes/:pid/terminate
 * Terminate a process
 */
router.post('/processes/:pid/terminate', async (req, res) => {
    try {
        const result = await hexstrikeBridge.terminateProcess(req.params.pid);
        res.json({ success: true, result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================================================
// CIPHERLINK SECURE FILE TRANSFER
// ============================================================================

/**
 * GET /api/hexstrike/cipherlink/status
 * Get CipherLink service status
 */
router.get('/cipherlink/status', async (req, res) => {
    try {
        const status = await hexstrikeBridge.getCipherLinkStatus();
        res.json(status);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/hexstrike/cipherlink/encrypt
 * Encrypt a file using AES-256
 */
router.post('/cipherlink/encrypt', async (req, res) => {
    try {
        const { filepath, password } = req.body;

        if (!filepath || !password) {
            return res.status(400).json({ error: 'filepath and password are required' });
        }

        const result = await hexstrikeBridge.encryptFile(filepath, password);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hexstrike/cipherlink/decrypt
 * Decrypt base64 data and save to file
 */
router.post('/cipherlink/decrypt', async (req, res) => {
    try {
        const { encrypted_data, iv, password, filename, output_dir } = req.body;

        if (!encrypted_data || !iv || !password || !filename) {
            return res.status(400).json({
                error: 'encrypted_data, iv, password, and filename are required'
            });
        }

        const result = await hexstrikeBridge.decryptFile(
            encrypted_data,
            iv,
            password,
            filename,
            output_dir
        );
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hexstrike/cipherlink/send
 * Send an encrypted file to a remote receiver
 */
router.post('/cipherlink/send', async (req, res) => {
    try {
        const { host, port, filepath, password, timeout } = req.body;

        if (!host || !port || !filepath || !password) {
            return res.status(400).json({
                error: 'host, port, filepath, and password are required'
            });
        }

        console.log(`[HEXSTRIKE-API] CipherLink send: ${filepath} -> ${host}:${port}`);

        const result = await hexstrikeBridge.sendSecureFile(
            host,
            parseInt(port),
            filepath,
            password,
            timeout || 30
        );
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hexstrike/cipherlink/receive/start
 * Start listening for incoming encrypted file
 */
router.post('/cipherlink/receive/start', async (req, res) => {
    try {
        const { port, password, save_dir, timeout } = req.body;

        if (!port || !password) {
            return res.status(400).json({ error: 'port and password are required' });
        }

        console.log(`[HEXSTRIKE-API] CipherLink receiver starting on port ${port}`);

        const result = await hexstrikeBridge.startReceiver(
            parseInt(port),
            password,
            save_dir,
            timeout || 300
        );
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hexstrike/cipherlink/receive/stop
 * Stop the file receiver
 */
router.post('/cipherlink/receive/stop', async (req, res) => {
    try {
        const result = await hexstrikeBridge.stopReceiver();
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/hexstrike/cipherlink/receive/result
 * Get the last receive operation result
 */
router.get('/cipherlink/receive/result', async (req, res) => {
    try {
        const result = await hexstrikeBridge.getReceiveResult();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


// ============================================================================
// LAZY TOOLKIT "5 TOOLS" AUTOMATION
// ============================================================================

const lazyService = require('./services/lazyToolkitService');

/**
 * POST /api/hexstrike/lazy/start
 * Start the 5-Tool Automated Pipeline
 */
router.post('/lazy/start', async (req, res) => {
    try {
        const { target } = req.body;
        if (!target) return res.status(400).json({ error: 'Target required' });

        const result = await lazyService.startPipeline(target);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/hexstrike/lazy/status/:jobId
 * Get status of Lazy Pipeline
 */
router.get('/lazy/status/:jobId', (req, res) => {
    const status = lazyService.getJobStatus(req.params.jobId);
    if (status.status === 'not_found') {
        return res.status(404).json({ error: 'Job not found' });
    }
    res.json(status);
});

module.exports = router;

