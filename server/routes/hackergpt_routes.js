/**
 * HackerGPT API Routes
 * Provides API endpoints for HackerGPT functionality
 */

const express = require('express');
const router = express.Router();
const { hackerGPTService, HACKERGPT_PERSONA } = require('../hackergpt_persona');

/**
 * GET /hackergpt/info
 * Get HackerGPT service information
 */
router.get('/info', (req, res) => {
    try {
        const info = hackerGPTService.getInfo();
        res.json({
            success: true,
            data: info
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /hackergpt/prompt
 * Get the system prompt for a specific mode
 */
router.get('/prompt', (req, res) => {
    try {
        const mode = req.query.mode || 'general';
        const prompt = hackerGPTService.getSystemPrompt(mode);
        res.json({
            success: true,
            mode,
            prompt
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /hackergpt/mode
 * Set the operational mode
 */
router.post('/mode', (req, res) => {
    try {
        const { mode } = req.body;
        const success = hackerGPTService.setMode(mode);

        if (success) {
            res.json({
                success: true,
                message: `Mode changed to ${mode.toUpperCase()}`,
                currentMode: mode
            });
        } else {
            res.status(400).json({
                success: false,
                error: 'Invalid mode',
                validModes: ['general', 'recon', 'exploit', 'report', 'osint']
            });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /hackergpt/tools
 * Get all available pentesting tools
 */
router.get('/tools', (req, res) => {
    try {
        const tools = hackerGPTService.getAllTools();
        res.json({
            success: true,
            count: tools.length,
            tools
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /hackergpt/tools/:name
 * Get specific tool information
 */
router.get('/tools/:name', (req, res) => {
    try {
        const tool = hackerGPTService.getTool(req.params.name);

        if (tool) {
            res.json({
                success: true,
                tool
            });
        } else {
            res.status(404).json({
                success: false,
                error: 'Tool not found'
            });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /hackergpt/report/template
 * Generate a vulnerability report template
 */
router.post('/report/template', (req, res) => {
    try {
        const { findings } = req.body;
        const template = hackerGPTService.generateReportTemplate(findings || []);
        res.json({
            success: true,
            report: template
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /hackergpt/cvss/:score
 * Classify severity based on CVSS score
 */
router.get('/cvss/:score', (req, res) => {
    try {
        const score = parseFloat(req.params.score);

        if (isNaN(score) || score < 0 || score > 10) {
            return res.status(400).json({
                success: false,
                error: 'Invalid CVSS score. Must be between 0 and 10.'
            });
        }

        const severity = hackerGPTService.classifySeverity(score);
        const reference = HACKERGPT_PERSONA.cvssReference[severity];

        res.json({
            success: true,
            score,
            severity,
            color: reference.color,
            range: `${reference.min} - ${reference.max}`
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /hackergpt/vulns
 * Get common vulnerability categories
 */
router.get('/vulns', (req, res) => {
    try {
        res.json({
            success: true,
            categories: HACKERGPT_PERSONA.vulnCategories
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

console.log('[HACKERGPT] API Routes loaded');

module.exports = router;
