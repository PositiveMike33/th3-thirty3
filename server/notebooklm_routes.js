/**
 * NOTEBOOKLM API ROUTES
 * Routes for the NotebookLM integration service
 */

const express = require('express');
const router = express.Router();
const NotebookLMService = require('./notebooklm_service');

let notebookLMService = null;

// Initialize with LLM Service
function initializeRoutes(llmService) {
    notebookLMService = new NotebookLMService(llmService);
    console.log('[NOTEBOOKLM] Routes initialized');
    return router;
}

// ================================
// DOMAIN ENDPOINTS
// ================================

// GET /api/notebooklm/domains - List all domains
router.get('/domains', async (req, res) => {
    try {
        const domains = await notebookLMService.listDomains();
        res.json({ success: true, domains });
    } catch (error) {
        console.error('[NOTEBOOKLM] Error listing domains:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// GET /api/notebooklm/domains/:domain - Get domain content
router.get('/domains/:domain', async (req, res) => {
    try {
        const { domain } = req.params;
        const content = await notebookLMService.getDomainContent(domain);
        res.json({ success: true, domain, content });
    } catch (error) {
        console.error(`[NOTEBOOKLM] Error getting domain ${req.params.domain}:`, error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ================================
// CONTENT ENDPOINTS
// ================================

// POST /api/notebooklm/content - Add content to a domain
router.post('/content', async (req, res) => {
    try {
        const { domain, title, content, metadata } = req.body;
        
        if (!domain || !title || !content) {
            return res.status(400).json({ 
                success: false, 
                error: 'domain, title, and content are required' 
            });
        }

        const result = await notebookLMService.addContent(domain, title, content, metadata || {});
        res.json({ success: true, file: result });
    } catch (error) {
        console.error('[NOTEBOOKLM] Error adding content:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// POST /api/notebooklm/import - Import content from text
router.post('/import', async (req, res) => {
    try {
        const { domain, title, text } = req.body;
        
        if (!domain || !title || !text) {
            return res.status(400).json({ 
                success: false, 
                error: 'domain, title, and text are required' 
            });
        }

        const result = await notebookLMService.importFromText(domain, title, text);
        res.json({ success: true, file: result });
    } catch (error) {
        console.error('[NOTEBOOKLM] Error importing content:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ================================
// LESSON ENDPOINTS
// ================================

// GET /api/notebooklm/lessons - Get cached lessons
router.get('/lessons', async (req, res) => {
    try {
        const { domain } = req.query;
        const lessons = notebookLMService.getCachedLessons(domain || null);
        res.json({ success: true, lessons });
    } catch (error) {
        console.error('[NOTEBOOKLM] Error getting lessons:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// POST /api/notebooklm/generate-lesson - Generate a lesson from domain content
router.post('/generate-lesson', async (req, res) => {
    try {
        const { domain, topic } = req.body;
        
        if (!domain) {
            return res.status(400).json({ 
                success: false, 
                error: 'domain is required' 
            });
        }

        console.log(`[NOTEBOOKLM] Generating lesson for domain: ${domain}, topic: ${topic || 'auto'}`);
        const lesson = await notebookLMService.generateLesson(domain, topic || null);
        res.json({ success: true, lesson });
    } catch (error) {
        console.error('[NOTEBOOKLM] Error generating lesson:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ================================
// PODCAST ENDPOINTS
// ================================

// POST /api/notebooklm/podcast - Generate a podcast summary
router.post('/podcast', async (req, res) => {
    try {
        const { domain } = req.body;
        
        if (!domain) {
            return res.status(400).json({ 
                success: false, 
                error: 'domain is required' 
            });
        }

        console.log(`[NOTEBOOKLM] Generating podcast for domain: ${domain}`);
        const podcast = await notebookLMService.generatePodcastSummary(domain);
        res.json({ success: true, podcast });
    } catch (error) {
        console.error('[NOTEBOOKLM] Error generating podcast:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ================================
// TEACHING ENDPOINTS
// ================================

// POST /api/notebooklm/teach - Teach a model with domain content
router.post('/teach', async (req, res) => {
    try {
        const { studentModel, domain, options } = req.body;
        
        if (!studentModel || !domain) {
            return res.status(400).json({ 
                success: false, 
                error: 'studentModel and domain are required' 
            });
        }

        console.log(`[NOTEBOOKLM] Teaching model ${studentModel} with domain: ${domain}`);
        const result = await notebookLMService.teachModel(studentModel, domain, options || {});
        res.json({ success: true, result });
    } catch (error) {
        console.error('[NOTEBOOKLM] Error teaching model:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = { router, initializeRoutes };
