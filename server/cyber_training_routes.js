/**
 * Routes API pour le Cyber Training
 */

const express = require('express');
const router = express.Router();
const CyberTrainingService = require('./cyber_training_service');

const cyberTraining = new CyberTrainingService();

/**
 * POST /api/cyber-training/train
 * Entraîner l'agent sur un module
 */
router.post('/train', async (req, res) => {
    const { module, commands } = req.body;
    
    if (!module || !commands) {
        return res.status(400).json({ 
            success: false, 
            error: 'module et commands requis' 
        });
    }

    const result = await cyberTraining.trainOnModule(module, commands);
    res.json(result);
});

/**
 * POST /api/cyber-training/explain
 * Expliquer une commande
 */
router.post('/explain', async (req, res) => {
    const { command } = req.body;
    
    if (!command) {
        return res.status(400).json({ 
            success: false, 
            error: 'command requis' 
        });
    }

    const result = await cyberTraining.explainCommand(command);
    res.json(result);
});

/**
 * POST /api/cyber-training/scenario
 * Générer un scénario d'attaque
 */
router.post('/scenario', async (req, res) => {
    const { targetType } = req.body;
    const result = await cyberTraining.generateAttackScenario(targetType || 'web_server');
    res.json(result);
});

/**
 * POST /api/cyber-training/quiz
 * Quiz sur un sujet
 */
router.post('/quiz', async (req, res) => {
    const { topic } = req.body;
    
    if (!topic) {
        return res.status(400).json({ 
            success: false, 
            error: 'topic requis' 
        });
    }

    const result = await cyberTraining.quizAgent(topic);
    res.json(result);
});

// ============================================
// AIKIDO SECURITY ROUTES
// ============================================

const AikidoSecurityService = require('./aikido_security_service');
const aikido = new AikidoSecurityService();

/**
 * GET /api/cyber-training/aikido/summary
 * Résumé de sécurité (dashboard)
 */
router.get('/aikido/summary', async (req, res) => {
    const result = await aikido.getSecuritySummary();
    res.json(result);
});

/**
 * GET /api/cyber-training/aikido/issues
 * Liste des issues de sécurité
 */
router.get('/aikido/issues', async (req, res) => {
    const page = parseInt(req.query.page) || 0;
    const pageSize = parseInt(req.query.pageSize) || 25;
    const result = await aikido.getOpenIssues(page, pageSize);
    res.json(result);
});

/**
 * GET /api/cyber-training/aikido/issues/:id
 * Détails d'un issue
 */
router.get('/aikido/issues/:id', async (req, res) => {
    const result = await aikido.getIssueDetails(req.params.id);
    res.json(result);
});

/**
 * GET /api/cyber-training/aikido/repos
 * Liste des repositories scannés
 */
router.get('/aikido/repos', async (req, res) => {
    const result = await aikido.getRepositories();
    res.json(result);
});

/**
 * GET /api/cyber-training/aikido/repos/:id/sbom
 * SBOM d'un repository
 */
router.get('/aikido/repos/:id/sbom', async (req, res) => {
    const result = await aikido.getSBOM(req.params.id);
    res.json(result);
});

/**
 * GET /api/cyber-training/aikido/compliance/soc2
 * Statut de conformité SOC2
 */
router.get('/aikido/compliance/soc2', async (req, res) => {
    const result = await aikido.getSOC2Compliance();
    res.json(result);
});

/**
 * GET /api/cyber-training/aikido/compliance/iso27001
 * Statut de conformité ISO 27001
 */
router.get('/aikido/compliance/iso27001', async (req, res) => {
    const result = await aikido.getISO27001Compliance();
    res.json(result);
});

/**
 * GET /api/cyber-training/aikido/ci-scans
 * Liste des scans CI/CD récents
 */
router.get('/aikido/ci-scans', async (req, res) => {
    const page = parseInt(req.query.page) || 0;
    const result = await aikido.getCIScans(page);
    res.json(result);
});

/**
 * GET /api/cyber-training/aikido/report
 * Générer un rapport PDF
 */
router.get('/aikido/report', async (req, res) => {
    const result = await aikido.generateReport();
    res.json(result);
});

module.exports = router;
