/**
 * Routes API pour le KPI Dashboard - Pilier XI Codex Operandi
 */

const express = require('express');
const router = express.Router();
const KPIDashboardService = require('./kpi_dashboard_service');

const dashboard = new KPIDashboardService();

/**
 * GET /api/dashboard/summary
 * Résumé global du dashboard avec Indice de Souveraineté
 */
router.get('/summary', async (req, res) => {
    try {
        const result = await dashboard.getDashboardSummary();
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/dashboard/security
 * Métriques de sécurité détaillées
 */
router.get('/security', async (req, res) => {
    try {
        const result = await dashboard.getSecurityMetrics();
        res.json({ success: true, data: result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/dashboard/productivity
 * Métriques de productivité
 */
router.get('/productivity', async (req, res) => {
    try {
        const result = await dashboard.getProductivityMetrics();
        res.json({ success: true, data: result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/dashboard/bio
 * Métriques bio-optimisation
 */
router.get('/bio', async (req, res) => {
    try {
        const result = await dashboard.getBioMetrics();
        res.json({ success: true, data: result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/dashboard/bio
 * Mettre à jour les métriques bio
 */
router.post('/bio', async (req, res) => {
    try {
        const result = await dashboard.updateBioMetrics(req.body);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/dashboard/compliance
 * Métriques de conformité
 */
router.get('/compliance', async (req, res) => {
    try {
        const result = await dashboard.getComplianceMetrics();
        res.json({ success: true, data: result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/dashboard/weekly-report
 * Rapport OODA hebdomadaire (Pilier XVIII)
 */
router.get('/weekly-report', async (req, res) => {
    try {
        const result = await dashboard.generateWeeklyReport();
        res.json({ success: true, data: result });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;
