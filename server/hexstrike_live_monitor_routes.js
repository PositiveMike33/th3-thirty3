/**
 * HexStrike Live Monitor Routes
 * 
 * API pour contrôler le moniteur d'entraînement en temps réel
 */

const express = require('express');
const router = express.Router();
const HexStrikeLiveMonitor = require('./hexstrike_live_monitor');

// Instance singleton du monitor
let monitor = null;
let lessons = []; // Historique des dernières leçons

function getMonitor() {
    if (!monitor) {
        monitor = new HexStrikeLiveMonitor();

        // Écouter les événements
        monitor.on('monitor:lesson', (lesson) => {
            lessons.unshift(lesson);
            // Garder seulement les 50 dernières leçons
            if (lessons.length > 50) {
                lessons = lessons.slice(0, 50);
            }
            console.log(`[MONITOR-ROUTE] New lesson: ${lesson.expert}`);
        });

        monitor.on('monitor:error', (error) => {
            console.error(`[MONITOR-ROUTE] Error:`, error);
        });
    }
    return monitor;
}

/**
 * GET /api/live-monitor/status
 * Obtenir le statut du monitor
 */
router.get('/status', (req, res) => {
    const m = getMonitor();
    res.json({
        status: m.getStatus(),
        lessonsCount: lessons.length,
        lastLesson: lessons[0] || null
    });
});

/**
 * POST /api/live-monitor/start
 * Démarrer le monitoring continu
 */
router.post('/start', (req, res) => {
    const { intervalSeconds = 30 } = req.body;
    const m = getMonitor();

    if (m.isRunning) {
        return res.json({ success: false, message: 'Monitor already running' });
    }

    m.start(intervalSeconds);
    res.json({
        success: true,
        message: `Monitor started with ${intervalSeconds}s interval`,
        status: m.getStatus()
    });
});

/**
 * POST /api/live-monitor/stop
 * Arrêter le monitoring
 */
router.post('/stop', (req, res) => {
    const m = getMonitor();
    m.stop();
    res.json({
        success: true,
        message: 'Monitor stopped',
        status: m.getStatus()
    });
});

/**
 * GET /api/live-monitor/lessons
 * Obtenir l'historique des leçons
 */
router.get('/lessons', (req, res) => {
    const limit = parseInt(req.query.limit) || 20;
    res.json({
        count: lessons.length,
        lessons: lessons.slice(0, limit)
    });
});

/**
 * GET /api/live-monitor/lessons/latest
 * Obtenir la dernière leçon
 */
router.get('/lessons/latest', (req, res) => {
    if (lessons.length === 0) {
        return res.json({ lesson: null, message: 'No lessons yet' });
    }
    res.json({ lesson: lessons[0] });
});

/**
 * POST /api/live-monitor/teach/:expertId
 * Forcer une leçon sur un expert spécifique
 */
router.post('/teach/:expertId', async (req, res) => {
    const m = getMonitor();
    try {
        const lesson = await m.teachExpert(req.params.expertId);
        lessons.unshift(lesson);
        res.json({ success: true, lesson });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/live-monitor/experts
 * Liste des experts disponibles
 */
router.get('/experts', (req, res) => {
    const m = getMonitor();
    res.json({
        count: m.experts.length,
        experts: m.experts.map(e => ({
            id: e.id,
            name: e.name,
            emoji: e.emoji,
            commandsCount: e.commands.length
        }))
    });
});

module.exports = router;
module.exports.getMonitor = getMonitor;
