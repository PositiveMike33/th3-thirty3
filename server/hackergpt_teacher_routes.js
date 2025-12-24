/**
 * HACKERGPT TEACHER API ROUTES
 * 
 * Routes pour le système d'enseignement HackerGPT -> Modèles locaux
 */

const express = require('express');
const router = express.Router();
const { getHackerGPTTeacherService } = require('./hackergpt_teacher_service');

// Lazy load
let teacherService = null;
function getService() {
    if (!teacherService) {
        teacherService = getHackerGPTTeacherService();
    }
    return teacherService;
}

/**
 * GET /api/teacher/status
 * Get teacher service status
 */
router.get('/status', (req, res) => {
    try {
        const status = getService().getStatus();
        res.json({ success: true, ...status });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/teacher/students
 * Get all student models with XP
 */
router.get('/students', (req, res) => {
    try {
        const students = getService().getStudentModels();
        res.json({ success: true, students, count: students.length });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/teacher/exercise
 * Generate a teaching exercise
 */
router.post('/exercise', async (req, res) => {
    try {
        const { category = 'cybersecurity', difficulty = 'intermediate' } = req.body;
        const exercise = await getService().generateTeachingExercise(category, difficulty);
        res.json({ success: true, ...exercise });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/teacher/session/start
 * Start a teaching session
 */
router.post('/session/start', (req, res) => {
    try {
        const { studentModel, category = 'cybersecurity' } = req.body;
        
        if (!studentModel) {
            return res.status(400).json({
                success: false,
                error: 'studentModel is required'
            });
        }

        const result = getService().startTeachingSession(studentModel, category);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/teacher/session/:sessionId/evaluate
 * Evaluate student response
 */
router.post('/session/:sessionId/evaluate', async (req, res) => {
    try {
        const { sessionId } = req.params;
        const { response, tokensGenerated = 100 } = req.body;
        
        const result = await getService().evaluateStudentResponse(
            sessionId, 
            response, 
            tokensGenerated
        );
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/teacher/session/:sessionId
 * Get session status
 */
router.get('/session/:sessionId', (req, res) => {
    try {
        const { sessionId } = req.params;
        const status = getService().getSessionStatus(sessionId);
        res.json({ success: true, ...status });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/teacher/session/:sessionId/end
 * End teaching session
 */
router.post('/session/:sessionId/end', (req, res) => {
    try {
        const { sessionId } = req.params;
        const result = getService().endSession(sessionId);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;
