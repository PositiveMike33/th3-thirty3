/**
 * HACKERGPT ACADEMY API ROUTES
 * 
 * REST API pour l'académie HackerGPT - Entraînement, Enseignement, Tests
 */

const express = require('express');
const router = express.Router();
const { getHackerGPTAcademyService } = require('./hackergpt_academy_service');

// LLM Service reference for evaluation
let llmService = null;
router.setLLMService = (service) => {
    llmService = service;
    console.log('[HACKERGPT-ACADEMY] LLM Service connected for evaluation');
};

// Lazy load service
let service = null;
function getService() {
    if (!service) {
        service = getHackerGPTAcademyService();
    }
    return service;
}

// ============================================
// STATUS & INFO
// ============================================

/**
 * GET /api/hackergpt-academy/status
 * Get academy status
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
 * GET /api/hackergpt-academy/modules
 * List all training modules
 */
router.get('/modules', (req, res) => {
    try {
        const modules = getService().getModules();
        res.json({ success: true, modules, count: modules.length });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/hackergpt-academy/modules/:id
 * Get specific module details
 */
router.get('/modules/:id', (req, res) => {
    try {
        const module = getService().getModule(req.params.id);
        if (!module) {
            return res.status(404).json({ success: false, error: 'Module not found' });
        }
        res.json({ success: true, module });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/hackergpt-academy/modules/category/:category
 * Get modules by category
 */
router.get('/modules/category/:category', (req, res) => {
    try {
        const modules = getService().getModulesByCategory(req.params.category);
        res.json({ success: true, modules, count: modules.length });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================
// TRAINING SESSIONS
// ============================================

/**
 * POST /api/hackergpt-academy/training/start
 * Start a training session
 */
router.post('/training/start', (req, res) => {
    try {
        const { userId = 'default', moduleId } = req.body;
        
        if (!moduleId) {
            return res.status(400).json({ success: false, error: 'moduleId is required' });
        }

        const result = getService().startTrainingSession(userId, moduleId);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/hackergpt-academy/training/:sessionId/current
 * Get current exercise in session
 */
router.get('/training/:sessionId/current', (req, res) => {
    try {
        const exercise = getService().getCurrentExercise(req.params.sessionId);
        res.json({ success: true, ...exercise });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hackergpt-academy/training/:sessionId/submit
 * Submit exercise answer
 */
router.post('/training/:sessionId/submit', async (req, res) => {
    try {
        const { answer } = req.body;
        
        if (!answer) {
            return res.status(400).json({ success: false, error: 'answer is required' });
        }

        const result = await getService().submitExercise(req.params.sessionId, answer, llmService);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================
// EXAMS
// ============================================

/**
 * POST /api/hackergpt-academy/exam/start
 * Start an exam
 */
router.post('/exam/start', (req, res) => {
    try {
        const { userId = 'default', moduleId } = req.body;
        
        if (!moduleId) {
            return res.status(400).json({ success: false, error: 'moduleId is required' });
        }

        const result = getService().startExam(userId, moduleId);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hackergpt-academy/exam/:examId/submit
 * Submit exam answers
 */
router.post('/exam/:examId/submit', async (req, res) => {
    try {
        const { answers } = req.body;
        
        if (!answers || typeof answers !== 'object') {
            return res.status(400).json({ success: false, error: 'answers object is required' });
        }

        const result = await getService().submitExam(req.params.examId, answers, llmService);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================
// PROGRESS & LEADERBOARD
// ============================================

/**
 * GET /api/hackergpt-academy/progress/:userId
 * Get user progress
 */
router.get('/progress/:userId', (req, res) => {
    try {
        const progress = getService().getUserProgress(req.params.userId);
        res.json({ success: true, ...progress });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/hackergpt-academy/leaderboard
 * Get leaderboard
 */
router.get('/leaderboard', (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 10;
        const leaderboard = getService().getLeaderboard(limit);
        res.json({ success: true, ...leaderboard });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================
// QUICK CHALLENGES
// ============================================

/**
 * GET /api/hackergpt-academy/challenge/random
 * Get a random quick challenge
 */
router.get('/challenge/random', (req, res) => {
    try {
        const { difficulty = 'intermediate' } = req.query;
        
        const challenges = [
            {
                id: 'ch1',
                title: 'XSS Hunter',
                difficulty: 'beginner',
                prompt: 'Find a working XSS payload for: <input type="text" value="USER_INPUT">',
                timeLimit: 120,
                points: 50
            },
            {
                id: 'ch2',
                title: 'SQLi Detective',
                difficulty: 'intermediate',
                prompt: 'This query is vulnerable: SELECT * FROM users WHERE id = $id. Write a payload to extract all usernames.',
                timeLimit: 180,
                points: 100
            },
            {
                id: 'ch3',
                title: 'Command Injection',
                difficulty: 'intermediate',
                prompt: 'The server runs: ping -c 4 $ip. Craft a payload to read /etc/passwd.',
                timeLimit: 120,
                points: 75
            },
            {
                id: 'ch4',
                title: 'JWT Attack',
                difficulty: 'advanced',
                prompt: 'You have a JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.xxx. How would you try to escalate to admin?',
                timeLimit: 300,
                points: 150
            },
            {
                id: 'ch5',
                title: 'SSRF Exploitation',
                difficulty: 'advanced',
                prompt: 'The endpoint /fetch?url= fetches URLs. How would you access internal AWS metadata?',
                timeLimit: 180,
                points: 125
            }
        ];

        const filtered = challenges.filter(c => c.difficulty === difficulty);
        const challenge = filtered[Math.floor(Math.random() * filtered.length)] || challenges[0];

        res.json({ success: true, challenge });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hackergpt-academy/challenge/submit
 * Submit challenge answer
 */
router.post('/challenge/submit', async (req, res) => {
    try {
        const { challengeId, answer } = req.body;
        
        // Simple evaluation - in production would use LLM
        const score = answer && answer.length > 10 ? Math.floor(Math.random() * 30) + 70 : 30;
        const passed = score >= 70;

        res.json({
            success: true,
            challengeId,
            score,
            maxScore: 100,
            passed,
            feedback: passed ? 'Great work! Challenge completed.' : 'Keep practicing. Try again!',
            xpEarned: passed ? score : Math.floor(score / 2)
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================
// PRACTICE LABS
// ============================================

/**
 * GET /api/hackergpt-academy/labs
 * List available practice labs
 */
router.get('/labs', (req, res) => {
    try {
        const labs = [
            {
                id: 'lab_sqli',
                name: 'SQL Injection Lab',
                description: 'Practice SQL injection on vulnerable endpoints',
                difficulty: 'beginner',
                environment: 'web',
                tools: ['Browser', 'SQLMap'],
                estimatedTime: '30 min'
            },
            {
                id: 'lab_xss',
                name: 'XSS Playground',
                description: 'Find and exploit various XSS vulnerabilities',
                difficulty: 'intermediate',
                environment: 'web',
                tools: ['Browser', 'Burp Suite'],
                estimatedTime: '45 min'
            },
            {
                id: 'lab_network',
                name: 'Network Reconnaissance Lab',
                description: 'Scan and enumerate a virtual network',
                difficulty: 'intermediate',
                environment: 'network',
                tools: ['Nmap', 'Wireshark'],
                estimatedTime: '60 min'
            },
            {
                id: 'lab_privesc',
                name: 'Linux Privilege Escalation',
                description: 'Escalate from user to root',
                difficulty: 'advanced',
                environment: 'linux',
                tools: ['linPEAS', 'GTFOBins'],
                estimatedTime: '90 min'
            },
            {
                id: 'lab_ad',
                name: 'Active Directory Attack Path',
                description: 'Compromise a Windows domain',
                difficulty: 'advanced',
                environment: 'windows',
                tools: ['BloodHound', 'Mimikatz', 'CrackMapExec'],
                estimatedTime: '120 min'
            }
        ];

        res.json({ success: true, labs, count: labs.length });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/hackergpt-academy/labs/:labId/start
 * Start a practice lab
 */
router.post('/labs/:labId/start', (req, res) => {
    try {
        const { userId = 'default' } = req.body;
        const labId = req.params.labId;

        // In a real implementation, this would spin up a lab environment
        res.json({
            success: true,
            labId,
            userId,
            status: 'started',
            message: 'Lab environment initializing... (simulated)',
            accessInfo: {
                type: 'simulated',
                note: 'Connect HackerAI to execute real commands',
                hackerAIRequired: true
            },
            objectives: [
                'Discover the entry point',
                'Exploit the vulnerability',
                'Capture the flag',
                'Document your approach'
            ]
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;
