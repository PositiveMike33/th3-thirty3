/**
 * HACKERGPT TEACHER SERVICE
 * 
 * Priorise HackerGPT comme enseignant principal pour les modèles Ollama locaux.
 * Optimisé pour performance laptop - utilise HackerGPT pour enseigner,
 * les modèles locaux apprennent et accumulent XP.
 * 
 * Architecture:
 * - HackerGPT (cloud) = Enseignant (génère exercices, évalue, corrige)
 * - Modèles Ollama = Élèves (apprennent, gagnent XP Fibonacci)
 */

const { getFibonacciXPSystem } = require('./fibonacci_xp_system');

class HackerGPTTeacherService {
    constructor() {
        this.xpSystem = getFibonacciXPSystem();
        this.activeSessions = new Map();
        this.priorityModel = 'hackergpt'; // Cloud teacher
        this.localModels = []; // Will be populated from Ollama
        
        console.log('[HACKERGPT-TEACHER] Service initialized - HackerGPT as primary teacher');
    }

    /**
     * Set available local models (called from LLM service)
     */
    setLocalModels(models) {
        this.localModels = models.filter(m => 
            !m.includes('embed') && 
            !m.includes('[') // Exclude cloud/special models
        );
        console.log(`[HACKERGPT-TEACHER] ${this.localModels.length} local models available for training`);
    }

    /**
     * Generate a teaching prompt from HackerGPT for local models
     */
    async generateTeachingExercise(category, difficulty = 'intermediate') {
        const categories = {
            cybersecurity: {
                topics: ['XSS', 'SQLi', 'CSRF', 'SSRF', 'RCE', 'LFI/RFI', 'Auth bypass'],
                prompt: (topic) => `Generate a ${difficulty} cybersecurity exercise about ${topic}. 
                    Include: 1) Scenario 2) What to find 3) Expected answer 4) Scoring criteria`
            },
            coding: {
                topics: ['algorithms', 'data structures', 'debugging', 'optimization', 'security'],
                prompt: (topic) => `Create a ${difficulty} coding exercise about ${topic}.
                    Include: 1) Problem statement 2) Input/Output examples 3) Constraints 4) Expected solution approach`
            },
            osint: {
                topics: ['social media', 'domain recon', 'email tracing', 'metadata', 'geolocation'],
                prompt: (topic) => `Design a ${difficulty} OSINT exercise about ${topic}.
                    Include: 1) Investigation scenario 2) Given data 3) Investigation steps 4) Expected findings`
            },
            redteam: {
                topics: ['phishing', 'social engineering', 'persistence', 'lateral movement', 'exfiltration'],
                prompt: (topic) => `Create a ${difficulty} red team exercise about ${topic}.
                    Include: 1) Objective 2) Constraints 3) Attack chain 4) Defense evasion considerations`
            }
        };

        const cat = categories[category] || categories.cybersecurity;
        const topic = cat.topics[Math.floor(Math.random() * cat.topics.length)];
        
        return {
            category,
            topic,
            difficulty,
            teacherPrompt: cat.prompt(topic),
            generatedAt: new Date().toISOString()
        };
    }

    /**
     * Start a teaching session - HackerGPT teaches local model
     */
    startTeachingSession(studentModel, category = 'cybersecurity') {
        const sessionId = `teach_${Date.now()}_${studentModel.replace(/[^a-zA-Z0-9]/g, '_')}`;
        
        const session = {
            id: sessionId,
            teacher: this.priorityModel,
            student: studentModel,
            category,
            startTime: new Date().toISOString(),
            exercises: [],
            totalXP: 0,
            status: 'active'
        };

        this.activeSessions.set(sessionId, session);
        
        console.log(`[HACKERGPT-TEACHER] Session started: ${this.priorityModel} teaching ${studentModel}`);
        
        return {
            success: true,
            sessionId,
            teacher: this.priorityModel,
            student: studentModel,
            category,
            message: `HackerGPT will teach ${studentModel} in ${category}`
        };
    }

    /**
     * Evaluate student response
     */
    async evaluateStudentResponse(sessionId, studentResponse, tokensGenerated = 100) {
        const session = this.activeSessions.get(sessionId);
        if (!session) {
            return { success: false, error: 'Session not found' };
        }

        // Generate a score (in real implementation, use HackerGPT to evaluate)
        const baseScore = Math.random() * 40 + 60; // 60-100 range
        
        // Add XP based on response
        const xpResult = this.xpSystem.addTrainingXP(session.student, tokensGenerated);
        
        const evaluation = {
            score: Math.round(baseScore),
            xpGained: xpResult.xpGained,
            feedback: baseScore > 80 
                ? 'Excellent work! Strong understanding demonstrated.'
                : baseScore > 60 
                    ? 'Good attempt. Review the key concepts and try again.'
                    : 'Needs improvement. Study the fundamentals.',
            tokensProcessed: tokensGenerated,
            studentLevel: xpResult.level,
            studentTitle: xpResult.title
        };

        session.exercises.push({
            timestamp: new Date().toISOString(),
            ...evaluation
        });
        session.totalXP += xpResult.xpGained;

        return {
            success: true,
            sessionId,
            ...evaluation,
            sessionStats: {
                exercisesCompleted: session.exercises.length,
                totalXP: session.totalXP
            },
            cognitiveRest: xpResult.cognitiveRest
        };
    }

    /**
     * Get teaching session status
     */
    getSessionStatus(sessionId) {
        const session = this.activeSessions.get(sessionId);
        if (!session) {
            return { exists: false };
        }
        return {
            exists: true,
            ...session,
            studentXP: this.xpSystem.getModelStatus(session.student)
        };
    }

    /**
     * End teaching session
     */
    endSession(sessionId) {
        const session = this.activeSessions.get(sessionId);
        if (!session) {
            return { success: false, error: 'Session not found' };
        }

        session.status = 'completed';
        session.endTime = new Date().toISOString();
        
        const result = {
            success: true,
            sessionId,
            student: session.student,
            exercisesCompleted: session.exercises.length,
            totalXP: session.totalXP,
            duration: Date.now() - new Date(session.startTime).getTime(),
            studentProgress: this.xpSystem.getModelStatus(session.student)
        };

        this.activeSessions.delete(sessionId);
        
        console.log(`[HACKERGPT-TEACHER] Session ended: ${session.student} gained ${session.totalXP} XP`);
        
        return result;
    }

    /**
     * Get all local models with their XP status
     */
    getStudentModels() {
        return this.localModels.map(model => ({
            modelName: model,
            ...this.xpSystem.getModelStatus(model)
        }));
    }

    /**
     * Get service status
     */
    getStatus() {
        return {
            initialized: true,
            teacher: this.priorityModel,
            localModelsCount: this.localModels.length,
            activeSessions: this.activeSessions.size,
            localModels: this.localModels.slice(0, 10), // Show first 10
            xpSystemStatus: this.xpSystem.getSystemStatus()
        };
    }
}

// Singleton
let instance = null;

function getHackerGPTTeacherService() {
    if (!instance) {
        instance = new HackerGPTTeacherService();
    }
    return instance;
}

module.exports = { HackerGPTTeacherService, getHackerGPTTeacherService };
