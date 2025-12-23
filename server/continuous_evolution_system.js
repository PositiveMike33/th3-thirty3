/**
 * HackerGPT Continuous Evolution System
 * 
 * Implements human-like continuous learning where:
 * - Each model's strengths are continuously developed
 * - New lessons and exams are generated progressively
 * - Models progress until they reach maximum development
 * - At max level, "Prodigy Score" (1-10) is evaluated
 * - Complexity adapts to each model's experience like humans
 * 
 * Based on Fibonacci (φ=1.618) for natural growth
 * 
 * @author Th3 Thirty3
 */

const fs = require('fs');
const path = require('path');
const EventEmitter = require('events');

// Golden Ratio constants
const PHI = 1.618033988749895;
const PHI_INVERSE = 0.618033988749895;

// Skill progression levels (expanded)
const EVOLUTION_LEVELS = {
    1: { name: 'Script Kiddie', minScore: 0, complexity: 1.0 },
    2: { name: 'Junior Pentester', minScore: 55, complexity: 1.2 },
    3: { name: 'Security Analyst', minScore: 68, complexity: 1.4 },
    4: { name: 'Red Team Operator', minScore: 75, complexity: 1.6 },
    5: { name: 'Elite Hacker', minScore: 82, complexity: PHI },
    6: { name: 'APT Specialist', minScore: 88, complexity: PHI * 1.2 },
    7: { name: 'Ghost', minScore: 93, complexity: PHI * PHI_INVERSE * 2 },
    8: { name: 'Legendary', minScore: 96, complexity: PHI * 1.5 },
    9: { name: 'Prodigy', minScore: 98, complexity: PHI * PHI },
    10: { name: 'Transcendent', minScore: 99.5, complexity: PHI * PHI * PHI_INVERSE }
};

// Model specializations and strengths
const MODEL_SPECIALIZATIONS = {
    'uandinotai/dolphin-uncensored': {
        name: 'Dolphin',
        primaryStrengths: ['exploit_dev', 'pentesting', 'red_team'],
        secondaryStrengths: ['network', 'forensics'],
        learningStyle: 'analytical',
        optimalTemp: 0.6
    },
    'nidumai/nidum-llama-3.2-3b-uncensored': {
        name: 'Nidum',
        primaryStrengths: ['exploit_dev', 'malware', 'cryptography'],
        secondaryStrengths: ['network', 'pentesting'],
        learningStyle: 'precise',
        optimalTemp: 0.3
    },
    'sadiq-bd/llama3.2-3b-uncensored': {
        name: 'Sadiq',
        primaryStrengths: ['social_engineering', 'osint', 'red_team'],
        secondaryStrengths: ['wireless', 'cloud'],
        learningStyle: 'creative',
        optimalTemp: 0.85
    }
};

// Available training domains
const TRAINING_DOMAINS = [
    'osint', 'network', 'pentesting', 'web_security', 'exploit_dev',
    'malware', 'social_engineering', 'wireless', 'cloud', 'forensics',
    'cryptography', 'red_team'
];

class ContinuousEvolutionSystem extends EventEmitter {
    constructor(hackergptService, llmService) {
        super();
        
        this.hackergpt = hackergptService;
        this.llmService = llmService;
        
        // Evolution state per model
        this.evolutionState = {};
        
        // Training schedule
        this.trainingActive = false;
        this.trainingInterval = null;
        
        // Data paths
        this.dataPath = path.join(__dirname, 'data', 'evolution_state.json');
        
        // Load state
        this.loadState();
        
        console.log('[EVOLUTION] Continuous Evolution System initialized');
        console.log('[EVOLUTION] φ-based complexity scaling active');
    }
    
    /**
     * Load evolution state from disk
     */
    loadState() {
        try {
            if (fs.existsSync(this.dataPath)) {
                const data = JSON.parse(fs.readFileSync(this.dataPath, 'utf8'));
                this.evolutionState = data.evolutionState || {};
                console.log(`[EVOLUTION] Loaded state for ${Object.keys(this.evolutionState).length} models`);
            }
        } catch (error) {
            console.error('[EVOLUTION] Failed to load state:', error.message);
        }
    }
    
    /**
     * Save evolution state to disk
     */
    saveState() {
        try {
            const dir = path.dirname(this.dataPath);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
            fs.writeFileSync(this.dataPath, JSON.stringify({
                evolutionState: this.evolutionState,
                lastSaved: new Date().toISOString()
            }, null, 2));
        } catch (error) {
            console.error('[EVOLUTION] Failed to save state:', error.message);
        }
    }
    
    /**
     * Get or initialize model evolution state
     */
    getModelState(modelName) {
        if (!this.evolutionState[modelName]) {
            const spec = MODEL_SPECIALIZATIONS[modelName] || {};
            
            this.evolutionState[modelName] = {
                name: modelName,
                displayName: spec.name || modelName.split('/').pop(),
                
                // Progression
                evolutionLevel: 1,
                prodigyScore: null,  // Only set when reaching max level
                
                // Domain expertise (0-100 each)
                domainExpertise: {},
                
                // Training history
                totalTrainingSessions: 0,
                totalExamsPassed: 0,
                totalExamsFailed: 0,
                experiencePoints: 0,
                
                // Specialization tracking
                primaryTrack: null,
                masteredDomains: [],
                
                // Complexity adaptation
                currentComplexity: 1.0,
                adaptiveMultiplier: 1.0,
                
                // Human-like traits
                fatigue: 0,  // Increases with training, resets over time
                momentum: 1.0,  // Success streak bonus
                lastMistakePattern: null,
                
                // Timestamps
                createdAt: new Date().toISOString(),
                lastTraining: null,
                lastLevelUp: null
            };
            
            // Initialize domain expertise
            for (const domain of TRAINING_DOMAINS) {
                this.evolutionState[modelName].domainExpertise[domain] = 0;
            }
        }
        
        return this.evolutionState[modelName];
    }
    
    /**
     * Calculate next training focus based on model's strengths and weaknesses
     */
    calculateTrainingFocus(modelName) {
        const state = this.getModelState(modelName);
        const spec = MODEL_SPECIALIZATIONS[modelName] || {};
        
        // Get primary and secondary strengths
        const primaryStrengths = spec.primaryStrengths || [];
        const secondaryStrengths = spec.secondaryStrengths || [];
        
        // Calculate priority for each domain
        const priorities = [];
        
        for (const domain of TRAINING_DOMAINS) {
            const expertise = state.domainExpertise[domain] || 0;
            
            let priority = 0;
            
            // Primary strength bonus (should be trained to mastery first)
            if (primaryStrengths.includes(domain)) {
                if (expertise < 80) {
                    priority = 100 - expertise;  // Higher priority for lower expertise
                } else {
                    priority = 20;  // Lower priority once mastered
                }
            }
            // Secondary strength
            else if (secondaryStrengths.includes(domain)) {
                if (expertise < 60) {
                    priority = 80 - expertise;
                } else {
                    priority = 10;
                }
            }
            // Other domains (train minimally)
            else {
                priority = Math.max(0, 40 - expertise);
            }
            
            // Momentum bonus for recently successful domains
            if (state.momentum > 1.2) {
                priority *= 0.8;  // Reduce priority for variety
            }
            
            priorities.push({ domain, priority, expertise });
        }
        
        // Sort by priority
        priorities.sort((a, b) => b.priority - a.priority);
        
        return priorities;
    }
    
    /**
     * Generate adaptive lesson based on model's level and domain
     */
    async generateAdaptiveLesson(modelName, domain) {
        const state = this.getModelState(modelName);
        const expertise = state.domainExpertise[domain] || 0;
        const complexity = state.currentComplexity;
        
        // Determine lesson difficulty
        let difficulty = 'beginner';
        if (expertise >= 80) difficulty = 'expert';
        else if (expertise >= 60) difficulty = 'advanced';
        else if (expertise >= 40) difficulty = 'intermediate';
        
        // Generate adaptive prompt for lesson
        const lessonPrompt = `Generate a ${difficulty}-level cybersecurity lesson on ${domain}.

The student's current expertise level is ${expertise}%.
Complexity multiplier: ${complexity.toFixed(2)}x

Requirements:
1. Adapt content complexity to the student's level
2. Include ${difficulty === 'expert' ? 'cutting-edge' : 'fundamental'} concepts
3. Provide practical examples and exercises
4. Include ${Math.floor(complexity * 3)} challenge problems
5. Focus on areas that build towards mastery

Domain: ${domain}
Target: Help the AI model become a world-class ${domain} expert.
`;

        // Use teacher model to generate lesson
        try {
            if (this.llmService && process.env.GROQ_API_KEY) {
                const lesson = await this.llmService.generateGroqResponse(
                    lessonPrompt,
                    'llama-3.3-70b-versatile',
                    'You are an elite cybersecurity instructor creating adaptive training content.'
                );
                return lesson;
            }
        } catch (error) {
            console.error('[EVOLUTION] Lesson generation failed:', error.message);
        }
        
        return `# ${domain.toUpperCase()} Training\n\n[Adaptive lesson at ${difficulty} level]`;
    }
    
    /**
     * Record training result and update evolution
     */
    recordTrainingResult(modelName, domain, score, passed) {
        const state = this.getModelState(modelName);
        
        // Update domain expertise using φ-based growth
        const currentExpertise = state.domainExpertise[domain] || 0;
        const growthFactor = passed ? PHI_INVERSE : (PHI_INVERSE * 0.3);  // Less growth on failure
        const newExpertise = Math.min(100, currentExpertise + (score * growthFactor * 0.1));
        
        state.domainExpertise[domain] = Math.round(newExpertise * 10) / 10;
        
        // Update training stats
        state.totalTrainingSessions++;
        if (passed) {
            state.totalExamsPassed++;
            state.momentum = Math.min(2.0, state.momentum * 1.1);  // Build momentum
        } else {
            state.totalExamsFailed++;
            state.momentum = Math.max(0.5, state.momentum * 0.9);  // Reduce momentum
            state.lastMistakePattern = domain;
        }
        
        // Calculate experience points
        state.experiencePoints += Math.floor(score * state.currentComplexity);
        
        // Update fatigue (human-like)
        state.fatigue = Math.min(100, state.fatigue + 10);
        
        // Check for level up
        this.checkLevelUp(modelName);
        
        // Update timestamp
        state.lastTraining = new Date().toISOString();
        
        // Save state
        this.saveState();
        
        // Emit event
        this.emit('trainingCompleted', {
            modelName,
            domain,
            score,
            passed,
            newExpertise,
            evolutionLevel: state.evolutionLevel
        });
        
        return state;
    }
    
    /**
     * Check if model should level up
     */
    checkLevelUp(modelName) {
        const state = this.getModelState(modelName);
        
        // Calculate overall score from domain expertise
        const expertiseValues = Object.values(state.domainExpertise);
        const avgExpertise = expertiseValues.reduce((a, b) => a + b, 0) / expertiseValues.length;
        
        // Find appropriate level
        let newLevel = 1;
        for (let level = 10; level >= 1; level--) {
            if (avgExpertise >= EVOLUTION_LEVELS[level].minScore) {
                newLevel = level;
                break;
            }
        }
        
        // Level up!
        if (newLevel > state.evolutionLevel) {
            const oldLevel = state.evolutionLevel;
            state.evolutionLevel = newLevel;
            state.currentComplexity = EVOLUTION_LEVELS[newLevel].complexity;
            state.lastLevelUp = new Date().toISOString();
            
            console.log(`[EVOLUTION] 🎉 ${state.displayName} LEVELED UP!`);
            console.log(`[EVOLUTION] ${EVOLUTION_LEVELS[oldLevel].name} → ${EVOLUTION_LEVELS[newLevel].name}`);
            
            // If reached max level, calculate Prodigy Score
            if (newLevel >= 9) {
                this.calculateProdigyScore(modelName);
            }
            
            this.emit('levelUp', {
                modelName,
                oldLevel,
                newLevel,
                levelName: EVOLUTION_LEVELS[newLevel].name
            });
        }
    }
    
    /**
     * Calculate Prodigy Score (1-10) for max-level models
     */
    calculateProdigyScore(modelName) {
        const state = this.getModelState(modelName);
        
        // Factors for Prodigy Score:
        // 1. Domain mastery (how many domains at 90%+)
        // 2. Consistency (pass rate)
        // 3. Complexity handling
        // 4. Speed of learning
        // 5. Specialization depth
        
        const expertiseValues = Object.values(state.domainExpertise);
        const masteredDomains = expertiseValues.filter(e => e >= 90).length;
        const avgExpertise = expertiseValues.reduce((a, b) => a + b, 0) / expertiseValues.length;
        const passRate = state.totalTrainingSessions > 0 
            ? state.totalExamsPassed / state.totalTrainingSessions 
            : 0;
        
        // Calculate Prodigy Score (1-10)
        let prodigyScore = 0;
        
        // Domain mastery (max 3 points)
        prodigyScore += Math.min(3, masteredDomains * 0.3);
        
        // Average expertise (max 3 points)
        prodigyScore += (avgExpertise / 100) * 3;
        
        // Pass rate (max 2 points)
        prodigyScore += passRate * 2;
        
        // Experience points bonus (max 1 point)
        prodigyScore += Math.min(1, state.experiencePoints / 10000);
        
        // Momentum bonus (max 1 point)
        prodigyScore += Math.min(1, (state.momentum - 1) * 2);
        
        // Round to 1 decimal
        state.prodigyScore = Math.round(Math.min(10, prodigyScore) * 10) / 10;
        
        console.log(`[EVOLUTION] ⭐ ${state.displayName} PRODIGY SCORE: ${state.prodigyScore}/10`);
        
        this.emit('prodigyAchieved', {
            modelName,
            prodigyScore: state.prodigyScore,
            masteredDomains,
            avgExpertise
        });
        
        return state.prodigyScore;
    }
    
    /**
     * Run a complete training session for a model
     * Focuses on their strengths progressively
     */
    async runEvolutionCycle(modelName) {
        console.log(`\n[EVOLUTION] Starting evolution cycle for ${modelName}`);
        
        const state = this.getModelState(modelName);
        
        // Check fatigue
        if (state.fatigue >= 80) {
            console.log('[EVOLUTION] Model is fatigued, resting...');
            state.fatigue = Math.max(0, state.fatigue - 30);
            this.saveState();
            return { status: 'resting', fatigue: state.fatigue };
        }
        
        // Calculate training focus
        const priorities = this.calculateTrainingFocus(modelName);
        const topDomain = priorities[0].domain;
        
        console.log(`[EVOLUTION] Focus: ${topDomain} (priority: ${priorities[0].priority})`);
        
        // Generate adaptive lesson
        const lesson = await this.generateAdaptiveLesson(modelName, topDomain);
        
        // Give exam via HackerGPT
        let examResult = null;
        try {
            // Map domain to course ID
            const courseMapping = {
                'osint': 'osint-1',
                'network': 'network-1',
                'pentesting': 'pentest-1',
                'web_security': 'web-1',
                'exploit_dev': 'exploit-1',
                'malware': 'malware-1',
                'social_engineering': 'social-1',
                'wireless': 'wireless-1',
                'cloud': 'cloud-1',
                'forensics': 'forensics-1',
                'cryptography': 'crypto-1',
                'red_team': 'redteam-1'
            };
            
            const courseId = courseMapping[topDomain] || 'pentest-1';
            examResult = await this.hackergpt.giveExam(modelName, courseId);
            
            // Record result
            this.recordTrainingResult(
                modelName, 
                topDomain, 
                examResult.averageScore, 
                examResult.passed
            );
            
        } catch (error) {
            console.error('[EVOLUTION] Exam failed:', error.message);
        }
        
        return {
            status: 'completed',
            domain: topDomain,
            score: examResult?.averageScore || 0,
            passed: examResult?.passed || false,
            evolutionLevel: state.evolutionLevel,
            expertise: state.domainExpertise[topDomain]
        };
    }
    
    /**
     * Start continuous evolution training
     * Runs training cycles periodically
     */
    startContinuousEvolution(intervalMinutes = 30) {
        if (this.trainingActive) {
            console.log('[EVOLUTION] Already running');
            return;
        }
        
        this.trainingActive = true;
        console.log(`[EVOLUTION] Starting continuous evolution (every ${intervalMinutes} min)`);
        
        // Run for all models
        const runCycle = async () => {
            for (const modelName of Object.keys(MODEL_SPECIALIZATIONS)) {
                try {
                    await this.runEvolutionCycle(modelName);
                } catch (error) {
                    console.error(`[EVOLUTION] Cycle failed for ${modelName}:`, error.message);
                }
            }
        };
        
        // Run immediately
        runCycle();
        
        // Schedule periodic runs
        this.trainingInterval = setInterval(runCycle, intervalMinutes * 60 * 1000);
    }
    
    /**
     * Stop continuous evolution
     */
    stopContinuousEvolution() {
        if (this.trainingInterval) {
            clearInterval(this.trainingInterval);
            this.trainingInterval = null;
        }
        this.trainingActive = false;
        console.log('[EVOLUTION] Stopped continuous evolution');
    }
    
    /**
     * Get evolution status for all models
     */
    getEvolutionStatus() {
        const models = Object.entries(this.evolutionState).map(([name, state]) => {
            const spec = MODEL_SPECIALIZATIONS[name] || {};
            return {
                name: state.displayName,
                fullName: name,
                evolutionLevel: state.evolutionLevel,
                levelName: EVOLUTION_LEVELS[state.evolutionLevel]?.name,
                prodigyScore: state.prodigyScore,
                primaryStrengths: spec.primaryStrengths,
                domainExpertise: state.domainExpertise,
                stats: {
                    sessions: state.totalTrainingSessions,
                    passed: state.totalExamsPassed,
                    failed: state.totalExamsFailed,
                    xp: state.experiencePoints,
                    fatigue: state.fatigue,
                    momentum: state.momentum
                },
                lastTraining: state.lastTraining
            };
        });
        
        return {
            models,
            levels: EVOLUTION_LEVELS,
            domains: TRAINING_DOMAINS,
            isActive: this.trainingActive
        };
    }
}

module.exports = ContinuousEvolutionSystem;
module.exports.EVOLUTION_LEVELS = EVOLUTION_LEVELS;
module.exports.MODEL_SPECIALIZATIONS = MODEL_SPECIALIZATIONS;
