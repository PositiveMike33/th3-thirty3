/**
 * FIBONACCI XP PROGRESSION SYSTEM
 * 
 * Système d'accumulation d'XP basé sur Fibonacci pour croissance exponentielle
 * 
 * RÈGLES:
 * - Chaque token assimilé rapporte des XP en progression Fibonacci
 * - 1000 XP = Niveau 2 (1,1,2,3,5,8,13,21,34,55,89,144...)
 * - Décroissance si trop long entre entraînements: 10,9,8,7,6,5,4,3,2,1 points/jour
 * 
 * PROGRESSION:
 * - Token 1: +1 XP
 * - Token 2: +1 XP
 * - Token 3: +2 XP
 * - Token 5: +3 XP
 * - Token 8: +5 XP
 * - Token 13: +8 XP
 * - ...exponential growth!
 */

const fs = require('fs');
const path = require('path');

// Fibonacci sequence for XP rewards (first 30 terms)
const FIBONACCI_XP = [
    1, 1, 2, 3, 5, 8, 13, 21, 34, 55,
    89, 144, 233, 377, 610, 987, 1597, 2584, 4181, 6765,
    10946, 17711, 28657, 46368, 75025, 121393, 196418, 317811, 514229, 832040
];

// Level thresholds (exponential based on Fibonacci)
const LEVEL_THRESHOLDS = [
    { level: 1, xp: 0, title: 'Novice' },
    { level: 2, xp: 1000, title: 'Apprentice' },
    { level: 3, xp: 2000, title: 'Initiate' },
    { level: 4, xp: 4000, title: 'Practitioner' },
    { level: 5, xp: 7000, title: 'Skilled' },
    { level: 6, xp: 12000, title: 'Expert' },
    { level: 7, xp: 20000, title: 'Master' },
    { level: 8, xp: 33000, title: 'Elite' },
    { level: 9, xp: 54000, title: 'Champion' },
    { level: 10, xp: 88000, title: 'Legendary' },
    { level: 11, xp: 143000, title: 'Mythic' },
    { level: 12, xp: 232000, title: 'Transcendent' },
    { level: 13, xp: 376000, title: 'Cybernetic' },
    { level: 14, xp: 610000, title: 'Ascended' },
    { level: 15, xp: 1000000, title: 'Maximum' }
];

// Decay rates per day of inactivity (descending)
const DECAY_RATES = [10, 9, 8, 7, 6, 5, 4, 3, 2, 1];

// COGNITIVE REST SYSTEM
// Like human neurons, AI models need rest to consolidate learning
// 3h30 (210 minutes) cognitive rest between training sessions
const COGNITIVE_REST_MINUTES = 210; // 3 hours 30 minutes
const MAX_TRAINING_PER_SESSION = 5; // Max trainings before mandatory rest
const REST_BONUS_MULTIPLIER = 1.5; // XP bonus for well-rested training
const FATIGUED_PENALTY = 0.5; // XP penalty for training while fatigued

// Data path
const XP_DATA_PATH = path.join(__dirname, 'data', 'model_xp.json');

class FibonacciXPSystem {
    constructor() {
        this.xpData = this.loadXPData();
        this.decayCheckInterval = null;
        
        console.log('[FIBONACCI-XP] System initialized');
        console.log('[FIBONACCI-XP] Level 2 at 1000 XP | Decay: 10-1 per day inactive');
        
        // Start decay checker
        this.startDecayChecker();
    }

    /**
     * Load XP data from disk
     */
    loadXPData() {
        try {
            const dir = path.dirname(XP_DATA_PATH);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
            if (fs.existsSync(XP_DATA_PATH)) {
                return JSON.parse(fs.readFileSync(XP_DATA_PATH, 'utf8'));
            }
        } catch (e) {
            console.error('[FIBONACCI-XP] Error loading XP data:', e.message);
        }
        return { models: {}, globalStats: { totalXP: 0, totalTokens: 0 } };
    }

    /**
     * Save XP data to disk
     */
    saveXPData() {
        try {
            fs.writeFileSync(XP_DATA_PATH, JSON.stringify(this.xpData, null, 2));
        } catch (e) {
            console.error('[FIBONACCI-XP] Error saving XP data:', e.message);
        }
    }

    /**
     * Get or create model XP entry
     */
    getOrCreateModelXP(modelName) {
        if (!this.xpData.models[modelName]) {
            this.xpData.models[modelName] = {
                modelName,
                xp: 0,
                level: 1,
                title: 'Novice',
                totalTokens: 0,
                trainingCount: 0,
                fibonacciIndex: 0,
                lastTraining: null,
                lastDecay: null,
                // COGNITIVE REST SYSTEM
                cognitiveRest: {
                    lastRestEnd: null,
                    sessionTrainingCount: 0,
                    isFatigued: false,
                    restUntil: null,
                    totalRestPeriods: 0
                },
                history: [],
                createdAt: new Date().toISOString()
            };
        }
        // Migrate existing models
        if (!this.xpData.models[modelName].cognitiveRest) {
            this.xpData.models[modelName].cognitiveRest = {
                lastRestEnd: null,
                sessionTrainingCount: 0,
                isFatigued: false,
                restUntil: null,
                totalRestPeriods: 0
            };
        }
        return this.xpData.models[modelName];
    }

    /**
     * Get Fibonacci XP reward for current training count
     * Uses the position in training sequence to determine reward
     */
    getFibonacciXP(trainingCount) {
        // Map training count to Fibonacci index with exponential scaling
        // Every 10 trainings, we advance 1 Fibonacci level
        const fibIndex = Math.min(
            Math.floor(trainingCount / 10),
            FIBONACCI_XP.length - 1
        );
        return FIBONACCI_XP[fibIndex];
    }

    /**
     * Check cognitive rest status
     * Models need 3h30 rest to consolidate learning into long-term memory
     */
    checkCognitiveRest(model) {
        const now = new Date();
        const rest = model.cognitiveRest;
        
        // Check if resting
        if (rest.restUntil) {
            const restEnd = new Date(rest.restUntil);
            if (now < restEnd) {
                const minutesLeft = Math.ceil((restEnd - now) / (1000 * 60));
                return {
                    canTrain: false,
                    isResting: true,
                    minutesUntilReady: minutesLeft,
                    hoursUntilReady: Math.floor(minutesLeft / 60),
                    message: `Repos cognitif: ${Math.floor(minutesLeft / 60)}h${minutesLeft % 60}m restantes pour consolidation mémoire`
                };
            } else {
                // Rest complete!
                rest.lastRestEnd = now.toISOString();
                rest.restUntil = null;
                rest.sessionTrainingCount = 0;
                rest.isFatigued = false;
                rest.totalRestPeriods++;
            }
        }
        
        // Check fatigue level
        const isFatigued = rest.sessionTrainingCount >= MAX_TRAINING_PER_SESSION;
        rest.isFatigued = isFatigued;
        
        // Calculate XP multiplier based on rest status
        let xpMultiplier = 1;
        if (rest.lastRestEnd) {
            const hoursSinceRest = (now - new Date(rest.lastRestEnd)) / (1000 * 60 * 60);
            if (hoursSinceRest >= 3.5) {
                // Well rested bonus!
                xpMultiplier = REST_BONUS_MULTIPLIER;
            }
        }
        
        if (isFatigued) {
            xpMultiplier = FATIGUED_PENALTY;
        }
        
        return {
            canTrain: true,
            isResting: false,
            isFatigued,
            sessionTrainingCount: rest.sessionTrainingCount,
            maxTrainingPerSession: MAX_TRAINING_PER_SESSION,
            xpMultiplier,
            message: isFatigued 
                ? 'Neurones fatigués - XP réduit de 50%' 
                : xpMultiplier > 1 
                    ? 'Bien reposé - Bonus XP +50%!'
                    : 'Prêt pour entraînement'
        };
    }

    /**
     * Start cognitive rest period (3h30)
     */
    startCognitiveRest(modelName) {
        const model = this.getOrCreateModelXP(modelName);
        const now = new Date();
        const restEnd = new Date(now.getTime() + COGNITIVE_REST_MINUTES * 60 * 1000);
        
        model.cognitiveRest.restUntil = restEnd.toISOString();
        model.cognitiveRest.isFatigued = false;
        
        model.history.push({
            type: 'cognitive_rest_start',
            date: now.toISOString(),
            restUntil: restEnd.toISOString(),
            durationMinutes: COGNITIVE_REST_MINUTES,
            reason: 'Consolidation mémoire long terme'
        });
        
        this.saveXPData();
        
        console.log(`[FIBONACCI-XP] 🧠 ${modelName}: Repos cognitif démarré - prêt à ${restEnd.toLocaleTimeString()}`);
        
        return {
            success: true,
            modelName,
            restStarted: now.toISOString(),
            restUntil: restEnd.toISOString(),
            durationMinutes: COGNITIVE_REST_MINUTES,
            message: `Repos cognitif 3h30 - consolidation mémoire long terme`
        };
    }

    /**
     * Add XP for tokens trained
     * @param {string} modelName - Model name
     * @param {number} tokensProcessed - Number of tokens in this training
     * @returns {object} XP gain result
     */
    addTrainingXP(modelName, tokensProcessed) {
        const model = this.getOrCreateModelXP(modelName);
        const now = new Date();
        
        // Check cognitive rest status
        const restStatus = this.checkCognitiveRest(model);
        
        if (!restStatus.canTrain) {
            return {
                success: false,
                modelName,
                ...restStatus,
                xpGained: 0,
                message: restStatus.message
            };
        }
        
        // Increment training count
        model.trainingCount++;
        model.totalTokens += tokensProcessed;
        model.cognitiveRest.sessionTrainingCount++;
        
        // Calculate XP based on Fibonacci progression
        const fibMultiplier = this.getFibonacciXP(model.trainingCount);
        
        // XP formula: tokens * fibonacci_multiplier / 100 * rest_multiplier
        const baseXP = Math.ceil(tokensProcessed / 100);
        let xpGained = Math.round(baseXP * fibMultiplier * restStatus.xpMultiplier);
        
        const oldLevel = model.level;
        const oldXP = model.xp;
        
        // Add XP
        model.xp += xpGained;
        model.lastTraining = now.toISOString();
        
        // Update level
        this.updateLevel(model);
        
        // Check for level up
        const leveledUp = model.level > oldLevel;
        
        // Auto-start rest if hitting max trainings
        let restStarted = false;
        if (model.cognitiveRest.sessionTrainingCount >= MAX_TRAINING_PER_SESSION) {
            this.startCognitiveRest(modelName);
            restStarted = true;
        }
        
        // Add to history
        model.history.push({
            type: 'training',
            date: now.toISOString(),
            tokens: tokensProcessed,
            xpGained,
            fibMultiplier,
            xpMultiplier: restStatus.xpMultiplier,
            trainingNumber: model.trainingCount,
            sessionTraining: model.cognitiveRest.sessionTrainingCount,
            newXP: model.xp,
            newLevel: model.level,
            wasFatigued: restStatus.isFatigued,
            wasRested: restStatus.xpMultiplier > 1
        });

        // Keep only last 100 history entries
        if (model.history.length > 100) {
            model.history = model.history.slice(-100);
        }

        // Update global stats
        this.xpData.globalStats.totalXP += xpGained;
        this.xpData.globalStats.totalTokens += tokensProcessed;
        
        this.saveXPData();

        const bonusText = restStatus.xpMultiplier > 1 ? ' 🌟 BONUS!' : restStatus.isFatigued ? ' ⚠️ FATIGUÉ' : '';
        console.log(`[FIBONACCI-XP] ${modelName}: +${xpGained} XP (fib×${fibMultiplier}${bonusText}) | Total: ${model.xp} | Level ${model.level}`);

        return {
            success: true,
            modelName,
            xpGained,
            fibMultiplier,
            xpMultiplier: restStatus.xpMultiplier,
            tokens: tokensProcessed,
            totalXP: model.xp,
            level: model.level,
            title: model.title,
            leveledUp,
            oldLevel,
            newLevel: model.level,
            progressToNextLevel: this.getProgressToNextLevel(model),
            trainingCount: model.trainingCount,
            cognitiveRest: {
                sessionTrainingCount: model.cognitiveRest.sessionTrainingCount,
                maxPerSession: MAX_TRAINING_PER_SESSION,
                isFatigued: restStatus.isFatigued,
                restStarted,
                message: restStatus.message
            }
        };
    }

    /**
     * Update model level based on XP
     */
    updateLevel(model) {
        for (let i = LEVEL_THRESHOLDS.length - 1; i >= 0; i--) {
            if (model.xp >= LEVEL_THRESHOLDS[i].xp) {
                model.level = LEVEL_THRESHOLDS[i].level;
                model.title = LEVEL_THRESHOLDS[i].title;
                break;
            }
        }
    }

    /**
     * Get progress to next level
     */
    getProgressToNextLevel(model) {
        const currentThreshold = LEVEL_THRESHOLDS.find(t => t.level === model.level);
        const nextThreshold = LEVEL_THRESHOLDS.find(t => t.level === model.level + 1);
        
        if (!nextThreshold) {
            return { progress: 100, xpNeeded: 0, nextLevelXP: currentThreshold.xp };
        }
        
        const currentLevelXP = currentThreshold.xp;
        const nextLevelXP = nextThreshold.xp;
        const xpInLevel = model.xp - currentLevelXP;
        const xpNeededForLevel = nextLevelXP - currentLevelXP;
        const progress = Math.round((xpInLevel / xpNeededForLevel) * 100);
        
        return {
            progress: Math.min(100, progress),
            xpNeeded: nextLevelXP - model.xp,
            currentXP: model.xp,
            nextLevelXP,
            xpInLevel
        };
    }

    /**
     * Apply decay if model has been inactive
     * Decay follows: 10,9,8,7,6,5,4,3,2,1 points per day
     */
    applyDecay(modelName) {
        const model = this.xpData.models[modelName];
        if (!model || !model.lastTraining) return null;

        const now = new Date();
        const lastActivity = new Date(model.lastTraining);
        const daysSinceActivity = Math.floor((now - lastActivity) / (1000 * 60 * 60 * 24));

        // No decay for first day
        if (daysSinceActivity < 1) return null;

        // Already decayed today
        if (model.lastDecay) {
            const lastDecayDate = new Date(model.lastDecay);
            const daysSinceDecay = Math.floor((now - lastDecayDate) / (1000 * 60 * 60 * 24));
            if (daysSinceDecay < 1) return null;
        }

        // Calculate decay amount based on days inactive
        // Day 1-10 inactive: decay rate from DECAY_RATES array
        // Beyond day 10: minimum decay of 1
        let totalDecay = 0;
        
        for (let day = 1; day <= daysSinceActivity; day++) {
            // Get decay rate for this day (1-indexed, so day 1 = index 0)
            const decayIndex = Math.min(day - 1, DECAY_RATES.length - 1);
            totalDecay += DECAY_RATES[decayIndex];
        }

        // Don't decay below 0
        if (model.xp <= 0 || totalDecay <= 0) return null;

        const oldXP = model.xp;
        const oldLevel = model.level;
        
        model.xp = Math.max(0, model.xp - totalDecay);
        model.lastDecay = now.toISOString();
        
        // Update level (may drop)
        this.updateLevel(model);

        // Log decay event
        model.history.push({
            type: 'decay',
            date: now.toISOString(),
            xpLost: totalDecay,
            daysSinceActivity,
            oldXP,
            newXP: model.xp,
            levelDrop: model.level < oldLevel
        });

        this.saveXPData();

        console.log(`[FIBONACCI-XP] DECAY: ${modelName} -${totalDecay} XP (${daysSinceActivity} days inactive) | ${model.xp} XP | Level ${model.level}`);

        return {
            modelName,
            xpLost: totalDecay,
            daysSinceActivity,
            oldXP,
            newXP: model.xp,
            oldLevel,
            newLevel: model.level,
            levelDropped: model.level < oldLevel
        };
    }

    /**
     * Start decay checker (runs every hour)
     */
    startDecayChecker() {
        // Check every hour
        this.decayCheckInterval = setInterval(() => {
            for (const modelName of Object.keys(this.xpData.models)) {
                this.applyDecay(modelName);
            }
        }, 60 * 60 * 1000); // Every hour

        // Also run on startup after 5 seconds
        setTimeout(() => {
            for (const modelName of Object.keys(this.xpData.models)) {
                this.applyDecay(modelName);
            }
        }, 5000);

        console.log('[FIBONACCI-XP] Decay checker started (10,9,8,7,6,5,4,3,2,1 per day inactive)');
    }

    /**
     * Get model XP status
     */
    getModelStatus(modelName) {
        const model = this.xpData.models[modelName];
        if (!model) {
            return { exists: false, message: 'Model has no XP data yet' };
        }

        const progress = this.getProgressToNextLevel(model);
        const fibMultiplier = this.getFibonacciXP(model.trainingCount);

        return {
            exists: true,
            modelName,
            xp: model.xp,
            level: model.level,
            title: model.title,
            totalTokens: model.totalTokens,
            trainingCount: model.trainingCount,
            currentFibMultiplier: fibMultiplier,
            nextFibMultiplier: this.getFibonacciXP(model.trainingCount + 1),
            progress,
            lastTraining: model.lastTraining,
            daysSinceTraining: model.lastTraining 
                ? Math.floor((Date.now() - new Date(model.lastTraining)) / (1000 * 60 * 60 * 24))
                : null,
            decayRisk: model.lastTraining 
                ? Math.floor((Date.now() - new Date(model.lastTraining)) / (1000 * 60 * 60 * 24)) >= 1
                : false
        };
    }

    /**
     * Get all models XP leaderboard
     */
    getLeaderboard() {
        const models = Object.values(this.xpData.models)
            .sort((a, b) => b.xp - a.xp)
            .map((m, index) => ({
                rank: index + 1,
                modelName: m.modelName,
                xp: m.xp,
                level: m.level,
                title: m.title,
                trainingCount: m.trainingCount,
                totalTokens: m.totalTokens
            }));

        return {
            leaderboard: models,
            totalModels: models.length,
            globalStats: this.xpData.globalStats
        };
    }

    /**
     * Get XP system status
     */
    getSystemStatus() {
        const modelCount = Object.keys(this.xpData.models).length;
        const totalXP = Object.values(this.xpData.models).reduce((sum, m) => sum + m.xp, 0);
        const avgLevel = modelCount > 0
            ? Object.values(this.xpData.models).reduce((sum, m) => sum + m.level, 0) / modelCount
            : 0;

        return {
            initialized: true,
            modelCount,
            totalXP,
            averageLevel: Math.round(avgLevel * 10) / 10,
            globalStats: this.xpData.globalStats,
            levelThresholds: LEVEL_THRESHOLDS.slice(0, 5), // Show first 5 levels
            decayRates: DECAY_RATES,
            fibonacciSequence: FIBONACCI_XP.slice(0, 10) // Show first 10 Fibonacci numbers
        };
    }

    /**
     * Stop decay checker
     */
    stop() {
        if (this.decayCheckInterval) {
            clearInterval(this.decayCheckInterval);
            this.decayCheckInterval = null;
        }
        console.log('[FIBONACCI-XP] System stopped');
    }
}

// Singleton
let instance = null;

function getFibonacciXPSystem() {
    if (!instance) {
        instance = new FibonacciXPSystem();
    }
    return instance;
}

module.exports = { 
    FibonacciXPSystem, 
    getFibonacciXPSystem,
    FIBONACCI_XP,
    LEVEL_THRESHOLDS,
    DECAY_RATES
};
