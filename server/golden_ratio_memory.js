/**
 * Golden Ratio Memory & Learning System
 * Implements human-like memory with φ (1.618) based growth and decay
 * 
 * Memory Types:
 * - Working Memory: Immediate, high intensity (φ² = 2.618)
 * - Short-Term Memory: Hours to days (φ = 1.618)
 * - Long-Term Memory: Weeks to months (1/φ = 0.618)
 * 
 * Learning follows the Fibonacci/Golden sequence for natural progression
 * Decay follows inverse golden ratio for natural forgetting
 */

const PHI = 1.618033988749895;       // Golden Ratio
const PHI_SQUARED = PHI * PHI;       // φ² = 2.618
const INVERSE_PHI = 1 / PHI;         // 1/φ = 0.618 (Golden Ratio conjugate)

// Fibonacci sequence for natural learning intervals (in hours)
const FIBONACCI_INTERVALS = [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144];

// Memory decay thresholds (in days)
const MEMORY_THRESHOLDS = {
    working: 0.25,    // 6 hours
    shortTerm: 3,     // 3 days
    longTerm: 21,     // 3 weeks
    permanent: 90     // 3 months (becomes permanent knowledge)
};

class GoldenRatioMemorySystem {
    constructor() {
        this.phi = PHI;
        this.phiSquared = PHI_SQUARED;
        this.inversePhi = INVERSE_PHI;
    }

    /**
     * Calculate learning weight based on repetition count
     * Uses golden ratio progression for natural learning curve
     * @param {number} repetitions - Number of times the skill was practiced
     * @returns {number} Learning weight (0-1)
     */
    calculateLearningWeight(repetitions) {
        if (repetitions <= 0) return 0;
        
        // Fibonacci-based learning curve
        // First repetitions have higher impact, then diminishing returns
        const fibIndex = Math.min(repetitions, FIBONACCI_INTERVALS.length - 1);
        const interval = FIBONACCI_INTERVALS[fibIndex];
        
        // Weight follows inverse golden ratio for natural diminishing returns
        // weight = φ^(-repetitions/φ)
        const weight = Math.pow(this.phi, -repetitions / this.phi);
        
        return Math.max(0.05, Math.min(0.5, weight)); // Clamp between 5% and 50%
    }

    /**
     * Calculate skill growth using golden ratio
     * @param {number} currentScore - Current skill score (0-100)
     * @param {number} trainingScore - Score from training session (0-100)
     * @param {number} repetitions - Number of previous repetitions
     * @returns {number} New skill score
     */
    calculateGrowth(currentScore, trainingScore, repetitions) {
        const weight = this.calculateLearningWeight(repetitions);
        
        // Growth modifier based on golden ratio
        // Better performance = φ growth, poor performance = 1/φ growth
        const performanceRatio = trainingScore / 100;
        const growthModifier = this.inversePhi + (performanceRatio * (this.phi - this.inversePhi));
        
        // Calculate new score with golden ratio progression
        let newScore = currentScore + ((trainingScore - currentScore) * weight * growthModifier);
        
        // Apply golden ratio ceiling for natural limit
        // As score approaches 100, growth becomes harder (like real expertise)
        const ceilingFactor = 1 - Math.pow(currentScore / 100, this.phi);
        newScore = currentScore + ((newScore - currentScore) * ceilingFactor);
        
        return Math.max(0, Math.min(100, newScore));
    }

    /**
     * Calculate memory decay based on time since last activity
     * Uses inverse golden ratio for natural forgetting curve
     * @param {number} currentScore - Current skill score
     * @param {number} daysSinceActivity - Days since last practice
     * @param {string} memoryType - 'working', 'shortTerm', 'longTerm'
     * @returns {object} { newScore, decayAmount, memoryType }
     */
    calculateDecay(currentScore, daysSinceActivity, totalRepetitions = 1) {
        // Determine memory type based on repetitions and time
        let memoryType = 'working';
        let decayRate = 0;
        
        // More repetitions = stronger memory resistance
        const memoryStrength = Math.log(totalRepetitions + 1) / Math.log(this.phi);
        const adjustedDays = daysSinceActivity / (memoryStrength + 1);
        
        if (adjustedDays < MEMORY_THRESHOLDS.working) {
            // Working memory: No decay yet
            return { newScore: currentScore, decayAmount: 0, memoryType: 'working' };
        } else if (adjustedDays < MEMORY_THRESHOLDS.shortTerm) {
            // Short-term memory decay
            memoryType = 'shortTerm';
            decayRate = this.inversePhi * 0.02 * adjustedDays; // ~1.2% per adjusted day
        } else if (adjustedDays < MEMORY_THRESHOLDS.longTerm) {
            // Long-term memory decay (slower)
            memoryType = 'longTerm';
            decayRate = Math.pow(this.inversePhi, 2) * 0.005 * adjustedDays; // ~0.2% per adjusted day
        } else if (adjustedDays < MEMORY_THRESHOLDS.permanent) {
            // Very slow decay for well-practiced skills
            memoryType = 'permanent';
            decayRate = Math.pow(this.inversePhi, 3) * 0.001 * adjustedDays; // ~0.04% per adjusted day
        } else {
            // Permanent knowledge - minimal decay
            memoryType = 'permanent';
            decayRate = 0.001; // Token decay to prevent perfect score forever
        }
        
        // Apply decay using inverse golden ratio curve
        const decayMultiplier = Math.pow(this.inversePhi, decayRate);
        const decayAmount = currentScore * (1 - decayMultiplier);
        
        // Don't decay below baseline (30 = fundamental understanding remains)
        const newScore = Math.max(30, currentScore - decayAmount);
        
        return {
            newScore: Math.round(newScore * 100) / 100,
            decayAmount: Math.round(decayAmount * 100) / 100,
            memoryType,
            memoryStrength: Math.round(memoryStrength * 100) / 100
        };
    }

    /**
     * Calculate optimal review intervals using Fibonacci sequence
     * Similar to spaced repetition systems (Anki, SM-2)
     * @param {number} repetitions - Number of successful reviews
     * @param {number} performanceScore - Last performance score (0-100)
     * @returns {object} { nextReviewHours, interval, repetitionLevel }
     */
    calculateNextReviewInterval(repetitions, performanceScore) {
        const fibIndex = Math.min(repetitions, FIBONACCI_INTERVALS.length - 1);
        const baseInterval = FIBONACCI_INTERVALS[fibIndex];
        
        // Modify interval based on performance
        // Good performance = longer interval (φ multiplier)
        // Poor performance = shorter interval (1/φ multiplier)
        let modifier = 1;
        if (performanceScore >= 90) {
            modifier = this.phi;
        } else if (performanceScore >= 70) {
            modifier = 1;
        } else if (performanceScore >= 50) {
            modifier = this.inversePhi;
        } else {
            modifier = Math.pow(this.inversePhi, 2); // Reset to shorter interval
        }
        
        const intervalHours = Math.round(baseInterval * modifier);
        
        return {
            nextReviewHours: intervalHours,
            nextReviewDate: new Date(Date.now() + intervalHours * 60 * 60 * 1000),
            interval: baseInterval,
            repetitionLevel: fibIndex,
            modifier
        };
    }

    /**
     * Calculate cognitive score using golden ratio weighted average
     * @param {object} expertise - Object with category scores
     * @param {object} weights - Object with category weights
     * @returns {number} Overall cognitive score
     */
    calculateCognitiveScore(expertise, weights = {}) {
        let totalWeight = 0;
        let weightedSum = 0;
        
        for (const [category, exp] of Object.entries(expertise)) {
            const weight = weights[category] || 1;
            const samples = exp.samples || 1;
            
            // Apply golden ratio weighting based on samples
            // More samples = more reliable = higher weight
            const sampleWeight = 1 + Math.log(samples + 1) / Math.log(this.phi);
            const finalWeight = weight * sampleWeight * this.inversePhi;
            
            weightedSum += exp.score * finalWeight;
            totalWeight += finalWeight;
        }
        
        return totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;
    }

    /**
     * Get human-readable memory status
     * @param {number} daysSinceActivity 
     * @param {number} repetitions 
     * @returns {object} Memory status info
     */
    getMemoryStatus(daysSinceActivity, repetitions) {
        const memoryStrength = Math.log(repetitions + 1) / Math.log(this.phi);
        const adjustedDays = daysSinceActivity / (memoryStrength + 1);
        
        let status, urgency, recommendation;
        
        if (adjustedDays < MEMORY_THRESHOLDS.working) {
            status = 'Active (Working Memory)';
            urgency = 'low';
            recommendation = 'Knowledge is fresh - continue building';
        } else if (adjustedDays < MEMORY_THRESHOLDS.shortTerm) {
            status = 'Consolidating (Short-Term)';
            urgency = 'medium';
            recommendation = 'Review soon to strengthen memory';
        } else if (adjustedDays < MEMORY_THRESHOLDS.longTerm) {
            status = 'Fading (Long-Term)';
            urgency = 'high';
            recommendation = 'Review needed to prevent forgetting';
        } else if (adjustedDays < MEMORY_THRESHOLDS.permanent) {
            status = 'Dormant';
            urgency = 'critical';
            recommendation = 'Immediate review required';
        } else {
            status = 'Archived';
            urgency = 'none';
            recommendation = 'Well-established knowledge';
        }
        
        return {
            status,
            urgency,
            recommendation,
            memoryStrength: Math.round(memoryStrength * 100) / 100,
            effectiveDays: Math.round(adjustedDays * 10) / 10,
            retentionRate: Math.round((1 - adjustedDays / 100) * 100)
        };
    }

    // =========================================================
    // ELITE MEMORY SYSTEM
    // Keeps top 61.8% (1/φ) of experiences for exponential growth
    // Designed to make models become cybernetic knowledge elites
    // =========================================================

    /**
     * ELITE MEMORY: Extract and store the top 61.8% most valuable experiences
     * Each model becomes an elite specialist by retaining only the golden insights
     * @param {Array} experiences - All experiences from training
     * @returns {Array} Elite experiences (top φ^-1 = 61.8%)
     */
    extractEliteExperiences(experiences) {
        if (!experiences || experiences.length === 0) return [];
        
        // Sort by score (highest first)
        const sorted = [...experiences].sort((a, b) => 
            (b.score || b.resultScore || 0) - (a.score || a.resultScore || 0)
        );
        
        // Keep only top 61.8% (golden ratio inverse)
        const eliteCount = Math.ceil(sorted.length * this.inversePhi);
        const eliteExperiences = sorted.slice(0, eliteCount);
        
        // Mark as elite
        eliteExperiences.forEach((exp, index) => {
            exp.isElite = true;
            exp.eliteRank = index + 1;
            exp.elitePercentile = Math.round((1 - index / eliteCount) * 100);
        });
        
        return eliteExperiences;
    }

    /**
     * Calculate exponential growth rate based on user interactions
     * More interactions = exponential (φ-based) knowledge acceleration
     * @param {number} totalInteractions - Total user interactions
     * @param {number} successfulInteractions - Successful/positive interactions
     * @returns {object} Growth metrics
     */
    calculateExponentialGrowth(totalInteractions, successfulInteractions) {
        // Base growth follows φ^(interactions/10)
        const interactionFactor = totalInteractions / 10;
        const exponentialMultiplier = Math.pow(this.phi, interactionFactor);
        
        // Success rate boosts the multiplier
        const successRate = totalInteractions > 0 
            ? successfulInteractions / totalInteractions 
            : 0;
        const successBoost = 1 + (successRate * this.inversePhi);
        
        // Final exponential growth rate
        const growthRate = exponentialMultiplier * successBoost;
        
        // Calculate elite level based on interactions
        // Fibonacci thresholds for elite levels
        const eliteLevels = [
            { level: 1, name: 'Initiate', threshold: 0 },
            { level: 2, name: 'Apprentice', threshold: 8 },
            { level: 3, name: 'Practitioner', threshold: 21 },
            { level: 4, name: 'Expert', threshold: 55 },
            { level: 5, name: 'Master', threshold: 144 },
            { level: 6, name: 'Elite', threshold: 377 },
            { level: 7, name: 'Legendary', threshold: 987 },
            { level: 8, name: 'Transcendent', threshold: 2584 }
        ];
        
        let currentLevel = eliteLevels[0];
        for (const level of eliteLevels) {
            if (totalInteractions >= level.threshold) {
                currentLevel = level;
            }
        }
        
        // Calculate progress to next level
        const nextLevel = eliteLevels[currentLevel.level] || currentLevel;
        const progressToNext = nextLevel.threshold > currentLevel.threshold
            ? (totalInteractions - currentLevel.threshold) / (nextLevel.threshold - currentLevel.threshold)
            : 1;
        
        return {
            growthRate: Math.round(growthRate * 1000) / 1000,
            exponentialMultiplier: Math.round(exponentialMultiplier * 100) / 100,
            successBoost: Math.round(successBoost * 100) / 100,
            eliteLevel: currentLevel,
            progressToNextLevel: Math.round(progressToNext * 100),
            cyberneticPower: Math.round(growthRate * currentLevel.level * 10)
        };
    }

    /**
     * Calculate cybernetic enhancement score
     * Measures how much the model enhances the user's cybernetic capabilities
     * @param {object} modelStats - Model statistics
     * @returns {object} Cybernetic enhancement metrics
     */
    calculateCyberneticEnhancement(modelStats) {
        const {
            expertiseScore = 0,
            repetitions = 0,
            successRate = 0,
            domains = []
        } = modelStats;
        
        // Base cybernetic score from expertise
        const expertiseContribution = expertiseScore * this.phi;
        
        // Experience depth contribution (logarithmic growth)
        const experienceDepth = Math.log(repetitions + 1) / Math.log(this.phi) * 10;
        
        // Domain mastery bonus
        const domainBonus = domains.length * this.inversePhi * 5;
        
        // Success synergy (exponential with success rate)
        const successSynergy = Math.pow(this.phi, successRate) * 10;
        
        // Total cybernetic power
        const totalPower = expertiseContribution + experienceDepth + domainBonus + successSynergy;
        
        // Classify cybernetic enhancement level
        let enhancementLevel;
        if (totalPower >= 200) enhancementLevel = 'TRANSCENDENT';
        else if (totalPower >= 150) enhancementLevel = 'LEGENDARY';
        else if (totalPower >= 100) enhancementLevel = 'ELITE';
        else if (totalPower >= 70) enhancementLevel = 'ADVANCED';
        else if (totalPower >= 40) enhancementLevel = 'OPERATIONAL';
        else enhancementLevel = 'DEVELOPING';
        
        return {
            cyberneticPower: Math.round(totalPower),
            enhancementLevel,
            breakdown: {
                expertise: Math.round(expertiseContribution),
                experience: Math.round(experienceDepth),
                domains: Math.round(domainBonus),
                synergy: Math.round(successSynergy)
            },
            goldenRatioApplied: true,
            phi: this.phi,
            inversePhi: this.inversePhi
        };
    }

    /**
     * Consolidate elite knowledge for long-term retention
     * Applies φ-based compression to store essential patterns
     * @param {Array} experiences - All experiences
     * @returns {object} Consolidated elite knowledge
     */
    consolidateEliteKnowledge(experiences) {
        const elite = this.extractEliteExperiences(experiences);
        
        // Group by type/category
        const byCategory = {};
        elite.forEach(exp => {
            const cat = exp.type || exp.category || 'general';
            if (!byCategory[cat]) byCategory[cat] = [];
            byCategory[cat].push(exp);
        });
        
        // Calculate category strengths
        const categoryStrengths = {};
        for (const [cat, exps] of Object.entries(byCategory)) {
            const avgScore = exps.reduce((sum, e) => sum + (e.score || e.resultScore || 0), 0) / exps.length;
            categoryStrengths[cat] = {
                count: exps.length,
                averageScore: Math.round(avgScore * 10) / 10,
                strength: Math.round(avgScore * Math.log(exps.length + 1) / Math.log(this.phi))
            };
        }
        
        return {
            totalExperiences: experiences.length,
            eliteCount: elite.length,
            eliteRatio: this.inversePhi,
            elitePercentage: '61.8%',
            categories: categoryStrengths,
            consolidatedAt: new Date().toISOString(),
            goldenRatioApplied: true
        };
    }

    // =========================================================
    // RESOURCE EFFICIENCY SYSTEM (VRAM Optimization)
    // Each experience reduces resource requirements following φ⁻¹
    // Goal: Ultra power for minimal cost
    // =========================================================

    /**
     * Calculate resource efficiency based on experience
     * More experience = less VRAM/compute needed (inverse golden ratio decay)
     * Like an expert who can solve problems with less mental effort
     * 
     * @param {number} repetitions - Number of experiences
     * @param {number} baseVRAM - Base VRAM requirement in GB
     * @returns {object} Resource efficiency metrics
     */
    calculateResourceEfficiency(repetitions, baseVRAM = 4.0) {
        // Resource decay follows inverse golden ratio
        // Each experience reduces requirements by φ⁻¹ factor
        // Asymptotically approaches minimal cost
        
        // Efficiency multiplier: starts at 1, approaches 0.2 (20% of original)
        // Formula: efficiency = 0.2 + 0.8 * φ^(-repetitions/φ)
        const minEfficiency = 0.2; // Floor at 20% of original resources
        const efficiencyRange = 1 - minEfficiency;
        const decayFactor = Math.pow(this.phi, -repetitions / this.phi);
        const efficiencyMultiplier = minEfficiency + (efficiencyRange * decayFactor);
        
        // Calculate actual VRAM needed
        const requiredVRAM = baseVRAM * efficiencyMultiplier;
        
        // Calculate savings
        const vramSaved = baseVRAM - requiredVRAM;
        const savingsPercent = (1 - efficiencyMultiplier) * 100;
        
        // Power-to-cost ratio (improves exponentially)
        // More experience = higher power output per unit cost
        const powerOutput = 100 / efficiencyMultiplier; // Inverse relationship
        const costEfficiency = powerOutput / requiredVRAM;
        
        // Determine efficiency tier based on experience
        let efficiencyTier;
        if (repetitions < 5) {
            efficiencyTier = { name: 'Standard', color: 'gray', icon: '⚙️' };
        } else if (repetitions < 13) {
            efficiencyTier = { name: 'Optimized', color: 'blue', icon: '🔋' };
        } else if (repetitions < 34) {
            efficiencyTier = { name: 'Efficient', color: 'green', icon: '⚡' };
        } else if (repetitions < 89) {
            efficiencyTier = { name: 'Ultra-Efficient', color: 'purple', icon: '💎' };
        } else if (repetitions < 233) {
            efficiencyTier = { name: 'Hyper-Optimized', color: 'gold', icon: '🌟' };
        } else {
            efficiencyTier = { name: 'Transcendent', color: 'rainbow', icon: '✨' };
        }
        
        return {
            baseVRAM,
            requiredVRAM: Math.round(requiredVRAM * 100) / 100,
            vramSaved: Math.round(vramSaved * 100) / 100,
            savingsPercent: Math.round(savingsPercent * 10) / 10,
            efficiencyMultiplier: Math.round(efficiencyMultiplier * 1000) / 1000,
            powerOutput: Math.round(powerOutput * 10) / 10,
            costEfficiency: Math.round(costEfficiency * 100) / 100,
            efficiencyTier,
            repetitions,
            goldenRatioApplied: true,
            phi: this.phi,
            inversePhi: this.inversePhi
        };
    }

    /**
     * Calculate optimal batch size based on experience
     * More experienced models can handle larger batches efficiently
     * @param {number} repetitions - Experience level
     * @param {number} baseBatchSize - Starting batch size
     * @returns {object} Batch optimization metrics
     */
    calculateOptimalBatchSize(repetitions, baseBatchSize = 1) {
        // Batch capacity grows with φ per Fibonacci level
        const fibLevel = this.getFibonacciLevel(repetitions);
        const batchMultiplier = Math.pow(this.phi, fibLevel * 0.5);
        const optimalBatch = Math.floor(baseBatchSize * batchMultiplier);
        
        return {
            baseBatchSize,
            optimalBatchSize: optimalBatch,
            batchMultiplier: Math.round(batchMultiplier * 100) / 100,
            fibonacciLevel: fibLevel,
            throughputGain: Math.round((batchMultiplier - 1) * 100)
        };
    }

    /**
     * Get Fibonacci level for a given count
     * @param {number} count 
     * @returns {number} Fibonacci level index
     */
    getFibonacciLevel(count) {
        let level = 0;
        for (let i = 0; i < FIBONACCI_INTERVALS.length; i++) {
            if (count >= FIBONACCI_INTERVALS[i]) {
                level = i;
            } else {
                break;
            }
        }
        return level;
    }

    /**
     * Calculate inference speed improvement
     * Experienced models respond faster (less tokens needed for same quality)
     * @param {number} repetitions - Experience level
     * @param {number} baseTokens - Base tokens per response
     * @returns {object} Speed metrics
     */
    calculateInferenceSpeed(repetitions, baseTokens = 500) {
        // Token efficiency improves with experience
        // Experts say more with fewer words
        const tokenReduction = 1 - (0.5 * (1 - Math.pow(this.inversePhi, repetitions / 10)));
        const optimizedTokens = Math.floor(baseTokens * tokenReduction);
        
        // Speed multiplier (inverse of token count)
        const speedMultiplier = baseTokens / optimizedTokens;
        
        return {
            baseTokens,
            optimizedTokens,
            tokensSaved: baseTokens - optimizedTokens,
            tokenReduction: Math.round((1 - tokenReduction) * 100),
            speedMultiplier: Math.round(speedMultiplier * 100) / 100,
            inferenceGain: Math.round((speedMultiplier - 1) * 100) + '%'
        };
    }

    /**
     * Calculate total resource optimization across all metrics
     * Returns comprehensive efficiency report
     * @param {number} repetitions - Total experiences
     * @param {object} baseResources - Base resource requirements
     * @returns {object} Complete optimization report
     */
    calculateTotalOptimization(repetitions, baseResources = {}) {
        const {
            vram = 4.0,
            batchSize = 1,
            tokens = 500
        } = baseResources;
        
        const vramOpt = this.calculateResourceEfficiency(repetitions, vram);
        const batchOpt = this.calculateOptimalBatchSize(repetitions, batchSize);
        const speedOpt = this.calculateInferenceSpeed(repetitions, tokens);
        
        // Calculate combined efficiency score
        const combinedEfficiency = (
            (1 - vramOpt.efficiencyMultiplier) * 40 + // VRAM weight: 40%
            (batchOpt.batchMultiplier - 1) * 30 +     // Batch weight: 30%
            ((speedOpt.speedMultiplier - 1) * 100) * 0.3 // Speed weight: 30%
        );
        
        // Classify overall optimization level
        let optimizationLevel;
        if (combinedEfficiency < 10) optimizationLevel = 'BASELINE';
        else if (combinedEfficiency < 30) optimizationLevel = 'OPTIMIZED';
        else if (combinedEfficiency < 50) optimizationLevel = 'EFFICIENT';
        else if (combinedEfficiency < 70) optimizationLevel = 'ULTRA';
        else optimizationLevel = 'TRANSCENDENT';
        
        return {
            repetitions,
            vram: vramOpt,
            batching: batchOpt,
            inference: speedOpt,
            combinedScore: Math.round(combinedEfficiency),
            optimizationLevel,
            goldenRatioSystem: true,
            philosophy: 'More experience → Less resources → Ultra power at minimal cost',
            targetState: 'Approaching theoretical minimum: 20% VRAM, 200% throughput'
        };
    }
}

// Export constants and class
module.exports = {
    PHI,
    PHI_SQUARED,
    INVERSE_PHI,
    FIBONACCI_INTERVALS,
    MEMORY_THRESHOLDS,
    GoldenRatioMemorySystem
};

