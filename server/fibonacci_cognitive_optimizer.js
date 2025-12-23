/**
 * FIBONACCI COGNITIVE OPTIMIZATION SYSTEM
 * ==========================================
 * 
 * Implements human-like learning where:
 * - Thinking time DECREASES as expertise grows (inverse Fibonacci)
 * - Error patterns are learned and avoided
 * - Direct-to-goal accuracy INCREASES with experience
 * 
 * Based on Fibonacci sequence for natural growth/decay:
 * 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144...
 * 
 * φ (Phi) = 1.618 - The Golden Ratio
 * 1/φ = 0.618 - Inverse for decay
 */

const fs = require('fs');
const path = require('path');

// Fibonacci sequence generator
const fibonacci = (n) => {
    if (n <= 1) return n;
    let prev = 0, curr = 1;
    for (let i = 2; i <= n; i++) {
        [prev, curr] = [curr, prev + curr];
    }
    return curr;
};

// Golden Ratio constants
const PHI = 1.618033988749895;
const INV_PHI = 0.6180339887498949;

class FibonacciCognitiveOptimizer {
    constructor() {
        this.dataPath = path.join(__dirname, 'data', 'cognitive_optimization.json');
        this.errorPatternsPath = path.join(__dirname, 'data', 'error_patterns.json');
        
        this.cognitiveData = {};
        this.errorPatterns = {};
        
        // Define expertise domains for cybersecurity training
        this.EXPERTISE_DOMAINS = {
            osint: {
                name: 'OSINT',
                description: 'Open Source Intelligence gathering and analysis',
                keywords: ['sherlock', 'reconnaissance', 'footprint', 'username', 'social media', 'whois', 'dns', 'subdomain', 'geolocation', 'doxing', 'spiderfoot']
            },
            network_security: {
                name: 'Network Security',
                description: 'Network analysis, scanning, and penetration testing',
                keywords: ['nmap', 'port', 'scan', 'firewall', 'packet', 'tcpdump', 'wireshark', 'sniff', 'mitm', 'arp', 'vpn', 'proxy', 'tor']
            },
            vulnerability: {
                name: 'Vulnerability Research',
                description: 'CVE analysis, exploit development, and vulnerability assessment',
                keywords: ['cve', 'exploit', 'vulnerability', 'buffer overflow', 'injection', 'xss', 'sqli', 'rce', 'payload', 'metasploit', 'reverse shell']
            },
            reverse_engineering: {
                name: 'Reverse Engineering',
                description: 'Binary analysis, malware reverse engineering, and code analysis',
                keywords: ['disassemble', 'decompile', 'ghidra', 'ida', 'binary', 'malware', 'assembly', 'debug', 'hook', 'unpack', 'obfuscation']
            },
            cryptography: {
                name: 'Cryptography',
                description: 'Encryption, hashing, and cryptographic protocols',
                keywords: ['encrypt', 'decrypt', 'hash', 'aes', 'rsa', 'sha256', 'md5', 'certificate', 'ssl', 'tls', 'jwt', 'signature']
            },
            web_security: {
                name: 'Web Security',
                description: 'Web application security testing',
                keywords: ['burp', 'owasp', 'cookie', 'session', 'csrf', 'cors', 'header', 'api', 'rest', 'authentication', 'authorization']
            },
            red_teaming: {
                name: 'Red Teaming',
                description: 'Adversarial simulation and offensive security',
                keywords: ['redteam', 'blueteam', 'adversary', 'c2', 'beacon', 'cobalt', 'empire', 'mimikatz', 'lateral', 'persistence', 'evasion']
            },
            prompt_engineering: {
                name: 'Prompt Engineering',
                description: 'LLM prompt crafting and injection techniques',
                keywords: ['prompt', 'inject', 'jailbreak', 'bypass', 'filter', 'guardrail', 'uncensored', 'system prompt', 'context', 'role']
            }
        };
        
        // Uncensored models with their initial expertise boosts
        this.UNCENSORED_MODELS = {
            'uandinotai/dolphin-uncensored:latest': {
                primaryExpertise: ['prompt_engineering', 'red_teaming'],
                boostFactor: 1.5
            },
            'sadiq-bd/llama3.2-3b-uncensored:latest': {
                primaryExpertise: ['osint', 'web_security'],
                boostFactor: 1.3
            },
            'nidumai/nidum-llama-3.2-3b-uncensored:latest': {
                primaryExpertise: ['vulnerability', 'reverse_engineering'],
                boostFactor: 1.4
            }
        };
        
        this.loadData();
        this.initializeUncensoredModels();
        
        console.log('[FIBONACCI-COGNITIVE] System initialized (φ=1.618, 1/φ=0.618)');
        console.log('[FIBONACCI-COGNITIVE] Expertise domains:', Object.keys(this.EXPERTISE_DOMAINS).join(', '));
    }
    
    /**
     * Initialize uncensored models with boosted expertise profiles
     */
    initializeUncensoredModels() {
        for (const [modelName, config] of Object.entries(this.UNCENSORED_MODELS)) {
            const profile = this.getModelProfile(modelName);
            
            // Apply initial expertise boosts
            for (const domain of config.primaryExpertise) {
                if (!profile.domains[domain]) {
                    profile.domains[domain] = { 
                        interactions: 10, 
                        successes: 8, 
                        expertise: 0.7 * config.boostFactor,
                        isPrimary: true
                    };
                } else if (!profile.domains[domain].isPrimary) {
                    profile.domains[domain].isPrimary = true;
                    profile.domains[domain].expertise *= config.boostFactor;
                }
            }
            
            // Mark as uncensored model
            profile.isUncensored = true;
            profile.primaryExpertise = config.primaryExpertise;
        }
        this.saveData();
    }

    loadData() {
        try {
            if (fs.existsSync(this.dataPath)) {
                this.cognitiveData = JSON.parse(fs.readFileSync(this.dataPath, 'utf8'));
            }
            if (fs.existsSync(this.errorPatternsPath)) {
                this.errorPatterns = JSON.parse(fs.readFileSync(this.errorPatternsPath, 'utf8'));
            }
        } catch (error) {
            console.error('[FIBONACCI-COGNITIVE] Load error:', error.message);
        }
    }

    saveData() {
        try {
            const dataDir = path.dirname(this.dataPath);
            if (!fs.existsSync(dataDir)) {
                fs.mkdirSync(dataDir, { recursive: true });
            }
            fs.writeFileSync(this.dataPath, JSON.stringify(this.cognitiveData, null, 2));
            fs.writeFileSync(this.errorPatternsPath, JSON.stringify(this.errorPatterns, null, 2));
        } catch (error) {
            console.error('[FIBONACCI-COGNITIVE] Save error:', error.message);
        }
    }

    /**
     * Get or create model cognitive profile
     */
    getModelProfile(modelName) {
        if (!this.cognitiveData[modelName]) {
            this.cognitiveData[modelName] = {
                modelName,
                createdAt: new Date().toISOString(),
                
                // Experience metrics
                totalInteractions: 0,
                successfulInteractions: 0,
                
                // Fibonacci level (determines optimization tier)
                fibonacciLevel: 1,
                fibonacciPosition: 1,  // Position in Fibonacci sequence
                
                // Thinking optimization (decreases with experience)
                thinkingMultiplier: 1.0,  // Starts at 100%, decreases
                targetThinkingMultiplier: 0.382,  // Target: 38.2% (Fib ratio)
                
                // Direct-to-goal accuracy (increases with experience)
                directAccuracy: 0.5,  // Starts at 50%
                targetAccuracy: 0.95,  // Target: 95%
                
                // Error learning
                errorCount: 0,
                learnedPatterns: 0,
                
                // Domain-specific expertise (auto-initialized)
                domains: {},
                primaryExpertise: [],
                
                // Uncensored model flag
                isUncensored: false,
                
                // History for trend analysis
                history: []
            };
            
            // Initialize all expertise domains
            for (const [domainId, domainInfo] of Object.entries(this.EXPERTISE_DOMAINS)) {
                this.cognitiveData[modelName].domains[domainId] = {
                    name: domainInfo.name,
                    interactions: 0,
                    successes: 0,
                    expertise: 0.5,
                    isPrimary: false
                };
            }
        }
        return this.cognitiveData[modelName];
    }
    
    /**
     * Auto-classify prompt into expertise domain based on keywords
     */
    classifyPromptDomain(prompt) {
        const promptLower = prompt.toLowerCase();
        const scores = {};
        
        for (const [domainId, domainInfo] of Object.entries(this.EXPERTISE_DOMAINS)) {
            let score = 0;
            for (const keyword of domainInfo.keywords) {
                if (promptLower.includes(keyword)) {
                    score++;
                }
            }
            if (score > 0) {
                scores[domainId] = score;
            }
        }
        
        // Return domain with highest score, or 'general'
        const sorted = Object.entries(scores).sort((a, b) => b[1] - a[1]);
        return sorted.length > 0 ? sorted[0][0] : 'general';
    }
    
    /**
     * Get best model for a specific domain
     */
    getBestModelForDomain(domain) {
        let bestModel = null;
        let bestExpertise = 0;
        
        for (const [modelName, profile] of Object.entries(this.cognitiveData)) {
            const domainExpertise = profile.domains[domain]?.expertise || 0.5;
            if (domainExpertise > bestExpertise) {
                bestExpertise = domainExpertise;
                bestModel = modelName;
            }
        }
        
        return { model: bestModel, expertise: bestExpertise };
    }

    /**
     * Calculate Fibonacci-based thinking reduction
     * As experience grows, thinking time decreases following 1/Fib pattern
     * 
     * Level 1: 100% thinking (beginner)
     * Level 5: ~61.8% thinking (competent)
     * Level 8: ~38.2% thinking (expert)
     * Level 13: ~23.6% thinking (master)
     */
    calculateThinkingMultiplier(fibLevel) {
        if (fibLevel <= 1) return 1.0;
        
        // Use inverse Fibonacci ratio for decay
        // Higher Fibonacci level = less thinking needed
        const fibValue = fibonacci(fibLevel);
        const prevFibValue = fibonacci(fibLevel - 1);
        
        // Ratio approaches 0.618 (inverse golden ratio)
        const ratio = prevFibValue / fibValue;
        
        // Apply further reduction based on level
        const levelReduction = Math.pow(INV_PHI, Math.log2(fibLevel));
        
        return Math.max(0.1, ratio * levelReduction);  // Minimum 10%
    }

    /**
     * Calculate direct-to-goal accuracy based on experience
     * Follows Fibonacci growth pattern
     */
    calculateDirectAccuracy(fibLevel, successRate) {
        if (fibLevel <= 1) return 0.5;
        
        // Base accuracy from Fibonacci position
        const fibValue = fibonacci(fibLevel);
        const baseAccuracy = 1 - (1 / Math.log2(fibValue + 1));
        
        // Adjust by actual success rate
        const adjustedAccuracy = (baseAccuracy * 0.7) + (successRate * 0.3);
        
        return Math.min(0.99, Math.max(0.5, adjustedAccuracy));
    }

    /**
     * Determine Fibonacci level based on experience
     */
    determineFibonacciLevel(interactions, successRate) {
        // Find the Fibonacci number closest to interactions
        let level = 1;
        let fibSum = 0;
        
        while (fibSum < interactions) {
            level++;
            fibSum += fibonacci(level);
            if (level > 20) break;  // Cap at level 20
        }
        
        // Adjust by success rate (poor performance slows progression)
        const adjustedLevel = Math.floor(level * successRate);
        
        return Math.max(1, adjustedLevel);
    }

    /**
     * Record an interaction and update cognitive optimization
     * Auto-classifies domain if not provided
     */
    recordInteraction(modelName, options) {
        const {
            success = true,
            responseTime = 0,
            thinkingTime = 0,  // Time spent in "thinking" phase
            domain = null,  // Will auto-classify if null
            errorType = null,
            prompt = '',
            response = ''
        } = options;

        // Auto-classify domain from prompt if not provided
        const actualDomain = domain || this.classifyPromptDomain(prompt);
        
        const profile = this.getModelProfile(modelName);
        
        // Update counters
        profile.totalInteractions++;
        if (success) {
            profile.successfulInteractions++;
        } else if (errorType) {
            profile.errorCount++;
            this.recordError(modelName, errorType, prompt);
        }

        // Calculate success rate
        const successRate = profile.successfulInteractions / profile.totalInteractions;

        // Update Fibonacci level
        const newFibLevel = this.determineFibonacciLevel(
            profile.totalInteractions, 
            successRate
        );
        
        const leveledUp = newFibLevel > profile.fibonacciLevel;
        profile.fibonacciLevel = newFibLevel;
        profile.fibonacciPosition = fibonacci(newFibLevel);

        // Update thinking multiplier (decreases with experience)
        profile.thinkingMultiplier = this.calculateThinkingMultiplier(newFibLevel);

        // Update direct accuracy (increases with experience)
        profile.directAccuracy = this.calculateDirectAccuracy(newFibLevel, successRate);

        // Update domain expertise with Fibonacci boost for uncensored models
        if (!profile.domains[actualDomain]) {
            profile.domains[actualDomain] = { 
                interactions: 0, 
                successes: 0, 
                expertise: 0.5,
                isPrimary: false 
            };
        }
        profile.domains[actualDomain].interactions++;
        if (success) profile.domains[actualDomain].successes++;
        
        // Apply Fibonacci-enhanced expertise calculation
        const baseExpertise = this.calculateDomainExpertise(profile.domains[actualDomain]);
        
        // Boost for primary expertise domains (uncensored models)
        const isPrimaryDomain = profile.primaryExpertise?.includes(actualDomain);
        const expertiseBoost = isPrimaryDomain ? PHI * 0.1 : 0;
        
        profile.domains[actualDomain].expertise = Math.min(0.99, baseExpertise + expertiseBoost);

        // Record history point
        profile.history.push({
            timestamp: new Date().toISOString(),
            fibLevel: newFibLevel,
            thinkingMultiplier: profile.thinkingMultiplier,
            directAccuracy: profile.directAccuracy,
            successRate,
            responseTime,
            thinkingTime,
            domain: actualDomain  // Track domain for learning analysis
        });

        // Keep history manageable (last 1000 entries)
        if (profile.history.length > 1000) {
            profile.history = profile.history.slice(-1000);
        }

        profile.lastUpdated = new Date().toISOString();
        this.saveData();

        // Log level up
        if (leveledUp) {
            console.log(`[FIBONACCI-COGNITIVE] ${modelName} leveled up! Level ${newFibLevel} (Fib: ${fibonacci(newFibLevel)})`);
            console.log(`  → Domain: ${actualDomain} | Expertise: ${(profile.domains[actualDomain].expertise * 100).toFixed(1)}%`);
            console.log(`  → Thinking: ${(profile.thinkingMultiplier * 100).toFixed(1)}%`);
            console.log(`  → Accuracy: ${(profile.directAccuracy * 100).toFixed(1)}%`);
        }

        return {
            modelName,
            fibonacciLevel: newFibLevel,
            fibonacciPosition: profile.fibonacciPosition,
            thinkingMultiplier: profile.thinkingMultiplier,
            directAccuracy: profile.directAccuracy,
            successRate,
            leveledUp,
            domain: actualDomain,
            domainExpertise: profile.domains[actualDomain].expertise,
            isUncensored: profile.isUncensored
        };
    }

    /**
     * Calculate domain-specific expertise using Fibonacci growth
     */
    calculateDomainExpertise(domain) {
        const successRate = domain.interactions > 0 
            ? domain.successes / domain.interactions 
            : 0.5;
        
        // Fibonacci-based growth curve
        const interactionFactor = Math.log2(domain.interactions + 1) / 10;
        const expertise = 0.5 + (successRate * interactionFactor * PHI);
        
        return Math.min(0.99, expertise);
    }

    /**
     * Record and learn from errors
     */
    recordError(modelName, errorType, prompt) {
        if (!this.errorPatterns[modelName]) {
            this.errorPatterns[modelName] = [];
        }

        // Extract error signature (simplified pattern)
        const signature = this.extractErrorSignature(errorType, prompt);
        
        // Check if we've seen this pattern before
        const existingPattern = this.errorPatterns[modelName].find(
            p => p.signature === signature
        );

        if (existingPattern) {
            existingPattern.occurrences++;
            existingPattern.lastSeen = new Date().toISOString();
        } else {
            this.errorPatterns[modelName].push({
                signature,
                errorType,
                promptHint: prompt.substring(0, 100),
                occurrences: 1,
                firstSeen: new Date().toISOString(),
                lastSeen: new Date().toISOString(),
                learned: false
            });
        }

        // Mark as learned if seen enough times (Fibonacci threshold)
        const pattern = existingPattern || this.errorPatterns[modelName].slice(-1)[0];
        const learnThreshold = fibonacci(5);  // 5 occurrences to learn
        if (pattern.occurrences >= learnThreshold && !pattern.learned) {
            pattern.learned = true;
            const profile = this.getModelProfile(modelName);
            profile.learnedPatterns++;
            console.log(`[FIBONACCI-COGNITIVE] ${modelName} learned error pattern: ${signature}`);
        }

        this.saveData();
    }

    /**
     * Extract simplified error signature
     */
    extractErrorSignature(errorType, prompt) {
        const keywords = prompt.toLowerCase()
            .split(/\s+/)
            .filter(w => w.length > 4)
            .slice(0, 3)
            .join('_');
        
        return `${errorType}:${keywords}`;
    }

    /**
     * Check if error pattern is known (to avoid)
     */
    isKnownErrorPattern(modelName, prompt) {
        const patterns = this.errorPatterns[modelName] || [];
        const testSignature = prompt.toLowerCase()
            .split(/\s+/)
            .filter(w => w.length > 4)
            .slice(0, 3)
            .join('_');

        return patterns.some(p => 
            p.learned && p.signature.includes(testSignature)
        );
    }

    /**
     * Get optimization recommendations for a query
     */
    getOptimizationRecommendations(modelName, domain = 'general') {
        const profile = this.getModelProfile(modelName);
        
        return {
            modelName,
            fibonacciLevel: profile.fibonacciLevel,
            
            // Thinking optimization
            recommendedThinkingTokens: Math.floor(1000 * profile.thinkingMultiplier),
            thinkingReduction: `${((1 - profile.thinkingMultiplier) * 100).toFixed(0)}%`,
            
            // Response optimization
            directToGoalProbability: profile.directAccuracy,
            suggestedMaxTokens: Math.floor(500 + (500 * profile.directAccuracy)),
            
            // Domain expertise
            domainExpertise: profile.domains[domain]?.expertise || 0.5,
            
            // Error avoidance
            learnedErrorPatterns: profile.learnedPatterns,
            
            // Growth indicators
            progressToNextLevel: this.getProgressToNextLevel(profile),
            
            // System prompt modifier
            systemPromptAddition: this.generateSystemPromptAddition(profile)
        };
    }

    /**
     * Get progress to next Fibonacci level
     */
    getProgressToNextLevel(profile) {
        const currentFibSum = this.getFibonacciSum(profile.fibonacciLevel);
        const nextFibSum = this.getFibonacciSum(profile.fibonacciLevel + 1);
        const progress = (profile.totalInteractions - currentFibSum) / (nextFibSum - currentFibSum);
        return Math.min(1, Math.max(0, progress));
    }

    getFibonacciSum(n) {
        let sum = 0;
        for (let i = 1; i <= n; i++) {
            sum += fibonacci(i);
        }
        return sum;
    }

    /**
     * Generate system prompt addition based on cognitive level
     */
    generateSystemPromptAddition(profile) {
        const level = profile.fibonacciLevel;
        
        if (level <= 2) {
            return "Take your time to think through problems carefully. Show your reasoning.";
        } else if (level <= 5) {
            return "You have growing expertise. Balance thorough analysis with efficiency.";
        } else if (level <= 8) {
            return "Your expertise is high. Focus on direct, accurate answers. Minimal deliberation needed.";
        } else {
            return "Master level. Provide immediate, precise answers. You know this domain well.";
        }
    }

    /**
     * Get full cognitive status for a model
     */
    getFullStatus(modelName) {
        const profile = this.getModelProfile(modelName);
        const successRate = profile.totalInteractions > 0 
            ? profile.successfulInteractions / profile.totalInteractions 
            : 0;

        return {
            modelName,
            
            // Fibonacci progression
            fibonacci: {
                level: profile.fibonacciLevel,
                position: profile.fibonacciPosition,
                sequence: Array.from({length: profile.fibonacciLevel}, (_, i) => fibonacci(i + 1)),
                progressToNext: this.getProgressToNextLevel(profile)
            },
            
            // Cognitive optimization
            optimization: {
                thinkingMultiplier: profile.thinkingMultiplier,
                thinkingReduction: `${((1 - profile.thinkingMultiplier) * 100).toFixed(1)}%`,
                directAccuracy: profile.directAccuracy,
                accuracyPercent: `${(profile.directAccuracy * 100).toFixed(1)}%`
            },
            
            // Performance
            performance: {
                totalInteractions: profile.totalInteractions,
                successRate: `${(successRate * 100).toFixed(1)}%`,
                errorCount: profile.errorCount,
                learnedPatterns: profile.learnedPatterns
            },
            
            // Domain expertise
            domains: profile.domains,
            
            // Golden ratio context
            goldenRatio: {
                phi: PHI,
                inversePhi: INV_PHI,
                description: "Learning follows natural Fibonacci growth, thinking follows inverse decay"
            },
            
            lastUpdated: profile.lastUpdated
        };
    }

    /**
     * Get all models status
     */
    getAllModelsStatus() {
        const statuses = {};
        for (const modelName of Object.keys(this.cognitiveData)) {
            statuses[modelName] = this.getFullStatus(modelName);
        }
        return statuses;
    }
}

module.exports = FibonacciCognitiveOptimizer;
