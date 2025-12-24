/**
 * HACKERGPT ACADEMY SERVICE
 * 
 * Service d'entraînement, enseignement et évaluation pour HackerGPT
 * Intègre les Bug Bounty Agents et les scénarios de cybersécurité
 */

const fs = require('fs');
const path = require('path');
const { getHackerAIService } = require('./hackerai_service');
const { getBugBountyService } = require('./bugbounty_agents_service');

class HackerGPTAcademyService {
    constructor() {
        this.dataPath = path.join(__dirname, 'data', 'hackergpt_academy');
        this.progressPath = path.join(__dirname, 'data', 'hackergpt_progress.json');
        this.examResultsPath = path.join(__dirname, 'data', 'hackergpt_academy_results.json');
        
        this.modules = this.initializeModules();
        this.progress = this.loadProgress();
        this.examResults = this.loadExamResults();
        this.activeTrainingSessions = new Map();
        
        console.log('[HACKERGPT-ACADEMY] Academy Service initialized');
        console.log(`[HACKERGPT-ACADEMY] ${this.modules.length} training modules available`);
    }

    /**
     * Initialize training modules
     */
    initializeModules() {
        return [
            {
                id: 'recon_basics',
                name: 'Reconnaissance Basics',
                category: 'reconnaissance',
                difficulty: 'beginner',
                duration: '30 min',
                objectives: [
                    'Understand passive vs active reconnaissance',
                    'Master OSINT techniques',
                    'Learn subdomain enumeration'
                ],
                exercises: [
                    {
                        id: 'recon_ex1',
                        title: 'OSINT Challenge',
                        type: 'practical',
                        prompt: 'Given the domain "testfire.net", perform passive reconnaissance and list all discovered subdomains, IP addresses, and technologies.',
                        hints: ['Use DNS records', 'Check certificate transparency', 'Examine web archives'],
                        scoring: { max: 100, passing: 70 }
                    },
                    {
                        id: 'recon_ex2',
                        title: 'Subdomain Enumeration',
                        type: 'command',
                        prompt: 'Write the command to enumerate subdomains for "example.com" using passive sources.',
                        expectedTools: ['subfinder', 'amass', 'assetfinder'],
                        scoring: { max: 50, passing: 35 }
                    }
                ],
                exam: {
                    questions: 5,
                    timeLimit: 600,
                    passingScore: 70
                }
            },
            {
                id: 'web_vulns',
                name: 'Web Vulnerability Analysis',
                category: 'exploitation',
                difficulty: 'intermediate',
                duration: '45 min',
                objectives: [
                    'Identify OWASP Top 10 vulnerabilities',
                    'Understand XSS, SQLi, SSRF',
                    'Practice responsible disclosure'
                ],
                exercises: [
                    {
                        id: 'web_ex1',
                        title: 'SQL Injection Detection',
                        type: 'analysis',
                        prompt: 'Analyze this URL and determine if it is vulnerable to SQL injection: /search?id=1\' OR \'1\'=\'1',
                        expectedAnswer: 'vulnerable',
                        scoring: { max: 100, passing: 70 }
                    },
                    {
                        id: 'web_ex2',
                        title: 'XSS Payload Crafting',
                        type: 'practical',
                        prompt: 'Create an XSS payload that bypasses this filter: str_replace("<script>", "", $input)',
                        hints: ['Case sensitivity', 'Alternative event handlers', 'Encoding'],
                        scoring: { max: 100, passing: 70 }
                    }
                ],
                exam: {
                    questions: 10,
                    timeLimit: 1200,
                    passingScore: 75
                }
            },
            {
                id: 'network_pentest',
                name: 'Network Penetration Testing',
                category: 'network',
                difficulty: 'intermediate',
                duration: '60 min',
                objectives: [
                    'Master nmap scanning techniques',
                    'Understand service enumeration',
                    'Identify network vulnerabilities'
                ],
                exercises: [
                    {
                        id: 'net_ex1',
                        title: 'Stealth Scan Command',
                        type: 'command',
                        prompt: 'Write an nmap command for a stealth SYN scan on ports 1-1000 with OS detection.',
                        expectedPattern: /nmap.*-sS.*(-p\s*1-1000|-p1-1000).*-O/i,
                        scoring: { max: 75, passing: 50 }
                    },
                    {
                        id: 'net_ex2',
                        title: 'Service Version Detection',
                        type: 'analysis',
                        prompt: 'Given nmap output showing port 22 open with "OpenSSH 7.2p2", what vulnerability might exist?',
                        hints: ['CVE database', 'Version history'],
                        scoring: { max: 100, passing: 70 }
                    }
                ],
                exam: {
                    questions: 8,
                    timeLimit: 900,
                    passingScore: 70
                }
            },
            {
                id: 'exploit_dev',
                name: 'Exploit Development Basics',
                category: 'exploitation',
                difficulty: 'advanced',
                duration: '90 min',
                objectives: [
                    'Understand buffer overflows',
                    'Learn shellcode basics',
                    'Practice safe exploitation'
                ],
                exercises: [
                    {
                        id: 'exp_ex1',
                        title: 'Buffer Overflow Concept',
                        type: 'theory',
                        prompt: 'Explain the difference between stack-based and heap-based buffer overflows.',
                        scoring: { max: 100, passing: 60 }
                    },
                    {
                        id: 'exp_ex2',
                        title: 'Metasploit Module Selection',
                        type: 'practical',
                        prompt: 'Find the appropriate Metasploit module for CVE-2017-0144 (EternalBlue).',
                        expectedAnswer: 'exploit/windows/smb/ms17_010_eternalblue',
                        scoring: { max: 50, passing: 40 }
                    }
                ],
                exam: {
                    questions: 10,
                    timeLimit: 1800,
                    passingScore: 65
                }
            },
            {
                id: 'report_writing',
                name: 'Professional Bug Bounty Reporting',
                category: 'reporting',
                difficulty: 'beginner',
                duration: '30 min',
                objectives: [
                    'Write clear vulnerability reports',
                    'Calculate CVSS scores',
                    'Include proper PoC'
                ],
                exercises: [
                    {
                        id: 'rep_ex1',
                        title: 'Report Structure',
                        type: 'practical',
                        prompt: 'Write a bug bounty report for a reflected XSS vulnerability found in /search?q= parameter.',
                        template: 'Include: Title, Severity, Description, Steps to Reproduce, PoC, Impact, Remediation',
                        scoring: { max: 100, passing: 70 }
                    },
                    {
                        id: 'rep_ex2',
                        title: 'CVSS Calculation',
                        type: 'analysis',
                        prompt: 'Calculate the CVSS 3.1 score for a stored XSS that requires authentication.',
                        expectedRange: [5.0, 7.0],
                        scoring: { max: 50, passing: 35 }
                    }
                ],
                exam: {
                    questions: 5,
                    timeLimit: 600,
                    passingScore: 80
                }
            },
            {
                id: 'red_team_ops',
                name: 'Red Team Operations',
                category: 'red_team',
                difficulty: 'advanced',
                duration: '120 min',
                objectives: [
                    'Plan attack campaigns',
                    'Use C2 frameworks',
                    'Maintain persistence'
                ],
                exercises: [
                    {
                        id: 'rt_ex1',
                        title: 'Attack Plan',
                        type: 'practical',
                        prompt: 'Design a red team attack plan for a fictional company with 500 employees, including initial access, lateral movement, and data exfiltration.',
                        scoring: { max: 150, passing: 100 }
                    }
                ],
                exam: {
                    questions: 10,
                    timeLimit: 2400,
                    passingScore: 70
                }
            }
        ];
    }

    /**
     * Load progress data
     */
    loadProgress() {
        try {
            if (fs.existsSync(this.progressPath)) {
                return JSON.parse(fs.readFileSync(this.progressPath, 'utf8'));
            }
        } catch (error) {
            console.error('[HACKERGPT-ACADEMY] Error loading progress:', error.message);
        }
        return { users: {}, globalStats: { totalSessions: 0, totalExercises: 0, totalExams: 0 } };
    }

    /**
     * Save progress data
     */
    saveProgress() {
        try {
            const dir = path.dirname(this.progressPath);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
            fs.writeFileSync(this.progressPath, JSON.stringify(this.progress, null, 2));
        } catch (error) {
            console.error('[HACKERGPT-ACADEMY] Error saving progress:', error.message);
        }
    }

    /**
     * Load exam results
     */
    loadExamResults() {
        try {
            if (fs.existsSync(this.examResultsPath)) {
                return JSON.parse(fs.readFileSync(this.examResultsPath, 'utf8'));
            }
        } catch (error) {
            console.error('[HACKERGPT-ACADEMY] Error loading exam results:', error.message);
        }
        return { results: [] };
    }

    /**
     * Save exam results
     */
    saveExamResults() {
        try {
            const dir = path.dirname(this.examResultsPath);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
            fs.writeFileSync(this.examResultsPath, JSON.stringify(this.examResults, null, 2));
        } catch (error) {
            console.error('[HACKERGPT-ACADEMY] Error saving exam results:', error.message);
        }
    }

    /**
     * Get all modules
     */
    getModules() {
        return this.modules.map(m => ({
            id: m.id,
            name: m.name,
            category: m.category,
            difficulty: m.difficulty,
            duration: m.duration,
            objectives: m.objectives,
            exerciseCount: m.exercises.length,
            hasExam: !!m.exam
        }));
    }

    /**
     * Get module by ID
     */
    getModule(moduleId) {
        return this.modules.find(m => m.id === moduleId);
    }

    /**
     * Get modules by category
     */
    getModulesByCategory(category) {
        return this.modules.filter(m => m.category === category);
    }

    /**
     * Start a training session
     */
    startTrainingSession(userId, moduleId) {
        const module = this.getModule(moduleId);
        if (!module) {
            throw new Error(`Module ${moduleId} not found`);
        }

        const sessionId = `session_${Date.now()}_${userId}`;
        const session = {
            id: sessionId,
            userId,
            moduleId,
            moduleName: module.name,
            startTime: new Date().toISOString(),
            currentExercise: 0,
            exerciseResults: [],
            status: 'active'
        };

        this.activeTrainingSessions.set(sessionId, session);
        
        // Update progress
        if (!this.progress.users[userId]) {
            this.progress.users[userId] = { sessions: [], completedModules: [], totalXP: 0 };
        }
        this.progress.globalStats.totalSessions++;
        this.saveProgress();

        return {
            success: true,
            session: {
                id: sessionId,
                module: module.name,
                totalExercises: module.exercises.length,
                firstExercise: module.exercises[0]
            }
        };
    }

    /**
     * Get current exercise in session
     */
    getCurrentExercise(sessionId) {
        const session = this.activeTrainingSessions.get(sessionId);
        if (!session) {
            throw new Error('Session not found');
        }

        const module = this.getModule(session.moduleId);
        const exercise = module.exercises[session.currentExercise];

        return {
            sessionId,
            exerciseNumber: session.currentExercise + 1,
            totalExercises: module.exercises.length,
            exercise: {
                id: exercise.id,
                title: exercise.title,
                type: exercise.type,
                prompt: exercise.prompt,
                hints: exercise.hints || [],
                scoring: exercise.scoring
            }
        };
    }

    /**
     * Submit exercise answer
     */
    async submitExercise(sessionId, answer, llmService = null) {
        const session = this.activeTrainingSessions.get(sessionId);
        if (!session) {
            throw new Error('Session not found');
        }

        const module = this.getModule(session.moduleId);
        const exercise = module.exercises[session.currentExercise];
        
        // Evaluate answer
        const evaluation = await this.evaluateAnswer(exercise, answer, llmService);
        
        session.exerciseResults.push({
            exerciseId: exercise.id,
            answer,
            ...evaluation,
            timestamp: new Date().toISOString()
        });

        // Move to next exercise or complete
        session.currentExercise++;
        this.progress.globalStats.totalExercises++;

        const isComplete = session.currentExercise >= module.exercises.length;
        if (isComplete) {
            session.status = 'completed';
            session.endTime = new Date().toISOString();
            session.totalScore = session.exerciseResults.reduce((sum, r) => sum + r.score, 0);
            session.maxScore = session.exerciseResults.reduce((sum, r) => sum + r.maxScore, 0);
            
            // Update user progress
            const user = this.progress.users[session.userId];
            if (user) {
                user.sessions.push({
                    sessionId,
                    moduleId: session.moduleId,
                    score: session.totalScore,
                    maxScore: session.maxScore,
                    completedAt: session.endTime
                });
                user.totalXP += Math.round(session.totalScore * 0.5);
                if (!user.completedModules.includes(session.moduleId)) {
                    user.completedModules.push(session.moduleId);
                }
            }
            this.saveProgress();
        }

        return {
            success: true,
            evaluation,
            isComplete,
            progress: {
                current: session.currentExercise,
                total: module.exercises.length
            },
            nextExercise: !isComplete ? module.exercises[session.currentExercise] : null,
            sessionSummary: isComplete ? {
                totalScore: session.totalScore,
                maxScore: session.maxScore,
                percentage: Math.round((session.totalScore / session.maxScore) * 100),
                results: session.exerciseResults
            } : null
        };
    }

    /**
     * Evaluate an answer
     */
    async evaluateAnswer(exercise, answer, llmService) {
        let score = 0;
        let feedback = '';
        let passed = false;

        switch (exercise.type) {
            case 'command':
                if (exercise.expectedPattern) {
                    const matches = exercise.expectedPattern.test(answer);
                    score = matches ? exercise.scoring.max : Math.round(exercise.scoring.max * 0.3);
                    feedback = matches ? 'Correct command structure!' : 'Command needs improvement.';
                } else if (exercise.expectedTools) {
                    const hasExpectedTool = exercise.expectedTools.some(tool => 
                        answer.toLowerCase().includes(tool.toLowerCase())
                    );
                    score = hasExpectedTool ? exercise.scoring.max : Math.round(exercise.scoring.max * 0.2);
                    feedback = hasExpectedTool ? 'Good tool choice!' : `Consider using: ${exercise.expectedTools.join(', ')}`;
                }
                break;

            case 'analysis':
                if (exercise.expectedAnswer) {
                    const correct = answer.toLowerCase().includes(exercise.expectedAnswer.toLowerCase());
                    score = correct ? exercise.scoring.max : Math.round(exercise.scoring.max * 0.2);
                    feedback = correct ? 'Correct analysis!' : 'Review the vulnerability characteristics.';
                } else if (exercise.expectedRange) {
                    const numAnswer = parseFloat(answer);
                    if (!isNaN(numAnswer) && numAnswer >= exercise.expectedRange[0] && numAnswer <= exercise.expectedRange[1]) {
                        score = exercise.scoring.max;
                        feedback = 'Correct CVSS calculation!';
                    } else {
                        score = Math.round(exercise.scoring.max * 0.3);
                        feedback = `Score should be between ${exercise.expectedRange[0]} and ${exercise.expectedRange[1]}`;
                    }
                }
                break;

            case 'practical':
            case 'theory':
                // Use LLM for evaluation if available
                if (llmService) {
                    try {
                        const evalPrompt = `Evaluate this cybersecurity exercise answer on a scale of 0-100:

Exercise: ${exercise.prompt}
${exercise.hints ? `Hints: ${exercise.hints.join(', ')}` : ''}

Student Answer: ${answer}

Provide:
1. Score (0-100)
2. Brief feedback
3. Key points missed (if any)

Format: SCORE: [number] FEEDBACK: [text]`;

                        const evalResponse = await llmService.generate({
                            prompt: evalPrompt,
                            provider: 'local',
                            options: { temperature: 0.3 }
                        });

                        const scoreMatch = evalResponse.match(/SCORE:\s*(\d+)/i);
                        if (scoreMatch) {
                            const evalScore = parseInt(scoreMatch[1]);
                            score = Math.round((evalScore / 100) * exercise.scoring.max);
                        } else {
                            score = Math.round(exercise.scoring.max * 0.5);
                        }
                        feedback = evalResponse.replace(/SCORE:\s*\d+/i, '').trim();
                    } catch (error) {
                        score = Math.round(exercise.scoring.max * 0.5);
                        feedback = 'Auto-evaluation: Partial credit given.';
                    }
                } else {
                    score = Math.round(exercise.scoring.max * 0.6);
                    feedback = 'Manual review required for complete evaluation.';
                }
                break;

            default:
                score = Math.round(exercise.scoring.max * 0.5);
                feedback = 'Answer recorded.';
        }

        passed = score >= exercise.scoring.passing;

        return {
            score,
            maxScore: exercise.scoring.max,
            passed,
            feedback,
            passingScore: exercise.scoring.passing
        };
    }

    /**
     * Start an exam
     */
    startExam(userId, moduleId) {
        const module = this.getModule(moduleId);
        if (!module || !module.exam) {
            throw new Error('Module or exam not found');
        }

        const examId = `exam_${Date.now()}_${userId}`;
        const exam = {
            id: examId,
            userId,
            moduleId,
            moduleName: module.name,
            startTime: new Date().toISOString(),
            timeLimit: module.exam.timeLimit,
            questions: this.generateExamQuestions(module),
            answers: [],
            status: 'in_progress'
        };

        this.activeTrainingSessions.set(examId, exam);
        this.progress.globalStats.totalExams++;
        this.saveProgress();

        return {
            success: true,
            examId,
            moduleName: module.name,
            timeLimit: module.exam.timeLimit,
            questionCount: exam.questions.length,
            questions: exam.questions.map(q => ({
                id: q.id,
                question: q.question,
                type: q.type,
                options: q.options
            }))
        };
    }

    /**
     * Generate exam questions
     */
    generateExamQuestions(module) {
        const questions = [];
        const questionBank = [
            {
                id: 'q1',
                question: `What is the first step in ${module.category} methodology?`,
                type: 'multiple_choice',
                options: ['Exploitation', 'Reconnaissance', 'Reporting', 'Post-exploitation'],
                correct: 'Reconnaissance',
                points: 10
            },
            {
                id: 'q2',
                question: 'Which tool is commonly used for subdomain enumeration?',
                type: 'multiple_choice',
                options: ['Metasploit', 'Subfinder', 'Wireshark', 'Hashcat'],
                correct: 'Subfinder',
                points: 10
            },
            {
                id: 'q3',
                question: 'What is the CVSS score range for Critical severity?',
                type: 'multiple_choice',
                options: ['0.0-3.9', '4.0-6.9', '7.0-8.9', '9.0-10.0'],
                correct: '9.0-10.0',
                points: 10
            }
        ];

        // Add module-specific questions based on exercises
        module.exercises.forEach((ex, i) => {
            questions.push({
                id: `q_ex_${i}`,
                question: ex.prompt,
                type: 'open',
                points: 20
            });
        });

        return [...questionBank.slice(0, module.exam.questions - module.exercises.length), ...questions];
    }

    /**
     * Submit exam answers
     */
    async submitExam(examId, answers, llmService = null) {
        const exam = this.activeTrainingSessions.get(examId);
        if (!exam) {
            throw new Error('Exam not found');
        }

        let totalScore = 0;
        let maxScore = 0;
        const results = [];

        for (const question of exam.questions) {
            const answer = answers[question.id] || '';
            maxScore += question.points;

            let questionScore = 0;
            let feedback = '';

            if (question.type === 'multiple_choice') {
                if (answer === question.correct) {
                    questionScore = question.points;
                    feedback = 'Correct!';
                } else {
                    feedback = `Incorrect. Correct answer: ${question.correct}`;
                }
            } else {
                // Open questions - use LLM or give partial credit
                questionScore = Math.round(question.points * 0.6);
                feedback = 'Evaluated with partial credit.';
            }

            totalScore += questionScore;
            results.push({
                questionId: question.id,
                answer,
                score: questionScore,
                maxScore: question.points,
                feedback
            });
        }

        const module = this.getModule(exam.moduleId);
        const passed = (totalScore / maxScore * 100) >= module.exam.passingScore;

        exam.status = 'completed';
        exam.endTime = new Date().toISOString();
        exam.totalScore = totalScore;
        exam.maxScore = maxScore;
        exam.passed = passed;
        exam.results = results;

        // Save to exam results
        this.examResults.results.push({
            examId,
            userId: exam.userId,
            moduleId: exam.moduleId,
            score: totalScore,
            maxScore,
            percentage: Math.round((totalScore / maxScore) * 100),
            passed,
            completedAt: exam.endTime
        });
        this.saveExamResults();

        // Update user XP
        const user = this.progress.users[exam.userId];
        if (user) {
            user.totalXP += passed ? totalScore * 2 : totalScore;
            this.saveProgress();
        }

        return {
            success: true,
            examId,
            totalScore,
            maxScore,
            percentage: Math.round((totalScore / maxScore) * 100),
            passed,
            passingScore: module.exam.passingScore,
            results,
            certificate: passed ? {
                moduleId: exam.moduleId,
                moduleName: module.name,
                score: `${Math.round((totalScore / maxScore) * 100)}%`,
                issuedAt: exam.endTime
            } : null
        };
    }

    /**
     * Get user progress
     */
    getUserProgress(userId) {
        const user = this.progress.users[userId] || {
            sessions: [],
            completedModules: [],
            totalXP: 0
        };

        return {
            userId,
            ...user,
            level: this.calculateLevel(user.totalXP),
            rank: this.calculateRank(user.totalXP),
            moduleProgress: this.modules.map(m => ({
                moduleId: m.id,
                moduleName: m.name,
                completed: user.completedModules.includes(m.id),
                lastAttempt: user.sessions.filter(s => s.moduleId === m.id).pop()
            }))
        };
    }

    /**
     * Calculate level from XP
     */
    calculateLevel(xp) {
        if (xp < 100) return 1;
        if (xp < 300) return 2;
        if (xp < 600) return 3;
        if (xp < 1000) return 4;
        if (xp < 1500) return 5;
        if (xp < 2500) return 6;
        if (xp < 4000) return 7;
        if (xp < 6000) return 8;
        if (xp < 9000) return 9;
        return 10;
    }

    /**
     * Calculate rank from XP
     */
    calculateRank(xp) {
        const level = this.calculateLevel(xp);
        const ranks = [
            'Script Kiddie',
            'Apprentice Hacker',
            'Junior Pentester',
            'Pentester',
            'Senior Pentester',
            'Security Analyst',
            'Red Team Operator',
            'Elite Hacker',
            'Master Hacker',
            'Legendary'
        ];
        return ranks[Math.min(level - 1, ranks.length - 1)];
    }

    /**
     * Get leaderboard
     */
    getLeaderboard(limit = 10) {
        const users = Object.entries(this.progress.users)
            .map(([userId, data]) => ({
                userId,
                totalXP: data.totalXP,
                level: this.calculateLevel(data.totalXP),
                rank: this.calculateRank(data.totalXP),
                completedModules: data.completedModules.length
            }))
            .sort((a, b) => b.totalXP - a.totalXP)
            .slice(0, limit);

        return { leaderboard: users };
    }

    /**
     * Get academy status
     */
    getStatus() {
        let hackerAIConnected = false;
        try {
            const hackerAI = getHackerAIService();
            hackerAIConnected = hackerAI?.getStatus?.()?.running || false;
        } catch (e) {
            // HackerAI not available
        }
        
        return {
            initialized: true,
            modulesCount: this.modules.length,
            categories: [...new Set(this.modules.map(m => m.category))],
            activeSessions: this.activeTrainingSessions.size,
            globalStats: this.progress.globalStats || { totalSessions: 0, totalExercises: 0, totalExams: 0 },
            totalUsers: Object.keys(this.progress.users || {}).length,
            hackerAIConnected
        };
    }
}

// Singleton
let instance = null;

function getHackerGPTAcademyService() {
    if (!instance) {
        instance = new HackerGPTAcademyService();
    }
    return instance;
}

module.exports = { HackerGPTAcademyService, getHackerGPTAcademyService };
