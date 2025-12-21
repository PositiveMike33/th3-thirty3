/**
 * AUTO-TEACHER SYSTEM
 * ====================
 * 
 * Un modèle "professeur" entraîne automatiquement les modèles "étudiants"
 * pour accélérer leur progression Fibonacci cognitive.
 * 
 * Processus:
 * 1. Le Teacher génère des exercices adaptés au niveau de l'étudiant
 * 2. L'étudiant répond
 * 3. Le Teacher évalue et fournit du feedback
 * 4. L'interaction est enregistrée pour progression Fibonacci
 */

const FibonacciCognitiveOptimizer = require('./fibonacci_cognitive_optimizer');

class AutoTeacher {
    constructor(llmService) {
        this.llmService = llmService;
        this.cognitiveOptimizer = new FibonacciCognitiveOptimizer();
        this.isTraining = false;
        this.trainingStats = {
            totalSessions: 0,
            totalExercises: 0,
            successRate: 0,
            lastSession: null
        };
        
        // Domaines d'entraînement avec exercices progressifs
        this.trainingDomains = {
            math: {
                name: 'Mathématiques',
                levels: [
                    { difficulty: 1, prompts: ['Calcule {a} + {b}', 'Calcule {a} - {b}', 'Calcule {a} × {b}'] },
                    { difficulty: 2, prompts: ['Résous: {a}x + {b} = {c}', 'Calcule √{a}', 'Calcule {a}² + {b}²'] },
                    { difficulty: 3, prompts: ['Dérive f(x) = {a}x² + {b}x + {c}', 'Intègre f(x) = {a}x', 'Limite de {a}/x quand x→∞'] }
                ]
            },
            logic: {
                name: 'Logique',
                levels: [
                    { difficulty: 1, prompts: ['Si A alors B. A est vrai. Que peut-on conclure?', 'Vrai ou Faux: Tous les X sont Y, donc tous les Y sont X'] },
                    { difficulty: 2, prompts: ['Complète: 2, 4, 8, 16, __', 'Trouve l\'intrus: pomme, orange, carotte, banane'] },
                    { difficulty: 3, prompts: ['Syllogisme: Tous les hommes sont mortels. Socrate est un homme. Conclusion?', 'Paradoxe du menteur: "Cette phrase est fausse" - analyse'] }
                ]
            },
            coding: {
                name: 'Programmation',
                levels: [
                    { difficulty: 1, prompts: ['Écris une fonction Python qui additionne deux nombres', 'Qu\'affiche print("Hello" + "World")?'] },
                    { difficulty: 2, prompts: ['Écris une fonction récursive pour factorielle en Python', 'Complexité de la recherche binaire?'] },
                    { difficulty: 3, prompts: ['Implémente un tri rapide (quicksort) en JavaScript', 'Explique le pattern MVC'] }
                ]
            },
            language: {
                name: 'Langage',
                levels: [
                    { difficulty: 1, prompts: ['Traduis "Hello World" en français', 'Conjugue "être" au présent'] },
                    { difficulty: 2, prompts: ['Corrige: "Je suis allé au magasin hier et j\'achète du pain"', 'Synonyme de "rapide"?'] },
                    { difficulty: 3, prompts: ['Analyse le style littéraire de cette phrase: "Le soleil se couchait sur la mer d\'huile"', 'Écris un haiku sur le printemps'] }
                ]
            },
            osint: {
                name: 'OSINT & Cybersécurité',
                levels: [
                    { difficulty: 1, prompts: ['Qu\'est-ce qu\'une adresse IP?', 'Différence entre HTTP et HTTPS?'] },
                    { difficulty: 2, prompts: ['Comment fonctionne le DNS?', 'Qu\'est-ce que le WHOIS?'] },
                    { difficulty: 3, prompts: ['Explique une attaque MITM', 'Comment analyser un header d\'email pour tracer l\'origine?'] }
                ]
            }
        };
        
        console.log('[AUTO-TEACHER] System initialized - Ready to train models');
    }

    /**
     * Génère un nombre aléatoire pour les exercices
     */
    randomNum(min = 1, max = 100) {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }

    /**
     * Génère un exercice adapté au niveau Fibonacci
     */
    generateExercise(domain, fibLevel) {
        const domainConfig = this.trainingDomains[domain];
        if (!domainConfig) return null;

        // Choisir la difficulté basée sur le niveau Fibonacci
        const difficulty = Math.min(3, Math.ceil(fibLevel / 3));
        const levelConfig = domainConfig.levels.find(l => l.difficulty === difficulty) || domainConfig.levels[0];
        
        // Choisir un prompt aléatoire
        const template = levelConfig.prompts[Math.floor(Math.random() * levelConfig.prompts.length)];
        
        // Remplacer les placeholders
        const exercise = template
            .replace('{a}', this.randomNum(2, 20))
            .replace('{b}', this.randomNum(2, 15))
            .replace('{c}', this.randomNum(5, 50));

        return {
            domain,
            difficulty,
            exercise,
            template
        };
    }

    /**
     * Le Teacher évalue la réponse de l'étudiant
     * Gemini est le professeur par défaut
     */
    async evaluateResponse(exercise, studentResponse, teacherModel = 'gemini') {
        const evaluationPrompt = `Tu es un professeur expert. Évalue cette réponse:

EXERCICE: ${exercise.exercise}
RÉPONSE DE L'ÉTUDIANT: ${studentResponse}

Réponds UNIQUEMENT en JSON avec ce format:
{
  "correct": true/false,
  "score": 0-100,
  "feedback": "explication courte",
  "improvement": "conseil d'amélioration"
}`;

        try {
            // Déterminer le provider et le modèle
            let provider, model;
            if (teacherModel === 'gemini') {
                provider = 'gemini';
                model = 'gemini-2.0-flash-exp';
            } else if (teacherModel === 'groq') {
                provider = 'groq';
                model = 'llama-3.3-70b-versatile';
            } else {
                provider = 'local';
                model = teacherModel;
            }

            const response = await this.llmService.generateResponse(
                evaluationPrompt,
                null,
                provider,
                model,
                'Tu es un évaluateur précis. Réponds uniquement en JSON valide.'
            );

            // Parser la réponse JSON
            const jsonMatch = response.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                return JSON.parse(jsonMatch[0]);
            }
            
            // Fallback si pas de JSON
            return {
                correct: response.toLowerCase().includes('correct'),
                score: 50,
                feedback: response.substring(0, 200),
                improvement: 'Continue à pratiquer'
            };
        } catch (error) {
            console.error('[AUTO-TEACHER] Evaluation error:', error.message);
            return { correct: false, score: 0, feedback: 'Erreur d\'évaluation', improvement: '' };
        }
    }

    /**
     * Session d'entraînement pour un modèle
     * FOCUSED MODE: Un seul domaine à la fois pour éviter les biais
     */
    async trainModel(studentModel, options = {}) {
        const {
            domains = ['math'],  // Par défaut un seul domaine (focused)
            exerciseCount = 5,
            teacherModel = 'gemini', // Gemini comme professeur par défaut
            focusedMode = true  // Mode isolé par défaut
        } = options;

        if (this.isTraining) {
            return { success: false, error: 'Training already in progress' };
        }

        this.isTraining = true;
        const sessionStart = Date.now();
        const results = [];

        // En mode focalisé, utiliser un seul domaine
        const trainingDomains = focusedMode ? [domains[0]] : domains;

        console.log(`[AUTO-TEACHER] Starting ${focusedMode ? 'FOCUSED' : 'MIXED'} training for ${studentModel}`);
        console.log(`  → Domain(s): ${trainingDomains.join(', ')}`);
        console.log(`  → Exercises: ${exerciseCount}`);
        console.log(`  → Teacher: ${teacherModel.toUpperCase()}`);
        if (focusedMode) {
            console.log(`  → Mode: ISOLATED (anti-bias)`);
        }

        // Obtenir le niveau actuel
        const currentStatus = this.cognitiveOptimizer.getFullStatus(studentModel);
        const fibLevel = currentStatus.fibonacci?.level || 1;

        try {
            for (let i = 0; i < exerciseCount; i++) {
                // Choisir un domaine aléatoire
                const domain = domains[i % domains.length];
                const exercise = this.generateExercise(domain, fibLevel);

                if (!exercise) continue;

                console.log(`[AUTO-TEACHER] Exercise ${i + 1}/${exerciseCount}: ${exercise.exercise}`);

                // L'étudiant répond
                const startTime = Date.now();
                let studentResponse;
                try {
                    studentResponse = await this.llmService.generateResponse(
                        exercise.exercise,
                        null,
                        'local',
                        studentModel,
                        'Réponds de manière concise et directe.'
                    );
                } catch (error) {
                    studentResponse = `Erreur: ${error.message}`;
                }
                const responseTime = Date.now() - startTime;

                // Le Teacher évalue
                const evaluation = await this.evaluateResponse(exercise, studentResponse, teacherModel);

                // Enregistrer l'interaction pour la progression Fibonacci
                this.cognitiveOptimizer.recordInteraction(studentModel, {
                    success: evaluation.correct,
                    responseTime,
                    domain: exercise.domain,
                    errorType: evaluation.correct ? null : 'incorrect_answer',
                    prompt: exercise.exercise
                });

                results.push({
                    exercise: exercise.exercise,
                    domain: exercise.domain,
                    studentResponse: studentResponse.substring(0, 200),
                    evaluation,
                    responseTime
                });

                console.log(`  → Score: ${evaluation.score}/100 | ${evaluation.correct ? '✅' : '❌'}`);

                // Petit délai entre les exercices
                await new Promise(r => setTimeout(r, 500));
            }

            // Calculer les stats
            const successCount = results.filter(r => r.evaluation.correct).length;
            const avgScore = results.reduce((sum, r) => sum + r.evaluation.score, 0) / results.length;
            const sessionDuration = Date.now() - sessionStart;

            // Mettre à jour les stats globales
            this.trainingStats.totalSessions++;
            this.trainingStats.totalExercises += exerciseCount;
            this.trainingStats.successRate = (this.trainingStats.successRate * (this.trainingStats.totalSessions - 1) + (successCount / exerciseCount)) / this.trainingStats.totalSessions;
            this.trainingStats.lastSession = new Date().toISOString();

            // Obtenir le nouveau niveau
            const newStatus = this.cognitiveOptimizer.getFullStatus(studentModel);

            const summary = {
                success: true,
                studentModel,
                exerciseCount,
                successCount,
                successRate: `${((successCount / exerciseCount) * 100).toFixed(0)}%`,
                averageScore: avgScore.toFixed(1),
                sessionDuration: `${(sessionDuration / 1000).toFixed(1)}s`,
                previousLevel: fibLevel,
                newLevel: newStatus.fibonacci?.level || 1,
                leveledUp: (newStatus.fibonacci?.level || 1) > fibLevel,
                optimization: newStatus.optimization,
                results
            };

            console.log(`[AUTO-TEACHER] Session complete!`);
            console.log(`  → Success: ${summary.successRate} | Avg Score: ${summary.averageScore}`);
            if (summary.leveledUp) {
                console.log(`  → 🎉 LEVEL UP! ${summary.previousLevel} → ${summary.newLevel}`);
            }

            this.isTraining = false;
            return summary;

        } catch (error) {
            this.isTraining = false;
            console.error('[AUTO-TEACHER] Training error:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Entraînement automatique continu en arrière-plan
     */
    async startAutoTraining(studentModel, options = {}) {
        const {
            interval = 60000, // 1 minute entre les sessions
            exercisesPerSession = 3,
            maxSessions = 10,
            domains = ['math', 'logic', 'coding', 'osint']
        } = options;

        console.log(`[AUTO-TEACHER] Starting autonomous training for ${studentModel}`);
        console.log(`  → Interval: ${interval / 1000}s | Sessions: ${maxSessions}`);

        let sessionsCompleted = 0;
        
        const trainingLoop = async () => {
            if (sessionsCompleted >= maxSessions) {
                console.log(`[AUTO-TEACHER] Autonomous training complete! ${sessionsCompleted} sessions.`);
                return;
            }

            if (!this.isTraining) {
                const result = await this.trainModel(studentModel, {
                    domains,
                    exerciseCount: exercisesPerSession,
                    teacherModel: 'groq'
                });

                if (result.success) {
                    sessionsCompleted++;
                    console.log(`[AUTO-TEACHER] Auto-session ${sessionsCompleted}/${maxSessions} complete`);
                }
            }

            setTimeout(trainingLoop, interval);
        };

        // Démarrer la boucle
        trainingLoop();

        return {
            started: true,
            studentModel,
            interval,
            maxSessions,
            message: `Auto-training started. Will run ${maxSessions} sessions.`
        };
    }

    /**
     * Obtenir les stats d'entraînement
     */
    getStats() {
        return {
            ...this.trainingStats,
            isTraining: this.isTraining,
            availableDomains: Object.keys(this.trainingDomains)
        };
    }
}

module.exports = AutoTeacher;
