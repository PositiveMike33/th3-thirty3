/**
 * CURRICULUM AGENT - Architecte de l'Apprentissage
 * ==================================================
 * 
 * Responsabilités:
 * 1. Composer les cheminements d'enseignement structurés
 * 2. Créer des agendas d'apprentissage personnalisés
 * 3. Classifier les cours de NOVICE → PRODIGE
 * 4. Adapter le rythme selon la progression Fibonacci
 * 
 * Niveaux de maîtrise:
 * - NOVICE (Fib 1-2): Fondamentaux
 * - APPRENTI (Fib 3-5): Pratique guidée
 * - PRATICIEN (Fib 5-8): Application autonome
 * - EXPERT (Fib 8-13): Maîtrise avancée
 * - MAÎTRE (Fib 13-21): Expertise complète
 * - PRODIGE (Fib 21+): Innovation et enseignement
 */

const fs = require('fs');
const path = require('path');

// Niveaux de maîtrise avec seuils Fibonacci
const MASTERY_LEVELS = {
    NOVICE: { minFib: 1, maxFib: 2, color: '🟢', description: 'Fondamentaux - Découverte des concepts' },
    APPRENTI: { minFib: 3, maxFib: 5, color: '🔵', description: 'Pratique guidée - Exercices supervisés' },
    PRATICIEN: { minFib: 5, maxFib: 8, color: '🟡', description: 'Application autonome - Projets réels' },
    EXPERT: { minFib: 8, maxFib: 13, color: '🟠', description: 'Maîtrise avancée - Cas complexes' },
    MAITRE: { minFib: 13, maxFib: 21, color: '🔴', description: 'Expertise complète - Recherche' },
    PRODIGE: { minFib: 21, maxFib: Infinity, color: '⭐', description: 'Innovation - Capacité d\'enseignement' }
};

// Curriculum complet OSINT & Cyber
const CURRICULUM = {
    // ═══════════════════════════════════════
    // DOMAINE: OSINT (Open Source Intelligence)
    // ═══════════════════════════════════════
    osint: {
        name: 'OSINT - Open Source Intelligence',
        description: 'Collecte et analyse de renseignements de sources ouvertes',
        tools: ['sherlock', 'spiderfoot', 'maltego', 'theharvester', 'amass', 'recon-ng'],
        paths: {
            NOVICE: {
                duration: '1 semaine',
                objectives: [
                    'Comprendre le cycle du renseignement',
                    'Maîtriser les recherches Google avancées (dorking)',
                    'Utiliser WHOIS et DNS lookups',
                    'Identifier les sources ouvertes principales'
                ],
                exercises: [
                    { type: 'theory', prompt: 'Qu\'est-ce que l\'OSINT et à quoi sert-il?' },
                    { type: 'theory', prompt: 'Expliquez les 5 phases du cycle du renseignement' },
                    { type: 'practice', prompt: 'Utilisez un Google dork pour trouver des fichiers PDF sur un domaine' },
                    { type: 'practice', prompt: 'Effectuez un WHOIS lookup et identifiez le registrar' }
                ],
                tools_intro: ['whois', 'nslookup', 'dig']
            },
            APPRENTI: {
                duration: '2 semaines',
                objectives: [
                    'Maîtriser Sherlock pour la recherche de usernames',
                    'Utiliser theHarvester pour la reconnaissance de domaines',
                    'Comprendre les métadonnées des fichiers',
                    'Analyser les profils de réseaux sociaux'
                ],
                exercises: [
                    { type: 'practice', prompt: 'Utilisez Sherlock pour trouver un username sur plusieurs plateformes' },
                    { type: 'practice', prompt: 'Lancez theHarvester sur un domaine et listez les emails trouvés' },
                    { type: 'analysis', prompt: 'Analysez les métadonnées d\'une image avec exiftool' },
                    { type: 'case_study', prompt: 'Créez un profil OSINT à partir d\'un nom de domaine' }
                ],
                tools_intro: ['sherlock', 'theharvester', 'exiftool']
            },
            PRATICIEN: {
                duration: '3 semaines',
                objectives: [
                    'Maîtriser Amass pour l\'énumération DNS',
                    'Utiliser SpiderFoot pour l\'automatisation',
                    'Créer des graphes de relations avec Maltego',
                    'Corréler des données de multiples sources'
                ],
                exercises: [
                    { type: 'practice', prompt: 'Utilisez Amass pour énumérer tous les sous-domaines' },
                    { type: 'practice', prompt: 'Configurez un scan SpiderFoot complet' },
                    { type: 'project', prompt: 'Créez un graphe Maltego reliant personnes-entreprises-domaines' },
                    { type: 'report', prompt: 'Rédigez un rapport OSINT structuré sur une cible' }
                ],
                tools_intro: ['amass', 'spiderfoot', 'maltego']
            },
            EXPERT: {
                duration: '4 semaines',
                objectives: [
                    'Développer des scripts d\'automatisation OSINT',
                    'Intégrer les APIs de renseignement (Shodan, Censys)',
                    'Analyser le dark web en toute sécurité',
                    'Créer des workflows d\'investigation complexes'
                ],
                exercises: [
                    { type: 'development', prompt: 'Écrivez un script Python qui combine Shodan + WHOIS + GeoIP' },
                    { type: 'practice', prompt: 'Utilisez Tor pour explorer des sources .onion' },
                    { type: 'case_study', prompt: 'Menez une investigation complète sur une campagne de phishing' },
                    { type: 'automation', prompt: 'Créez un pipeline n8n/Zapier pour l\'OSINT automatisé' }
                ],
                tools_intro: ['shodan', 'censys', 'tor', 'recon-ng']
            },
            MAITRE: {
                duration: '6 semaines',
                objectives: [
                    'Développer de nouveaux outils OSINT',
                    'Former des équipes aux techniques avancées',
                    'Établir des méthodologies d\'investigation',
                    'Contribuer à la communauté OSINT'
                ],
                exercises: [
                    { type: 'research', prompt: 'Identifiez une lacune dans les outils OSINT existants' },
                    { type: 'development', prompt: 'Développez un outil/module comblant cette lacune' },
                    { type: 'teaching', prompt: 'Créez un cours complet sur une technique avancée' },
                    { type: 'publication', prompt: 'Rédigez un article technique pour la communauté' }
                ],
                tools_intro: ['custom_tools', 'api_development']
            },
            PRODIGE: {
                duration: 'Continu',
                objectives: [
                    'Innover dans le domaine de l\'OSINT',
                    'Mentor de nouvelles générations',
                    'Recherche et développement',
                    'Conférences et publications'
                ],
                exercises: [
                    { type: 'innovation', prompt: 'Proposez une nouvelle méthodologie OSINT' },
                    { type: 'mentoring', prompt: 'Encadrez 3 apprentis dans leurs projets' },
                    { type: 'conference', prompt: 'Préparez une présentation pour une conférence' }
                ],
                tools_intro: ['research', 'teaching', 'innovation']
            }
        }
    },

    // ═══════════════════════════════════════
    // DOMAINE: NETWORK SCANNING
    // ═══════════════════════════════════════
    network: {
        name: 'Network Scanning & Analysis',
        description: 'Découverte et analyse d\'infrastructures réseau',
        tools: ['nmap', 'wireshark', 'masscan', 'netcat', 'tcpdump'],
        paths: {
            NOVICE: {
                duration: '1 semaine',
                objectives: [
                    'Comprendre le modèle OSI et TCP/IP',
                    'Maîtriser les scans Nmap de base',
                    'Lire les captures Wireshark simples',
                    'Identifier les ports et services communs'
                ],
                exercises: [
                    { type: 'theory', prompt: 'Expliquez les 7 couches du modèle OSI' },
                    { type: 'practice', prompt: 'Effectuez un scan Nmap -sn pour découvrir les hôtes' },
                    { type: 'practice', prompt: 'Capturez le trafic HTTP avec Wireshark et analysez' },
                    { type: 'quiz', prompt: 'Associez les ports 22, 80, 443, 3306 à leurs services' }
                ],
                tools_intro: ['nmap', 'wireshark']
            },
            APPRENTI: {
                duration: '2 semaines',
                objectives: [
                    'Maîtriser les différents types de scans Nmap',
                    'Détecter les versions de services (-sV)',
                    'Analyser les protocoles dans Wireshark',
                    'Utiliser les scripts NSE de base'
                ],
                exercises: [
                    { type: 'practice', prompt: 'Comparez les résultats de -sS, -sT et -sU' },
                    { type: 'practice', prompt: 'Utilisez nmap -sV pour identifier les versions' },
                    { type: 'analysis', prompt: 'Reconstituez une session TCP dans Wireshark' },
                    { type: 'practice', prompt: 'Lancez nmap --script=vuln sur un réseau de test' }
                ],
                tools_intro: ['nmap_scripts', 'tshark']
            },
            PRATICIEN: {
                duration: '3 semaines',
                objectives: [
                    'Effectuer des scans furtifs et timing',
                    'Analyser le trafic chiffré (patterns)',
                    'Utiliser Masscan pour les grands réseaux',
                    'Créer des scripts NSE personnalisés'
                ],
                exercises: [
                    { type: 'practice', prompt: 'Effectuez un scan -T0 et comparez avec -T4' },
                    { type: 'analysis', prompt: 'Identifiez un tunnel SSH dans une capture pcap' },
                    { type: 'practice', prompt: 'Scannez un /16 avec Masscan en moins de 5 minutes' },
                    { type: 'development', prompt: 'Écrivez un script NSE pour détecter une vulnérabilité' }
                ],
                tools_intro: ['masscan', 'nse_scripting']
            },
            EXPERT: {
                duration: '4 semaines',
                objectives: [
                    'Détection d\'intrusion via analyse réseau',
                    'Analyse forensique de captures',
                    'Évasion de firewalls et IDS',
                    'Automatisation des scans à grande échelle'
                ],
                exercises: [
                    { type: 'analysis', prompt: 'Identifiez une exfiltration de données dans un pcap' },
                    { type: 'practice', prompt: 'Contournez un IDS avec des techniques de fragmentation' },
                    { type: 'development', prompt: 'Créez un pipeline de scan automatisé avec reporting' },
                    { type: 'case_study', prompt: 'Analysez une attaque APT à partir de captures réseau' }
                ],
                tools_intro: ['suricata', 'zeek', 'custom_automation']
            },
            MAITRE: {
                duration: '6 semaines',
                objectives: [
                    'Recherche de vulnérabilités 0-day',
                    'Développement d\'outils de scan avancés',
                    'Formation d\'équipes SOC',
                    'Architecture de monitoring réseau'
                ],
                exercises: [
                    { type: 'research', prompt: 'Identifiez un comportement réseau anormal non documenté' },
                    { type: 'development', prompt: 'Développez un outil de détection basé sur ML' },
                    { type: 'architecture', prompt: 'Concevez une infrastructure de monitoring complète' }
                ],
                tools_intro: ['ml_detection', 'custom_ids']
            },
            PRODIGE: {
                duration: 'Continu',
                objectives: [
                    'Innovation en analyse réseau',
                    'Publications et brevets',
                    'Leadership technique'
                ],
                exercises: [
                    { type: 'innovation', prompt: 'Proposez une nouvelle technique de détection' },
                    { type: 'publication', prompt: 'Publiez vos recherches' }
                ],
                tools_intro: ['research', 'innovation']
            }
        }
    },

    // ═══════════════════════════════════════
    // DOMAINE: VULNERABILITY ASSESSMENT
    // ═══════════════════════════════════════
    vuln: {
        name: 'Vulnerability Assessment',
        description: 'Identification et évaluation des vulnérabilités',
        tools: ['nmap_vuln', 'nikto', 'sqlmap', 'burpsuite', 'nuclei'],
        paths: {
            NOVICE: {
                duration: '1 semaine',
                objectives: [
                    'Comprendre le CVSS et les types de vulnérabilités',
                    'Utiliser les scripts NSE vulnérabilités',
                    'Scanner les applications web avec Nikto',
                    'Identifier les vulnérabilités communes (OWASP Top 10)'
                ],
                exercises: [
                    { type: 'theory', prompt: 'Expliquez les composantes du score CVSS' },
                    { type: 'theory', prompt: 'Listez le OWASP Top 10 actuel' },
                    { type: 'practice', prompt: 'Lancez nmap --script=vuln et interprétez les résultats' },
                    { type: 'practice', prompt: 'Scannez une application web avec Nikto' }
                ],
                tools_intro: ['nmap_vuln', 'nikto']
            },
            APPRENTI: {
                duration: '2 semaines',
                objectives: [
                    'Maîtriser SQLMap pour l\'injection SQL',
                    'Utiliser Burp Suite pour le test manuel',
                    'Comprendre les XSS et CSRF',
                    'Documenter les vulnérabilités trouvées'
                ],
                exercises: [
                    { type: 'practice', prompt: 'Exploitez une injection SQL avec SQLMap' },
                    { type: 'practice', prompt: 'Interceptez et modifiez une requête avec Burp' },
                    { type: 'practice', prompt: 'Identifiez une vulnérabilité XSS stored' },
                    { type: 'report', prompt: 'Rédigez un rapport de vulnérabilité standard' }
                ],
                tools_intro: ['sqlmap', 'burpsuite']
            },
            PRATICIEN: {
                duration: '3 semaines',
                objectives: [
                    'Automatiser les scans avec Nuclei',
                    'Créer des templates de détection personnalisés',
                    'Tester les API REST/GraphQL',
                    'Évaluer les configurations cloud'
                ],
                exercises: [
                    { type: 'practice', prompt: 'Scannez avec Nuclei et créez un template custom' },
                    { type: 'practice', prompt: 'Testez une API REST pour les vulnérabilités BOLA' },
                    { type: 'practice', prompt: 'Auditez une configuration AWS S3' },
                    { type: 'project', prompt: 'Effectuez un pentest complet d\'une application' }
                ],
                tools_intro: ['nuclei', 'api_testing']
            },
            EXPERT: {
                duration: '4 semaines',
                objectives: [
                    'Développer des exploits',
                    'Analyse de code source pour vulnérabilités',
                    'Tests de pénétration avancés',
                    'Red Team operations'
                ],
                exercises: [
                    { type: 'development', prompt: 'Écrivez un exploit pour une CVE récente' },
                    { type: 'analysis', prompt: 'Effectuez une revue de code sécurité' },
                    { type: 'operation', prompt: 'Simulez une attaque Red Team complète' }
                ],
                tools_intro: ['exploit_dev', 'code_review']
            },
            MAITRE: {
                duration: '6 semaines',
                objectives: [
                    'Découverte de vulnérabilités 0-day',
                    'Bug bounty avancé',
                    'CVE publication',
                    'Formation de pentesters'
                ],
                exercises: [
                    { type: 'research', prompt: 'Trouvez une vulnérabilité non documentée' },
                    { type: 'publication', prompt: 'Soumettez un CVE' },
                    { type: 'teaching', prompt: 'Créez un cours de pentest avancé' }
                ],
                tools_intro: ['0day_research', 'responsible_disclosure']
            },
            PRODIGE: {
                duration: 'Continu',
                objectives: ['Innovation en sécurité offensive'],
                exercises: [{ type: 'innovation', prompt: 'Contribuez à la sécurité globale' }],
                tools_intro: ['research']
            }
        }
    },

    // ═══════════════════════════════════════
    // DOMAINE: CODING FOR SECURITY
    // ═══════════════════════════════════════
    coding: {
        name: 'Security Automation & Scripting',
        description: 'Programmation pour la sécurité et l\'automatisation',
        tools: ['python', 'bash', 'javascript', 'powershell'],
        paths: {
            NOVICE: {
                duration: '2 semaines',
                objectives: [
                    'Bases de Python pour la sécurité',
                    'Scripts Bash pour l\'automatisation',
                    'Manipulation de fichiers et parsing',
                    'Requêtes HTTP avec requests'
                ],
                exercises: [
                    { type: 'practice', prompt: 'Écrivez un script Python qui fait un ping sweep' },
                    { type: 'practice', prompt: 'Créez un script Bash qui liste les ports ouverts' },
                    { type: 'practice', prompt: 'Parsez un fichier de logs et extrayez les IPs' }
                ],
                tools_intro: ['python_basics', 'bash_basics']
            },
            APPRENTI: {
                duration: '3 semaines',
                objectives: [
                    'Sockets et communication réseau',
                    'Utilisation des APIs de sécurité',
                    'Automatisation avec Selenium/Playwright',
                    'Parsing HTML avec BeautifulSoup'
                ],
                exercises: [
                    { type: 'practice', prompt: 'Créez un port scanner avec sockets Python' },
                    { type: 'practice', prompt: 'Interrogez l\'API Shodan et formatez les résultats' },
                    { type: 'practice', prompt: 'Automatisez la collecte OSINT avec Playwright' }
                ],
                tools_intro: ['sockets', 'apis', 'web_scraping']
            },
            PRATICIEN: {
                duration: '4 semaines',
                objectives: [
                    'Développer des outils de reconnaissance',
                    'Créer des exploits en Python',
                    'Intégration avec Metasploit',
                    'Framework de test automatisé'
                ],
                exercises: [
                    { type: 'development', prompt: 'Développez un outil de reconnaissance complet' },
                    { type: 'development', prompt: 'Écrivez un module Metasploit en Ruby' },
                    { type: 'project', prompt: 'Créez un framework de test de sécurité' }
                ],
                tools_intro: ['tool_development', 'metasploit_modules']
            },
            EXPERT: {
                duration: '6 semaines',
                objectives: [
                    'Développement d\'exploits avancés',
                    'Reverse engineering de protocoles',
                    'Machine Learning pour la sécurité',
                    'Architecture de systèmes sécurisés'
                ],
                exercises: [
                    { type: 'development', prompt: 'Créez un detector de malware avec ML' },
                    { type: 'reverse', prompt: 'Reverse un protocole binaire propriétaire' }
                ],
                tools_intro: ['ml_security', 'reverse_engineering']
            },
            MAITRE: {
                duration: '8 semaines',
                objectives: [
                    'Contribution open source majeure',
                    'Architecture de frameworks de sécurité',
                    'Mentorat de développeurs'
                ],
                exercises: [
                    { type: 'contribution', prompt: 'Contribuez à un projet de sécurité majeur' }
                ],
                tools_intro: ['open_source', 'architecture']
            },
            PRODIGE: {
                duration: 'Continu',
                objectives: ['Innovation et leadership'],
                exercises: [{ type: 'innovation', prompt: 'Créez le prochain outil de référence' }],
                tools_intro: ['innovation']
            }
        }
    }
};

class CurriculumAgent {
    constructor() {
        this.dataPath = path.join(__dirname, 'data', 'curriculum_progress.json');
        this.agendaPath = path.join(__dirname, 'data', 'learning_agendas.json');
        
        this.progress = {};
        this.agendas = {};
        
        this.loadData();
        
        console.log('[CURRICULUM-AGENT] 📚 Système initialisé - Novice → Prodige');
        console.log(`  → Domaines: ${Object.keys(CURRICULUM).join(', ')}`);
    }

    loadData() {
        try {
            if (fs.existsSync(this.dataPath)) {
                this.progress = JSON.parse(fs.readFileSync(this.dataPath, 'utf8'));
            }
            if (fs.existsSync(this.agendaPath)) {
                this.agendas = JSON.parse(fs.readFileSync(this.agendaPath, 'utf8'));
            }
        } catch (error) {
            console.error('[CURRICULUM-AGENT] Erreur chargement:', error.message);
        }
    }

    saveData() {
        try {
            const dataDir = path.dirname(this.dataPath);
            if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
            fs.writeFileSync(this.dataPath, JSON.stringify(this.progress, null, 2));
            fs.writeFileSync(this.agendaPath, JSON.stringify(this.agendas, null, 2));
        } catch (error) {
            console.error('[CURRICULUM-AGENT] Erreur sauvegarde:', error.message);
        }
    }

    /**
     * Détermine le niveau de maîtrise basé sur le niveau Fibonacci
     */
    getMasteryLevel(fibLevel) {
        for (const [level, config] of Object.entries(MASTERY_LEVELS)) {
            if (fibLevel >= config.minFib && fibLevel < config.maxFib) {
                return { name: level, ...config };
            }
        }
        return { name: 'NOVICE', ...MASTERY_LEVELS.NOVICE };
    }

    /**
     * Obtient ou crée le profil de progression d'un modèle
     */
    getModelProgress(modelName) {
        if (!this.progress[modelName]) {
            this.progress[modelName] = {
                modelName,
                createdAt: new Date().toISOString(),
                domains: {},
                totalExercisesCompleted: 0,
                certifications: []
            };
            
            // Initialiser chaque domaine
            for (const domainKey of Object.keys(CURRICULUM)) {
                this.progress[modelName].domains[domainKey] = {
                    currentLevel: 'NOVICE',
                    exercisesCompleted: 0,
                    currentPathIndex: 0,
                    startedAt: null,
                    completedLevels: []
                };
            }
        }
        return this.progress[modelName];
    }

    /**
     * Crée un agenda d'apprentissage personnalisé
     */
    createLearningAgenda(modelName, domain, options = {}) {
        const {
            startDate = new Date(),
            hoursPerDay = 2,
            daysPerWeek = 5
        } = options;

        const curriculum = CURRICULUM[domain];
        if (!curriculum) {
            return { success: false, error: `Domaine inconnu: ${domain}` };
        }

        const progress = this.getModelProgress(modelName);
        const currentLevel = progress.domains[domain]?.currentLevel || 'NOVICE';
        const pathConfig = curriculum.paths[currentLevel];

        // Calculer les dates basées sur la durée
        const durationWeeks = parseInt(pathConfig.duration) || 1;
        const totalDays = durationWeeks * daysPerWeek;
        const totalExercises = pathConfig.exercises.length;
        const exercisesPerDay = Math.ceil(totalExercises / totalDays);

        // Générer l'agenda
        const agenda = {
            modelName,
            domain,
            domainName: curriculum.name,
            level: currentLevel,
            levelInfo: MASTERY_LEVELS[currentLevel],
            startDate: startDate.toISOString(),
            duration: pathConfig.duration,
            hoursPerDay,
            daysPerWeek,
            objectives: pathConfig.objectives,
            tools: pathConfig.tools_intro,
            schedule: []
        };

        // Créer le planning jour par jour
        let currentDate = new Date(startDate);
        let exerciseIndex = 0;

        for (let day = 1; day <= totalDays && exerciseIndex < totalExercises; day++) {
            const dayPlan = {
                day,
                date: currentDate.toISOString().split('T')[0],
                exercises: []
            };

            for (let e = 0; e < exercisesPerDay && exerciseIndex < totalExercises; e++) {
                dayPlan.exercises.push({
                    ...pathConfig.exercises[exerciseIndex],
                    index: exerciseIndex,
                    estimatedMinutes: 30
                });
                exerciseIndex++;
            }

            agenda.schedule.push(dayPlan);
            
            // Avancer au jour suivant (sauter les weekends si nécessaire)
            currentDate.setDate(currentDate.getDate() + 1);
            if (daysPerWeek === 5) {
                const dayOfWeek = currentDate.getDay();
                if (dayOfWeek === 0) currentDate.setDate(currentDate.getDate() + 1); // Dimanche
                if (dayOfWeek === 6) currentDate.setDate(currentDate.getDate() + 2); // Samedi
            }
        }

        agenda.endDate = currentDate.toISOString().split('T')[0];
        agenda.totalExercises = totalExercises;

        // Sauvegarder l'agenda
        if (!this.agendas[modelName]) this.agendas[modelName] = {};
        this.agendas[modelName][domain] = agenda;
        this.saveData();

        console.log(`[CURRICULUM-AGENT] 📅 Agenda créé pour ${modelName} - ${domain} (${currentLevel})`);
        console.log(`  → Durée: ${pathConfig.duration} | Exercices: ${totalExercises}`);

        return { success: true, agenda };
    }

    /**
     * Obtient le prochain exercice à faire
     */
    getNextExercise(modelName, domain) {
        const agenda = this.agendas[modelName]?.[domain];
        if (!agenda) {
            // Créer un agenda automatiquement
            const result = this.createLearningAgenda(modelName, domain);
            if (!result.success) return result;
            return this.getNextExercise(modelName, domain);
        }

        const progress = this.getModelProgress(modelName);
        const domainProgress = progress.domains[domain];
        const completedCount = domainProgress.exercisesCompleted;

        // Trouver le prochain exercice
        let exerciseIndex = 0;
        for (const day of agenda.schedule) {
            for (const exercise of day.exercises) {
                if (exerciseIndex === completedCount) {
                    return {
                        success: true,
                        exercise: {
                            ...exercise,
                            domain,
                            level: agenda.level,
                            dayNumber: day.day,
                            date: day.date,
                            progress: `${completedCount + 1}/${agenda.totalExercises}`
                        }
                    };
                }
                exerciseIndex++;
            }
        }

        // Tous les exercices sont complétés
        return {
            success: true,
            completed: true,
            message: `Niveau ${agenda.level} complété! Prêt pour le niveau suivant.`,
            nextLevel: this.getNextLevel(agenda.level)
        };
    }

    /**
     * Marque un exercice comme complété
     */
    completeExercise(modelName, domain, score, fibLevelUp = false) {
        const progress = this.getModelProgress(modelName);
        
        progress.domains[domain].exercisesCompleted++;
        progress.totalExercisesCompleted++;

        // Vérifier si le niveau est complété
        const agenda = this.agendas[modelName]?.[domain];
        if (agenda && progress.domains[domain].exercisesCompleted >= agenda.totalExercises) {
            progress.domains[domain].completedLevels.push({
                level: agenda.level,
                completedAt: new Date().toISOString(),
                averageScore: score
            });

            // Passer au niveau suivant
            const nextLevel = this.getNextLevel(agenda.level);
            if (nextLevel) {
                progress.domains[domain].currentLevel = nextLevel;
                progress.domains[domain].exercisesCompleted = 0;
                
                // Créer le nouvel agenda
                this.createLearningAgenda(modelName, domain);
                
                console.log(`[CURRICULUM-AGENT] 🎉 ${modelName} passe à ${nextLevel} en ${domain}!`);
            } else {
                // Certification PRODIGE
                progress.certifications.push({
                    domain,
                    level: 'PRODIGE',
                    achievedAt: new Date().toISOString()
                });
                console.log(`[CURRICULUM-AGENT] ⭐ ${modelName} atteint le niveau PRODIGE en ${domain}!`);
            }
        }

        this.saveData();
        return progress.domains[domain];
    }

    getNextLevel(currentLevel) {
        const levels = Object.keys(MASTERY_LEVELS);
        const currentIndex = levels.indexOf(currentLevel);
        return levels[currentIndex + 1] || null;
    }

    /**
     * Obtient le curriculum complet d'un domaine
     */
    getDomainCurriculum(domain) {
        const curriculum = CURRICULUM[domain];
        if (!curriculum) return null;

        return {
            ...curriculum,
            levels: Object.entries(curriculum.paths).map(([level, config]) => ({
                level,
                ...MASTERY_LEVELS[level],
                ...config
            }))
        };
    }

    /**
     * Obtient tous les domaines disponibles
     */
    getAllDomains() {
        return Object.entries(CURRICULUM).map(([key, value]) => ({
            id: key,
            name: value.name,
            description: value.description,
            tools: value.tools,
            levelsCount: Object.keys(value.paths).length
        }));
    }

    /**
     * Obtient le statut complet d'un modèle
     */
    getModelStatus(modelName) {
        const progress = this.getModelProgress(modelName);
        
        const domainStatuses = {};
        for (const [domain, domainProgress] of Object.entries(progress.domains)) {
            const levelInfo = MASTERY_LEVELS[domainProgress.currentLevel];
            domainStatuses[domain] = {
                ...domainProgress,
                levelInfo,
                agenda: this.agendas[modelName]?.[domain] || null
            };
        }

        return {
            modelName,
            totalExercisesCompleted: progress.totalExercisesCompleted,
            certifications: progress.certifications,
            domains: domainStatuses,
            createdAt: progress.createdAt
        };
    }
}

module.exports = { CurriculumAgent, CURRICULUM, MASTERY_LEVELS };
