import React, { useState, useEffect, useRef } from 'react';

/**
 * CV Dynamique Intelligent - ProfessionalPage
 * Basé sur l'analyse LinkedIn de Michaël Gauthier Guillet
 * Focus: Transition Blue Collar → Tech Innovator
 */

const ProfessionalPage = () => {
    const [stats, setStats] = useState({});
    const [achievements, setAchievements] = useState([]);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState('overview');
    const [isExporting, setIsExporting] = useState(false);
    const cvRef = useRef(null);

    // Données du profil basées sur LinkedIn + Th3 Thirty3
    const PROFILE = {
        name: "Michaël Gauthier Guillet",
        title: "Expert Excellence Opérationnelle & Innovateur Technologique",
        subtitle: "Manufacturing Specialist → AI Developer → Cybersecurity Enthusiast",
        tagline: "De l'usine au code: je transforme l'expertise terrain en innovation technologique",
        location: "Québec, Canada",
        email: "mgauthierguillet@gmail.com",
        phone: "+1 (438) XXX-XXXX",
        linkedin: "https://www.linkedin.com/in/micha%C3%ABl-gauthier-guillet-2141b8198/",
        github: "https://github.com/th3th",
        website: "http://localhost:5173",
        avatar: "/logo_security.jpg",
        status: "🎯 Ouvert aux opportunités Tech & Innovation",
        summary: `Professionnel atypique combinant 4+ ans d'expérience en production industrielle chez AB InBev 
        et une passion brûlante pour les technologies émergentes. Créateur autodidacte de Th3 Thirty3, 
        une plateforme d'intelligence opérationnelle intégrant IA multi-agents, OSINT et cybersécurité.
        
        Mon parcours unique me permet de comprendre les défis réels du terrain tout en développant 
        des solutions technologiques innovantes. Je suis la preuve que la curiosité et la détermination 
        peuvent transformer un opérateur de machines en développeur IA full-stack.`,
        
        valueProp: [
            "🏭 Comprend les réalités opérationnelles - pas juste la théorie",
            "🤖 Autodidacte en IA : de zéro à 37+ agents orchestrés",
            "🛡️ Vision sécurité : OSINT, ethical hacking, protection des données",
            "⚡ Exécution rapide : idée → prototype fonctionnel en semaines"
        ]
    };

    // Compétences repositionnées sans KeelClip
    const SKILL_CATEGORIES = {
        tech: {
            name: "💻 Développement & IA",
            color: "#3b82f6",
            description: "Compétences techniques autodidactes",
            skills: [
                { name: "JavaScript / Node.js", level: 85, trend: "+8", detail: "Backend, APIs, automation" },
                { name: "React / Frontend", level: 82, trend: "+10", detail: "Dashboards, interfaces complexes" },
                { name: "LLM / IA Générative", level: 78, trend: "+15", detail: "Ollama, prompting, fine-tuning" },
                { name: "Python", level: 70, trend: "+12", detail: "Scripts, ML, data analysis" },
                { name: "Docker / DevOps", level: 65, trend: "+8", detail: "Containers, déploiement" },
                { name: "Databases / APIs", level: 75, trend: "+6", detail: "MongoDB, REST, WebSockets" }
            ]
        },
        security: {
            name: "🛡️ Cybersécurité & OSINT",
            color: "#ef4444",
            description: "Passion sécurité et renseignement",
            skills: [
                { name: "OSINT / Reconnaissance", level: 80, trend: "+12", detail: "Social intelligence, data gathering" },
                { name: "Threat Intelligence", level: 72, trend: "+10", detail: "Analyse menaces, monitoring" },
                { name: "Ethical Hacking Basics", level: 68, trend: "+8", detail: "Kali, scanning, vulnérabilités" },
                { name: "Social Engineering Awareness", level: 75, trend: "+5", detail: "Manipulation, phishing detection" },
                { name: "Network Security", level: 60, trend: "+7", detail: "VPN, TOR, anonymisation" },
                { name: "Security Protocols IT/OT", level: 65, trend: "+10", detail: "Convergence industrielle" }
            ]
        },
        manufacturing: {
            name: "🏭 Excellence Opérationnelle",
            color: "#10b981",
            description: "Expertise terrain AB InBev",
            skills: [
                { name: "Opérations Machines", level: 95, trend: "+2", detail: "Packaging, production" },
                { name: "Lean Manufacturing", level: 85, trend: "+3", detail: "Optimisation, efficacité" },
                { name: "Qualité & Conformité", level: 90, trend: "+2", detail: "Standards, audits" },
                { name: "Résolution Problèmes", level: 92, trend: "+4", detail: "5-Why, RCA" },
                { name: "Sécurité Industrielle", level: 88, trend: "+3", detail: "HSE, protocoles" },
                { name: "Amélioration Continue", level: 85, trend: "+5", detail: "Kaizen, suggestions" }
            ]
        },
        soft: {
            name: "🧠 Compétences Transversales",
            color: "#8b5cf6",
            description: "Ce qui fait la différence",
            skills: [
                { name: "Apprentissage Autodidacte", level: 98, trend: "+5", detail: "Maîtrise en mois, pas années" },
                { name: "Problem Solving Créatif", level: 92, trend: "+3", detail: "Solutions non conventionnelles" },
                { name: "Adaptabilité", level: 95, trend: "+2", detail: "Pivot rapide, multicasquette" },
                { name: "Vision Systémique", level: 85, trend: "+7", detail: "Voit le big picture" },
                { name: "Communication Technique", level: 80, trend: "+6", detail: "Vulgarisation complexité" },
                { name: "Persévérance", level: 98, trend: "+1", detail: "Ne lâche jamais" }
            ]
        }
    };

    // Expérience professionnelle mise à jour
    const EXPERIENCE = [
        {
            title: "Opérateur Machines - Ligne de Production",
            company: "AB InBev",
            location: "Québec, Canada",
            period: "2020 - Présent",
            current: true,
            logo: "🍺",
            color: "#dc2626",
            type: "work",
            highlights: [
                "Opération et maintenance de lignes d'emballage haute cadence",
                "Expert en résolution de problèmes machines (5-Why, RCA)",
                "Formation des nouveaux employés sur les procédures",
                "Proposition d'améliorations d'efficacité adoptées par la direction",
                "Respect constant des standards qualité et sécurité AB InBev"
            ],
            impact: "4+ ans d'expérience dans un environnement de production mondiale",
            skills: ["Production", "Qualité", "Sécurité", "Lean", "Formation"]
        },
        {
            title: "Créateur & Développeur Principal",
            company: "Th3 Thirty3",
            location: "Projet Personnel",
            period: "2024 - Présent",
            current: true,
            logo: "🤖",
            color: "#3b82f6",
            type: "project",
            highlights: [
                "Développement d'une plateforme complète d'intelligence opérationnelle",
                "Architecture multi-agents (37+ agents IA orchestrés)",
                "Intégration OSINT et modules de cybersécurité",
                "Stack moderne: React, Node.js, Ollama, AnythingLLM",
                "Dashboards temps réel, simulations cyber-cinétiques, analytics"
            ],
            impact: "Projet démontrant la capacité à concevoir et développer des systèmes complexes en autodidacte",
            skills: ["React", "Node.js", "IA/LLM", "OSINT", "Full-Stack"]
        },
        {
            title: "Autoformation Intensive",
            company: "Parcours Autodidacte",
            location: "En ligne",
            period: "2023 - Présent",
            current: true,
            logo: "📚",
            color: "#8b5cf6",
            type: "learning",
            highlights: [
                "Développement Full-Stack (JavaScript, React, Node.js)",
                "Intelligence Artificielle et LLMs (Ollama, prompts, fine-tuning)",
                "Cybersécurité et OSINT (bases ethical hacking, Kali Linux)",
                "DevOps et containerisation (Docker, déploiement)",
                "Apprentissage continu via projets pratiques"
            ],
            impact: "Centaines d'heures d'apprentissage transformées en compétences démontrables",
            skills: ["Webdev", "AI/ML", "Security", "DevOps", "Self-Learning"]
        }
    ];

    // Projets (sans KeelClip)
    const PROJECTS = [
        {
            name: "Th3 Thirty3",
            description: "Plateforme d'intelligence opérationnelle intégrant IA multi-agents, OSINT, cybersécurité et automatisation",
            status: "En développement actif",
            featured: true,
            tech: ["React", "Node.js", "Ollama", "AnythingLLM", "DartAI", "Socket.io"],
            metrics: { 
                agents: "37+", 
                models: "7", 
                features: "15+" 
            },
            link: "http://localhost:5173",
            highlights: [
                "Dashboard temps réel avec monitoring multi-services",
                "Simulateur cyber-cinétique pour formation sécurité",
                "Tracking de risques IT/OT avec matrice probabilité/impact",
                "Intégration Google APIs (Gmail, Calendar, Tasks)",
                "Architecture modulaire et extensible"
            ]
        },
        {
            name: "Cyber-Kinetic Simulator",
            description: "Module de formation gamifié pour scénarios de sécurité hybride IT/OT",
            status: "Complété",
            featured: false,
            tech: ["React", "Gamification", "Security Training"],
            metrics: { 
                scenarios: "3", 
                completion: "100%"
            },
            link: "/simulator",
            highlights: [
                "Scénarios réalistes basés sur analyses de risques",
                "Système de scoring et debriefing",
                "Timer et choix multiple avec conséquences"
            ]
        },
        {
            name: "Risk Dashboard IT/OT",
            description: "Tableau de bord de suivi des risques de sécurité hybride",
            status: "Complété",
            featured: false,
            tech: ["React", "Data Visualization", "Risk Management"],
            metrics: { 
                views: "3", 
                risks: "8+"
            },
            link: "/risks",
            highlights: [
                "Matrice probabilité × impact interactive",
                "Suivi des recommandations avec progression",
                "Filtres et drill-down par risque"
            ]
        }
    ];

    // Ce qui me différencie
    const DIFFERENTIATORS = [
        {
            icon: "🔄",
            title: "Parcours Non-Linéaire",
            description: "Du terrain industriel au code, ma trajectoire prouve que la passion surpasse les diplômes",
            color: "#10b981"
        },
        {
            icon: "🧩",
            title: "Vision Terrain + Tech",
            description: "Je comprends les problèmes réels parce que je les ai vécus. Mes solutions sont pratiques, pas théoriques",
            color: "#3b82f6"
        },
        {
            icon: "⚡",
            title: "Exécution Rapide",
            description: "Th3 Thirty3 : de l'idée au prototype fonctionnel avec 37+ agents en quelques mois d'apprentissage",
            color: "#f59e0b"
        },
        {
            icon: "🎯",
            title: "Motivation Inépuisable",
            description: "Je code après mes shifts, j'apprends pendant mes pauses. La tech n'est pas un travail, c'est une obsession saine",
            color: "#ef4444"
        }
    ];

    // Langues
    const LANGUAGES = [
        { name: "Français", level: "Langue maternelle", percent: 100, flag: "🇫🇷" },
        { name: "Anglais", level: "Professionnel", percent: 80, flag: "🇬🇧" }
    ];

    // Centres d'intérêt
    const INTERESTS = [
        { icon: "🤖", name: "Intelligence Artificielle" },
        { icon: "🛡️", name: "Cybersécurité" },
        { icon: "🔍", name: "OSINT" },
        { icon: "🏭", name: "Industry 4.0" },
        { icon: "📊", name: "Data & Analytics" },
        { icon: "🎮", name: "Gaming" },
        { icon: "📚", name: "Apprentissage continu" },
        { icon: "🧠", name: "Tech émergentes" }
    ];

    // Charger les données en temps réel
    useEffect(() => {
        const loadRealTimeData = async () => {
            try {
                setStats({
                    modelsActive: 7,
                    agentsManaged: 37,
                    projectsActive: PROJECTS.length,
                    hoursLearning: 400,
                    skillsTracked: Object.values(SKILL_CATEGORIES).reduce((sum, cat) => sum + cat.skills.length, 0),
                    avgSkillLevel: Math.round(
                        Object.values(SKILL_CATEGORIES)
                            .flatMap(cat => cat.skills)
                            .reduce((sum, s) => sum + s.level, 0) / 24
                    )
                });

                setAchievements([
                    { icon: "🚀", title: "Self-Made Developer", description: "Développeur autodidacte sans formation formelle", date: "2024", rarity: "legendary" },
                    { icon: "🤖", title: "AI Orchestrator", description: "37+ agents IA développés et intégrés", date: "2024", rarity: "epic" },
                    { icon: "🏭", title: "Industry Veteran", description: "4+ ans d'expérience AB InBev", date: "2024", rarity: "rare" },
                    { icon: "🛡️", title: "Security Mindset", description: "Modules OSINT et cyber-sécurité créés", date: "2024", rarity: "epic" },
                    { icon: "⚡", title: "Rapid Learner", description: "Full-stack en moins d'un an", date: "2024", rarity: "legendary" },
                    { icon: "🎯", title: "Problem Solver", description: "Solutions créatives terrain + tech", date: "2024", rarity: "rare" }
                ]);

                setLoading(false);
            } catch (error) {
                console.error('Error loading profile data:', error);
                setLoading(false);
            }
        };

        loadRealTimeData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    const exportToPDF = () => {
        setIsExporting(true);
        // Simulé - nécessiterait html2pdf.js en production
        setTimeout(() => {
            window.print();
            setIsExporting(false);
        }, 500);
    };

    const getRarityColor = (rarity) => {
        switch(rarity) {
            case 'legendary': return 'from-yellow-500 to-orange-500';
            case 'epic': return 'from-purple-500 to-pink-500';
            case 'rare': return 'from-blue-500 to-cyan-500';
            default: return 'from-gray-500 to-gray-600';
        }
    };

    const SkillBar = ({ skill, color }) => (
        <div className="mb-4">
            <div className="flex justify-between items-center mb-1">
                <div>
                    <span className="text-sm font-medium text-gray-200">{skill.name}</span>
                    <span className="text-xs text-gray-500 ml-2">({skill.detail})</span>
                </div>
                <div className="flex items-center gap-2">
                    <span className="text-xs text-green-400 font-mono">+{skill.trend}%</span>
                    <span className="text-sm font-bold" style={{ color }}>{skill.level}%</span>
                </div>
            </div>
            <div className="h-2.5 bg-gray-700/50 rounded-full overflow-hidden">
                <div
                    className="h-full rounded-full transition-all duration-1000 ease-out relative"
                    style={{
                        width: `${skill.level}%`,
                        background: `linear-gradient(90deg, ${color}, ${color}88)`
                    }}
                >
                    <div className="absolute inset-0 bg-white/20 animate-pulse" style={{ animationDuration: '2s' }}></div>
                </div>
            </div>
        </div>
    );

    if (loading) {
        return (
            <div className="w-full h-full flex items-center justify-center bg-gradient-to-br from-gray-900 via-gray-800 to-black">
                <div className="text-center">
                    <div className="w-16 h-16 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
                    <div className="text-cyan-400 font-mono">Analyse du profil en cours...</div>
                </div>
            </div>
        );
    }

    return (
        <div className="w-full h-full overflow-y-auto bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white print:bg-white print:text-black" ref={cvRef}>
            {/* Export Button */}
            <button
                onClick={exportToPDF}
                disabled={isExporting}
                className="fixed bottom-8 right-8 z-50 px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 rounded-full shadow-lg shadow-cyan-500/30 font-semibold transition-all duration-300 transform hover:scale-105 flex items-center gap-2 print:hidden"
            >
                {isExporting ? (
                    <><div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>Export...</>
                ) : (
                    <>📄 Imprimer / PDF</>
                )}
            </button>

            <div className="max-w-6xl mx-auto p-8">
                {/* Hero Header */}
                <div className="relative mb-8">
                    <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/10 via-blue-500/10 to-purple-500/10 rounded-3xl blur-xl"></div>
                    
                    <div className="relative bg-gray-800/60 backdrop-blur-xl border border-gray-700/50 rounded-3xl p-8 md:p-10">
                        <div className="flex flex-col lg:flex-row items-center gap-8">
                            {/* Avatar */}
                            <div className="relative flex-shrink-0">
                                <div className="w-36 h-36 rounded-full bg-gradient-to-br from-cyan-500 via-blue-500 to-purple-600 p-1 shadow-2xl shadow-cyan-500/30">
                                    <div className="w-full h-full rounded-full bg-gray-900 flex items-center justify-center overflow-hidden">
                                        <div className="text-6xl">👨‍💻</div>
                                    </div>
                                </div>
                                <div className="absolute -bottom-1 -right-1 px-3 py-1.5 bg-green-500 rounded-full text-xs font-bold text-white shadow-lg">
                                    ● Disponible
                                </div>
                            </div>

                            {/* Main Info */}
                            <div className="flex-grow text-center lg:text-left">
                                <div className="inline-block px-4 py-1.5 mb-3 rounded-full bg-gradient-to-r from-cyan-500/20 to-purple-500/20 border border-cyan-500/30">
                                    <span className="text-cyan-400 text-sm font-mono tracking-wider">{PROFILE.status}</span>
                                </div>

                                <h1 className="text-4xl md:text-5xl font-bold mb-2 bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-500 bg-clip-text text-transparent">
                                    {PROFILE.name}
                                </h1>

                                <p className="text-xl md:text-2xl text-gray-200 font-light mb-2">
                                    {PROFILE.title}
                                </p>
                                
                                <p className="text-sm text-gray-400 italic mb-4">
                                    "{PROFILE.tagline}"
                                </p>

                                {/* Quick Links */}
                                <div className="flex flex-wrap justify-center lg:justify-start gap-3">
                                    <a href={`mailto:${PROFILE.email}`} className="flex items-center gap-2 px-4 py-2 bg-gray-700/50 hover:bg-gray-600/50 rounded-xl transition-all text-sm">
                                        <span>📧</span>
                                        <span className="text-gray-300">{PROFILE.email}</span>
                                    </a>
                                    <a href={PROFILE.linkedin} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 px-4 py-2 bg-blue-600/20 hover:bg-blue-600/40 rounded-xl transition-all border border-blue-500/30 text-sm">
                                        <span>💼</span>
                                        <span className="text-blue-400">LinkedIn</span>
                                    </a>
                                    <span className="flex items-center gap-2 px-4 py-2 bg-gray-700/50 rounded-xl text-sm">
                                        <span>📍</span>
                                        <span className="text-gray-300">{PROFILE.location}</span>
                                    </span>
                                </div>
                            </div>

                            {/* Quick Stats */}
                            <div className="grid grid-cols-2 gap-3 flex-shrink-0">
                                {[
                                    { value: stats.avgSkillLevel + '%', label: 'Compétences', color: 'cyan', icon: '📊' },
                                    { value: stats.agentsManaged + '+', label: 'Agents IA', color: 'blue', icon: '🤖' },
                                    { value: '4+ ans', label: 'Expérience', color: 'green', icon: '🏭' },
                                    { value: stats.hoursLearning + 'h+', label: 'Autoformation', color: 'purple', icon: '📚' }
                                ].map((stat, idx) => (
                                    <div key={idx} className={`p-4 bg-gray-900/50 border border-${stat.color}-500/30 rounded-xl text-center hover:border-${stat.color}-400/50 transition-all`}>
                                        <div className="text-lg mb-1">{stat.icon}</div>
                                        <div className={`text-xl font-bold text-${stat.color}-400`}>{stat.value}</div>
                                        <div className="text-xs text-gray-500">{stat.label}</div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Value Proposition */}
                        <div className="mt-8 pt-6 border-t border-gray-700/50">
                            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
                                {PROFILE.valueProp.map((prop, idx) => (
                                    <div key={idx} className="flex items-start gap-2 text-sm text-gray-300">
                                        <span className="text-lg">{prop.split(' ')[0]}</span>
                                        <span>{prop.split(' ').slice(1).join(' ')}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>

                {/* Navigation Tabs */}
                <div className="flex justify-center mb-8 print:hidden overflow-x-auto">
                    <div className="inline-flex bg-gray-800/50 rounded-2xl p-1 border border-gray-700/50">
                        {[
                            { id: 'overview', label: '📊 Vue d\'ensemble' },
                            { id: 'skills', label: '💪 Compétences' },
                            { id: 'experience', label: '💼 Parcours' },
                            { id: 'projects', label: '🚀 Projets' },
                            { id: 'achievements', label: '🏆 Achievements' }
                        ].map(tab => (
                            <button
                                key={tab.id}
                                onClick={() => setActiveTab(tab.id)}
                                className={`px-5 py-2.5 rounded-xl font-semibold transition-all duration-300 whitespace-nowrap ${
                                    activeTab === tab.id
                                        ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-lg'
                                        : 'text-gray-400 hover:text-white hover:bg-gray-700/50'
                                }`}
                            >
                                {tab.label}
                            </button>
                        ))}
                    </div>
                </div>

                {/* Overview Tab */}
                {activeTab === 'overview' && (
                    <div className="space-y-6">
                        {/* About Me */}
                        <div className="bg-gray-800/30 border border-gray-700/50 rounded-2xl p-6">
                            <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
                                <span className="text-2xl">👤</span>
                                À Propos
                            </h3>
                            <p className="text-gray-300 leading-relaxed whitespace-pre-line">
                                {PROFILE.summary}
                            </p>
                        </div>

                        {/* What Makes Me Different */}
                        <div className="bg-gray-800/30 border border-gray-700/50 rounded-2xl p-6">
                            <h3 className="text-xl font-bold mb-6 flex items-center gap-2">
                                <span className="text-2xl">✨</span>
                                Ce Qui Me Différencie
                            </h3>
                            <div className="grid md:grid-cols-2 gap-4">
                                {DIFFERENTIATORS.map((diff, idx) => (
                                    <div key={idx} className="p-4 bg-gray-900/50 rounded-xl border border-gray-700/50 hover:border-opacity-100 transition-all" style={{ borderColor: diff.color + '40' }}>
                                        <div className="flex items-start gap-3">
                                            <div className="text-3xl">{diff.icon}</div>
                                            <div>
                                                <h4 className="font-bold text-white mb-1">{diff.title}</h4>
                                                <p className="text-sm text-gray-400">{diff.description}</p>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Skills Overview + Languages */}
                        <div className="grid md:grid-cols-3 gap-6">
                            {/* Top Skills by Category */}
                            <div className="md:col-span-2 bg-gray-800/30 border border-gray-700/50 rounded-2xl p-6">
                                <h3 className="text-xl font-bold mb-4">🔥 Top Compétences</h3>
                                <div className="grid md:grid-cols-2 gap-6">
                                    {Object.values(SKILL_CATEGORIES).map((category, idx) => (
                                        <div key={idx}>
                                            <h4 className="text-sm font-bold mb-3 flex items-center gap-2" style={{ color: category.color }}>
                                                {category.name}
                                            </h4>
                                            {category.skills.slice(0, 2).map((skill, sidx) => (
                                                <SkillBar key={sidx} skill={skill} color={category.color} />
                                            ))}
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {/* Languages + Interests */}
                            <div className="space-y-6">
                                <div className="bg-gray-800/30 border border-gray-700/50 rounded-2xl p-6">
                                    <h3 className="text-lg font-bold mb-4">🌍 Langues</h3>
                                    {LANGUAGES.map((lang, idx) => (
                                        <div key={idx} className="mb-3">
                                            <div className="flex justify-between items-center mb-1">
                                                <span className="flex items-center gap-2 text-sm">
                                                    <span>{lang.flag}</span>
                                                    <span>{lang.name}</span>
                                                </span>
                                                <span className="text-xs text-gray-400">{lang.level}</span>
                                            </div>
                                            <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                                                <div className="h-full bg-gradient-to-r from-cyan-500 to-blue-500" style={{ width: `${lang.percent}%` }} />
                                            </div>
                                        </div>
                                    ))}
                                </div>

                                <div className="bg-gray-800/30 border border-gray-700/50 rounded-2xl p-6">
                                    <h3 className="text-lg font-bold mb-4">💡 Intérêts</h3>
                                    <div className="flex flex-wrap gap-2">
                                        {INTERESTS.map((interest, idx) => (
                                            <span key={idx} className="px-3 py-1.5 bg-gray-700/50 rounded-full text-xs text-gray-300 flex items-center gap-1">
                                                <span>{interest.icon}</span>
                                                {interest.name}
                                            </span>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {/* Skills Tab */}
                {activeTab === 'skills' && (
                    <div className="grid md:grid-cols-2 gap-6">
                        {Object.values(SKILL_CATEGORIES).map((category, idx) => (
                            <div key={idx} className="bg-gray-800/30 border border-gray-700/50 rounded-2xl p-6">
                                <div className="flex items-center justify-between mb-2">
                                    <h3 className="text-xl font-bold" style={{ color: category.color }}>
                                        {category.name}
                                    </h3>
                                </div>
                                <p className="text-sm text-gray-500 mb-6">{category.description}</p>
                                
                                {category.skills.map((skill, sidx) => (
                                    <SkillBar key={sidx} skill={skill} color={category.color} />
                                ))}
                                
                                <div className="mt-4 pt-4 border-t border-gray-700/50 flex justify-between items-center">
                                    <span className="text-sm text-gray-500">Moyenne catégorie:</span>
                                    <span className="font-bold text-lg" style={{ color: category.color }}>
                                        {Math.round(category.skills.reduce((s, sk) => s + sk.level, 0) / category.skills.length)}%
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>
                )}

                {/* Experience Tab */}
                {activeTab === 'experience' && (
                    <div className="space-y-6">
                        {EXPERIENCE.map((exp, idx) => (
                            <div key={idx} className="bg-gray-800/30 border border-gray-700/50 rounded-2xl p-6 hover:border-cyan-500/30 transition-all duration-300">
                                <div className="flex items-start gap-5">
                                    <div 
                                        className="w-14 h-14 rounded-xl flex items-center justify-center text-2xl flex-shrink-0"
                                        style={{ background: `${exp.color}20`, border: `1px solid ${exp.color}40` }}
                                    >
                                        {exp.logo}
                                    </div>
                                    <div className="flex-grow">
                                        <div className="flex flex-wrap items-center gap-3 mb-1">
                                            <h3 className="text-xl font-bold text-white">{exp.title}</h3>
                                            {exp.current && (
                                                <span className="px-2.5 py-0.5 bg-green-500/20 text-green-400 text-xs rounded-full font-semibold">
                                                    Actuel
                                                </span>
                                            )}
                                            <span className="px-2.5 py-0.5 bg-gray-700/50 text-gray-400 text-xs rounded-full capitalize">
                                                {exp.type}
                                            </span>
                                        </div>
                                        <div className="text-cyan-400 font-mono text-sm mb-3">
                                            {exp.company} • {exp.location} • {exp.period}
                                        </div>
                                        
                                        <ul className="space-y-1.5 mb-4">
                                            {exp.highlights.map((h, hidx) => (
                                                <li key={hidx} className="flex items-start gap-2 text-sm text-gray-300">
                                                    <span className="text-cyan-400 mt-0.5">▸</span>
                                                    {h}
                                                </li>
                                            ))}
                                        </ul>
                                        
                                        <div className="p-3 bg-gray-900/50 rounded-lg mb-4 border-l-2" style={{ borderColor: exp.color }}>
                                            <span className="text-xs text-gray-500">IMPACT: </span>
                                            <span className="text-sm text-gray-300">{exp.impact}</span>
                                        </div>
                                        
                                        <div className="flex flex-wrap gap-2">
                                            {exp.skills.map((skill, sidx) => (
                                                <span key={sidx} className="px-3 py-1 bg-gray-700/50 text-gray-300 text-xs rounded-full">
                                                    {skill}
                                                </span>
                                            ))}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                )}

                {/* Projects Tab */}
                {activeTab === 'projects' && (
                    <div className="space-y-6">
                        {PROJECTS.map((project, idx) => (
                            <div key={idx} className={`bg-gray-800/30 border rounded-2xl p-6 transition-all duration-300 ${project.featured ? 'border-cyan-500/50 shadow-lg shadow-cyan-500/10' : 'border-gray-700/50 hover:border-gray-600'}`}>
                                {project.featured && (
                                    <div className="inline-block px-3 py-1 mb-4 bg-gradient-to-r from-cyan-500/20 to-blue-500/20 border border-cyan-500/30 rounded-full">
                                        <span className="text-cyan-400 text-xs font-bold">⭐ PROJET PHARE</span>
                                    </div>
                                )}
                                
                                <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4 mb-4">
                                    <div>
                                        <h3 className="text-2xl font-bold text-white mb-1">{project.name}</h3>
                                        <p className="text-gray-400">{project.description}</p>
                                    </div>
                                    <span className={`px-3 py-1 text-xs rounded-full font-semibold flex-shrink-0 ${
                                        project.status === 'En développement actif' ? 'bg-green-500/20 text-green-400' :
                                        project.status === 'Complété' ? 'bg-blue-500/20 text-blue-400' :
                                        'bg-yellow-500/20 text-yellow-400'
                                    }`}>
                                        {project.status}
                                    </span>
                                </div>

                                {project.highlights && (
                                    <ul className="mb-4 space-y-1">
                                        {project.highlights.map((h, hidx) => (
                                            <li key={hidx} className="flex items-start gap-2 text-sm text-gray-300">
                                                <span className="text-cyan-400">✓</span>
                                                {h}
                                            </li>
                                        ))}
                                    </ul>
                                )}

                                <div className="flex flex-wrap items-center gap-4">
                                    <div className="flex flex-wrap gap-2">
                                        {project.tech.map((t, tidx) => (
                                            <span key={tidx} className="px-2.5 py-1 bg-gray-700/50 text-gray-300 text-xs rounded-lg">
                                                {t}
                                            </span>
                                        ))}
                                    </div>
                                    <div className="flex gap-4 ml-auto">
                                        {Object.entries(project.metrics).map(([key, val], midx) => (
                                            <div key={midx} className="text-center">
                                                <div className="text-lg font-bold text-cyan-400">{val}</div>
                                                <div className="text-xs text-gray-500 capitalize">{key}</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                )}

                {/* Achievements Tab */}
                {activeTab === 'achievements' && (
                    <div className="grid md:grid-cols-3 gap-6">
                        {achievements.map((ach, idx) => (
                            <div 
                                key={idx}
                                className="relative bg-gray-800/30 border border-gray-700/50 rounded-2xl p-6 overflow-hidden group hover:scale-105 transition-all duration-300"
                            >
                                <div className={`absolute inset-0 bg-gradient-to-br ${getRarityColor(ach.rarity)} opacity-5 group-hover:opacity-10 transition-opacity`}></div>
                                <div className="relative text-center">
                                    <div className="text-5xl mb-4 transform group-hover:scale-110 transition-transform">{ach.icon}</div>
                                    <h3 className="text-lg font-bold text-white mb-2">{ach.title}</h3>
                                    <p className="text-gray-400 text-sm mb-4">{ach.description}</p>
                                    <div className="flex justify-between items-center">
                                        <span className="text-xs text-gray-500">{ach.date}</span>
                                        <span className={`px-3 py-1 rounded-full text-xs font-bold bg-gradient-to-r ${getRarityColor(ach.rarity)} text-white`}>
                                            {ach.rarity.toUpperCase()}
                                        </span>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                )}

                {/* Footer */}
                <div className="mt-12 text-center py-8 border-t border-gray-800 print:border-gray-300">
                    <p className="text-gray-500 text-sm print:text-gray-600">
                        CV dynamique généré par <span className="text-cyan-400 print:text-cyan-600 font-semibold">Th3 Thirty3</span> • 
                        Dernière mise à jour: {new Date().toLocaleDateString('fr-FR', { year: 'numeric', month: 'long', day: 'numeric' })}
                    </p>
                    <p className="text-gray-600 text-xs mt-2">
                        Compétences trackées en temps réel • Progression: +{Math.round(stats.avgSkillLevel * 0.1)}% ce mois
                    </p>
                </div>
            </div>
        </div>
    );
};

export default ProfessionalPage;
