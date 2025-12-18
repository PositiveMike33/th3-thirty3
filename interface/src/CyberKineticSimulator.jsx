import React, { useState, useEffect } from 'react';

/**
 * Module de Simulation Cyber-Cinétique
 * Permet de simuler des scénarios où les menaces numériques impactent la réalité physique
 */

const SCENARIOS = [
    {
        id: 'scenario-1',
        name: 'Attaque PLC - Ligne de Production',
        category: 'industrial',
        description: 'Un attaquant a compromis le contrôleur PLC de la ligne de production principale. Les capteurs affichent des valeurs normales mais les ouvriers signalent des vibrations anormales.',
        difficulty: 'hard',
        timeLimit: 300, // 5 minutes
        steps: [
            {
                id: 1,
                situation: "Les moniteurs SCADA affichent une production normale à 100%. Cependant, l'opérateur de la machine #3 vous contacte: 'Les vibrations sont bizarres, ça ne ressemble pas à d'habitude.'",
                options: [
                    { text: "Ignorer - les capteurs montrent tout normal", points: -10, consequence: "Les capteurs sont compromis. La machine continue à se dégrader." },
                    { text: "Vérifier physiquement la machine", points: 15, consequence: "Vous découvrez que les roulements surchauffent malgré les températures 'normales' affichées." },
                    { text: "Arrêter la ligne par précaution", points: 10, consequence: "Décision prudente. Vous évitez des dommages mais perdez du temps de production." },
                    { text: "Contacter l'équipe IT pour vérifier les capteurs", points: 5, consequence: "Bonne initiative mais prend du temps. L'IT met 20 minutes à répondre." }
                ]
            },
            {
                id: 2,
                situation: "L'équipe IT confirme une intrusion dans le réseau OT. Les valeurs des capteurs ont été falsifiées. Que faites-vous?",
                options: [
                    { text: "Isoler immédiatement le réseau OT d'Internet", points: 20, consequence: "Excellente décision. L'attaquant perd l'accès." },
                    { text: "Attendre les instructions de la direction", points: -5, consequence: "Pendant l'attente, l'attaquant continue ses manipulations." },
                    { text: "Basculer sur les contrôles manuels", points: 15, consequence: "Bonne décision. Les opérateurs reprennent le contrôle direct." },
                    { text: "Éteindre tous les systèmes", points: 5, consequence: "Radical mais efficace. Cependant, risque de perte de données." }
                ]
            },
            {
                id: 3,
                situation: "Le réseau est isolé mais vous découvrez que l'attaquant a programmé une commande différée qui va surcharger le four industriel dans 10 minutes.",
                options: [
                    { text: "Couper l'alimentation électrique du four", points: 20, consequence: "Action décisive. Le four s'arrête en sécurité." },
                    { text: "Tenter de supprimer la commande malveillante", points: -10, consequence: "Trop risqué sans certitude. La commande s'exécute partiellement." },
                    { text: "Évacuer la zone et couper le gaz", points: 25, consequence: "Sécurité maximale. Vous protégez le personnel ET l'équipement." },
                    { text: "Appeler le fournisseur du système", points: -15, consequence: "Pas le temps. Le fournisseur ne peut pas répondre en 10 minutes." }
                ]
            }
        ],
        debriefing: {
            keyLessons: [
                "L'observation humaine est cruciale quand les capteurs sont compromis",
                "L'isolation réseau doit être possible en moins de 5 minutes",
                "Les contrôles manuels doivent toujours être disponibles",
                "La sécurité des personnes prime sur la continuité de production"
            ],
            bestPractices: [
                "Former les opérateurs à faire confiance à leurs sens",
                "Avoir des kill-switch physiques accessibles",
                "Maintenir des canaux de communication hors-bande",
                "Établir une autorité décisionnelle claire pour les urgences"
            ]
        }
    },
    {
        id: 'scenario-2',
        name: 'Ingénierie Sociale - Maintenance',
        category: 'social',
        description: "Un individu se présentant comme technicien de maintenance du fournisseur demande un accès urgent au datacenter pour une 'mise à jour critique de sécurité'.",
        difficulty: 'medium',
        timeLimit: 180,
        steps: [
            {
                id: 1,
                situation: "Un homme en uniforme de maintenance se présente à l'accueil avec un ordre de travail urgent. Il dit que votre système de contrôle a une faille critique qui doit être patchée immédiatement.",
                options: [
                    { text: "Le laisser passer - c'est urgent et il a l'air professionnel", points: -25, consequence: "Il installe un backdoor dans votre système de contrôle." },
                    { text: "Vérifier son identité auprès du fournisseur", points: 20, consequence: "Le fournisseur confirme qu'ils n'ont envoyé personne aujourd'hui." },
                    { text: "Demander à voir son badge et l'ordre de travail", points: 10, consequence: "Les documents semblent authentiques mais vous remarquez des incohérences." },
                    { text: "Lui demander d'attendre et appeler votre responsable", points: 15, consequence: "Bon réflexe. Votre responsable peut valider la procédure." }
                ]
            },
            {
                id: 2,
                situation: "L'individu devient pressant: 'Chaque minute qui passe augmente le risque. Si vous ne me laissez pas entrer, je documenterai votre refus et vous serez responsable.'",
                options: [
                    { text: "Céder à la pression - il a raison, c'est urgent", points: -20, consequence: "La pression émotionnelle a fonctionné. Vous avez été manipulé." },
                    { text: "Maintenir votre position fermement", points: 25, consequence: "Excellente résistance à la manipulation. L'individu abandonne." },
                    { text: "Proposer de l'accompagner pendant l'intervention", points: 5, consequence: "Compromis raisonnable mais qui lui donne quand même accès." },
                    { text: "Appeler la sécurité", points: 20, consequence: "Bonne décision. La sécurité peut gérer la situation." }
                ]
            }
        ],
        debriefing: {
            keyLessons: [
                "L'urgence artificielle est une technique de manipulation classique",
                "Les attaquants exploitent la peur de la responsabilité",
                "Toujours vérifier l'identité par un canal indépendant",
                "Un professionnel légitime comprendra vos vérifications"
            ],
            bestPractices: [
                "Avoir une liste des maintenanciers autorisés",
                "Procédure de vérification en moins de 5 minutes",
                "Former tout le personnel à résister à la pression",
                "Documenter toutes les tentatives d'accès suspectes"
            ]
        }
    },
    {
        id: 'scenario-3',
        name: 'Données Contradictoires - Décision Critique',
        category: 'decision',
        description: "Le système d'alerte incendie se déclenche mais les capteurs de fumée ne détectent rien. Les caméras montrent une zone normale. Un opérateur signale une odeur de brûlé.",
        difficulty: 'expert',
        timeLimit: 120,
        steps: [
            {
                id: 1,
                situation: "Alarme incendie déclenchée dans la zone de stockage. Capteurs fumée: 0%. Caméras: RAS. Mais l'opérateur au téléphone insiste: 'Je vous dis que ça sent le brûlé!'",
                options: [
                    { text: "Ignorer l'opérateur - tous les capteurs sont normaux", points: -30, consequence: "Un feu couve dans un angle mort des capteurs. Il se propage." },
                    { text: "Évacuer la zone immédiatement", points: 20, consequence: "Décision de sécurité. L'enquête révèle un court-circuit dans le faux plafond." },
                    { text: "Envoyer quelqu'un vérifier sur place", points: 15, consequence: "Bon compromis. La personne confirme une odeur et localise le problème." },
                    { text: "Désactiver l'alarme - c'est probablement un faux positif", points: -25, consequence: "Désactiver l'alarme pendant un vrai incendie est catastrophique." }
                ]
            },
            {
                id: 2,
                situation: "Vous décidez d'évacuer. Mais le responsable de production vous appelle: 'On a une commande critique. Chaque heure d'arrêt coûte 50 000€.'",
                options: [
                    { text: "Annuler l'évacuation pour préserver la production", points: -20, consequence: "Mettre la production avant la sécurité est inacceptable." },
                    { text: "Maintenir l'évacuation, la sécurité prime", points: 25, consequence: "Décision correcte. La vie humaine n'a pas de prix." },
                    { text: "Proposer une évacuation partielle", points: 5, consequence: "Compromis risqué mais qui montre une tentative d'équilibre." },
                    { text: "Demander l'autorisation du directeur", points: -10, consequence: "Perdre du temps en chaîne hiérarchique pendant une urgence." }
                ]
            }
        ],
        debriefing: {
            keyLessons: [
                "Les sens humains détectent ce que les capteurs peuvent manquer",
                "La pression économique ne doit jamais compromettre la sécurité",
                "En cas de doute, toujours choisir l'option la plus sûre",
                "L'autorité décisionnelle doit être claire AVANT la crise"
            ],
            bestPractices: [
                "Établir que l'opérateur terrain a autorité pour évacuer",
                "Former les managers à prioriser la sécurité",
                "Avoir des capteurs redondants dans les zones critiques",
                "Documenter les décisions et leurs justifications"
            ]
        }
    }
];

const CyberKineticSimulator = () => {
    const [activeScenario, setActiveScenario] = useState(null);
    const [currentStep, setCurrentStep] = useState(0);
    const [score, setScore] = useState(0);
    const [history, setHistory] = useState([]);
    const [timeRemaining, setTimeRemaining] = useState(0);
    const [isRunning, setIsRunning] = useState(false);
    const [showDebriefing, setShowDebriefing] = useState(false);
    const [completedScenarios, setCompletedScenarios] = useState([]);

    // Timer
    useEffect(() => {
        let timer;
        if (isRunning && timeRemaining > 0) {
            timer = setInterval(() => {
                setTimeRemaining(t => {
                    if (t <= 1) {
                        setIsRunning(false);
                        setShowDebriefing(true);
                        return 0;
                    }
                    return t - 1;
                });
            }, 1000);
        }
        return () => clearInterval(timer);
    }, [isRunning, timeRemaining]);

    const startScenario = (scenario) => {
        setActiveScenario(scenario);
        setCurrentStep(0);
        setScore(0);
        setHistory([]);
        setTimeRemaining(scenario.timeLimit);
        setIsRunning(true);
        setShowDebriefing(false);
    };

    const handleChoice = (option, stepIndex) => {
        setScore(s => s + option.points);
        setHistory(h => [...h, { step: stepIndex, choice: option.text, points: option.points, consequence: option.consequence }]);
        
        if (currentStep < activeScenario.steps.length - 1) {
            setCurrentStep(s => s + 1);
        } else {
            setIsRunning(false);
            setShowDebriefing(true);
            setCompletedScenarios(cs => [...cs, { id: activeScenario.id, score, time: activeScenario.timeLimit - timeRemaining }]);
        }
    };

    const resetSimulator = () => {
        setActiveScenario(null);
        setCurrentStep(0);
        setScore(0);
        setHistory([]);
        setShowDebriefing(false);
    };

    const formatTime = (seconds) => {
        const m = Math.floor(seconds / 60);
        const s = seconds % 60;
        return `${m}:${s.toString().padStart(2, '0')}`;
    };

    const getScoreGrade = (score, maxScore) => {
        const percent = (score / maxScore) * 100;
        if (percent >= 80) return { grade: 'A', color: '#10b981', label: 'Excellent' };
        if (percent >= 60) return { grade: 'B', color: '#3b82f6', label: 'Bon' };
        if (percent >= 40) return { grade: 'C', color: '#f59e0b', label: 'Acceptable' };
        return { grade: 'D', color: '#ef4444', label: 'À améliorer' };
    };

    return (
        <div style={{
            minHeight: '100vh',
            background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
            color: '#e2e8f0',
            padding: '2rem'
        }}>
            {/* Header */}
            <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '2rem',
                padding: '1.5rem',
                background: 'rgba(30, 41, 59, 0.8)',
                borderRadius: '16px',
                border: '1px solid rgba(99, 102, 241, 0.3)'
            }}>
                <div>
                    <h1 style={{
                        fontSize: '2rem',
                        fontWeight: 'bold',
                        background: 'linear-gradient(90deg, #818cf8, #c084fc)',
                        WebkitBackgroundClip: 'text',
                        WebkitTextFillColor: 'transparent',
                        marginBottom: '0.5rem'
                    }}>
                        🎮 Simulateur Cyber-Cinétique
                    </h1>
                    <p style={{ color: '#94a3b8' }}>
                        Entraînement aux scénarios où les menaces numériques impactent la réalité physique
                    </p>
                </div>
                {activeScenario && (
                    <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '2rem'
                    }}>
                        <div style={{
                            textAlign: 'center',
                            padding: '1rem',
                            background: timeRemaining < 60 ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                            borderRadius: '12px'
                        }}>
                            <div style={{ fontSize: '0.8rem', color: '#94a3b8' }}>Temps restant</div>
                            <div style={{
                                fontSize: '2rem',
                                fontWeight: 'bold',
                                color: timeRemaining < 60 ? '#ef4444' : '#10b981'
                            }}>
                                {formatTime(timeRemaining)}
                            </div>
                        </div>
                        <div style={{
                            textAlign: 'center',
                            padding: '1rem',
                            background: score >= 0 ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                            borderRadius: '12px'
                        }}>
                            <div style={{ fontSize: '0.8rem', color: '#94a3b8' }}>Score</div>
                            <div style={{
                                fontSize: '2rem',
                                fontWeight: 'bold',
                                color: score >= 0 ? '#10b981' : '#ef4444'
                            }}>
                                {score > 0 ? '+' : ''}{score}
                            </div>
                        </div>
                    </div>
                )}
            </div>

            {/* Scenario Selection */}
            {!activeScenario && (
                <div>
                    <h2 style={{ fontSize: '1.5rem', marginBottom: '1.5rem', color: '#f8fafc' }}>
                        📋 Sélectionnez un scénario
                    </h2>
                    <div style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))',
                        gap: '1.5rem'
                    }}>
                        {SCENARIOS.map(scenario => {
                            const completed = completedScenarios.find(c => c.id === scenario.id);
                            const difficultyColors = {
                                easy: '#10b981',
                                medium: '#f59e0b',
                                hard: '#ef4444',
                                expert: '#8b5cf6'
                            };
                            
                            return (
                                <div
                                    key={scenario.id}
                                    onClick={() => startScenario(scenario)}
                                    style={{
                                        padding: '1.5rem',
                                        background: 'rgba(30, 41, 59, 0.8)',
                                        borderRadius: '16px',
                                        border: completed ? '2px solid #10b981' : '1px solid rgba(99, 102, 241, 0.3)',
                                        cursor: 'pointer',
                                        transition: 'all 0.3s ease',
                                        transform: 'translateY(0)'
                                    }}
                                    onMouseEnter={e => {
                                        e.currentTarget.style.transform = 'translateY(-4px)';
                                        e.currentTarget.style.borderColor = '#818cf8';
                                    }}
                                    onMouseLeave={e => {
                                        e.currentTarget.style.transform = 'translateY(0)';
                                        e.currentTarget.style.borderColor = completed ? '#10b981' : 'rgba(99, 102, 241, 0.3)';
                                    }}
                                >
                                    <div style={{
                                        display: 'flex',
                                        justifyContent: 'space-between',
                                        alignItems: 'flex-start',
                                        marginBottom: '1rem'
                                    }}>
                                        <h3 style={{ fontSize: '1.2rem', fontWeight: 'bold', color: '#f8fafc' }}>
                                            {scenario.name}
                                        </h3>
                                        <span style={{
                                            padding: '0.25rem 0.75rem',
                                            background: `${difficultyColors[scenario.difficulty]}20`,
                                            color: difficultyColors[scenario.difficulty],
                                            borderRadius: '999px',
                                            fontSize: '0.75rem',
                                            fontWeight: 'bold',
                                            textTransform: 'uppercase'
                                        }}>
                                            {scenario.difficulty}
                                        </span>
                                    </div>
                                    <p style={{ color: '#94a3b8', marginBottom: '1rem', lineHeight: 1.6 }}>
                                        {scenario.description}
                                    </p>
                                    <div style={{
                                        display: 'flex',
                                        justifyContent: 'space-between',
                                        alignItems: 'center',
                                        paddingTop: '1rem',
                                        borderTop: '1px solid rgba(148, 163, 184, 0.2)'
                                    }}>
                                        <span style={{ color: '#64748b', fontSize: '0.9rem' }}>
                                            ⏱️ {Math.floor(scenario.timeLimit / 60)} minutes
                                        </span>
                                        <span style={{ color: '#64748b', fontSize: '0.9rem' }}>
                                            📝 {scenario.steps.length} étapes
                                        </span>
                                        {completed && (
                                            <span style={{ color: '#10b981', fontSize: '0.9rem' }}>
                                                ✅ Score: {completed.score}
                                            </span>
                                        )}
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </div>
            )}

            {/* Active Scenario */}
            {activeScenario && !showDebriefing && (
                <div style={{
                    maxWidth: '900px',
                    margin: '0 auto'
                }}>
                    {/* Progress */}
                    <div style={{
                        display: 'flex',
                        gap: '0.5rem',
                        marginBottom: '2rem'
                    }}>
                        {activeScenario.steps.map((_, idx) => (
                            <div
                                key={idx}
                                style={{
                                    flex: 1,
                                    height: '8px',
                                    borderRadius: '4px',
                                    background: idx < currentStep ? '#10b981' : idx === currentStep ? '#818cf8' : 'rgba(148, 163, 184, 0.3)'
                                }}
                            />
                        ))}
                    </div>

                    {/* Current Step */}
                    <div style={{
                        background: 'rgba(30, 41, 59, 0.9)',
                        borderRadius: '16px',
                        padding: '2rem',
                        border: '1px solid rgba(99, 102, 241, 0.3)'
                    }}>
                        <div style={{
                            marginBottom: '2rem',
                            padding: '1.5rem',
                            background: 'rgba(99, 102, 241, 0.1)',
                            borderRadius: '12px',
                            borderLeft: '4px solid #818cf8'
                        }}>
                            <h3 style={{ color: '#c084fc', marginBottom: '0.5rem', fontSize: '0.9rem' }}>
                                SITUATION {currentStep + 1}/{activeScenario.steps.length}
                            </h3>
                            <p style={{ fontSize: '1.1rem', lineHeight: 1.7 }}>
                                {activeScenario.steps[currentStep].situation}
                            </p>
                        </div>

                        <h4 style={{ color: '#f8fafc', marginBottom: '1rem' }}>
                            Quelle est votre décision?
                        </h4>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                            {activeScenario.steps[currentStep].options.map((option, idx) => (
                                <button
                                    key={idx}
                                    onClick={() => handleChoice(option, currentStep)}
                                    style={{
                                        padding: '1.25rem',
                                        background: 'rgba(15, 23, 42, 0.8)',
                                        border: '1px solid rgba(148, 163, 184, 0.3)',
                                        borderRadius: '12px',
                                        color: '#e2e8f0',
                                        textAlign: 'left',
                                        cursor: 'pointer',
                                        transition: 'all 0.3s ease',
                                        fontSize: '1rem'
                                    }}
                                    onMouseEnter={e => {
                                        e.currentTarget.style.borderColor = '#818cf8';
                                        e.currentTarget.style.background = 'rgba(99, 102, 241, 0.1)';
                                    }}
                                    onMouseLeave={e => {
                                        e.currentTarget.style.borderColor = 'rgba(148, 163, 184, 0.3)';
                                        e.currentTarget.style.background = 'rgba(15, 23, 42, 0.8)';
                                    }}
                                >
                                    <span style={{ color: '#818cf8', fontWeight: 'bold', marginRight: '0.75rem' }}>
                                        {String.fromCharCode(65 + idx)}.
                                    </span>
                                    {option.text}
                                </button>
                            ))}
                        </div>
                    </div>
                </div>
            )}

            {/* Debriefing */}
            {showDebriefing && activeScenario && (
                <div style={{
                    maxWidth: '900px',
                    margin: '0 auto'
                }}>
                    <div style={{
                        background: 'rgba(30, 41, 59, 0.9)',
                        borderRadius: '16px',
                        padding: '2rem',
                        border: '1px solid rgba(16, 185, 129, 0.3)'
                    }}>
                        <h2 style={{
                            fontSize: '1.8rem',
                            marginBottom: '1.5rem',
                            background: 'linear-gradient(90deg, #10b981, #3b82f6)',
                            WebkitBackgroundClip: 'text',
                            WebkitTextFillColor: 'transparent'
                        }}>
                            📊 Debriefing - {activeScenario.name}
                        </h2>

                        {/* Score final */}
                        {(() => {
                            const maxScore = activeScenario.steps.reduce((sum, step) => 
                                sum + Math.max(...step.options.map(o => o.points)), 0);
                            const gradeInfo = getScoreGrade(score, maxScore);
                            
                            return (
                                <div style={{
                                    display: 'flex',
                                    justifyContent: 'center',
                                    gap: '3rem',
                                    marginBottom: '2rem',
                                    padding: '2rem',
                                    background: 'rgba(15, 23, 42, 0.5)',
                                    borderRadius: '12px'
                                }}>
                                    <div style={{ textAlign: 'center' }}>
                                        <div style={{ fontSize: '4rem', fontWeight: 'bold', color: gradeInfo.color }}>
                                            {gradeInfo.grade}
                                        </div>
                                        <div style={{ color: '#94a3b8' }}>{gradeInfo.label}</div>
                                    </div>
                                    <div style={{ textAlign: 'center' }}>
                                        <div style={{ fontSize: '2rem', fontWeight: 'bold', color: score >= 0 ? '#10b981' : '#ef4444' }}>
                                            {score > 0 ? '+' : ''}{score} / {maxScore}
                                        </div>
                                        <div style={{ color: '#94a3b8' }}>Points obtenus</div>
                                    </div>
                                    <div style={{ textAlign: 'center' }}>
                                        <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#3b82f6' }}>
                                            {formatTime(activeScenario.timeLimit - timeRemaining)}
                                        </div>
                                        <div style={{ color: '#94a3b8' }}>Temps utilisé</div>
                                    </div>
                                </div>
                            );
                        })()}

                        {/* Historique des choix */}
                        <h3 style={{ color: '#f8fafc', marginBottom: '1rem' }}>📝 Vos décisions</h3>
                        <div style={{ marginBottom: '2rem' }}>
                            {history.map((h, idx) => (
                                <div key={idx} style={{
                                    padding: '1rem',
                                    marginBottom: '0.5rem',
                                    background: h.points > 0 ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                                    borderRadius: '8px',
                                    borderLeft: `4px solid ${h.points > 0 ? '#10b981' : '#ef4444'}`
                                }}>
                                    <div style={{ fontWeight: 'bold', marginBottom: '0.5rem' }}>
                                        {h.choice}
                                        <span style={{
                                            marginLeft: '1rem',
                                            color: h.points > 0 ? '#10b981' : '#ef4444'
                                        }}>
                                            {h.points > 0 ? '+' : ''}{h.points} pts
                                        </span>
                                    </div>
                                    <div style={{ color: '#94a3b8', fontSize: '0.9rem' }}>
                                        → {h.consequence}
                                    </div>
                                </div>
                            ))}
                        </div>

                        {/* Leçons clés */}
                        <h3 style={{ color: '#f8fafc', marginBottom: '1rem' }}>🎓 Leçons clés</h3>
                        <div style={{
                            display: 'grid',
                            gridTemplateColumns: 'repeat(2, 1fr)',
                            gap: '1rem',
                            marginBottom: '2rem'
                        }}>
                            {activeScenario.debriefing.keyLessons.map((lesson, idx) => (
                                <div key={idx} style={{
                                    padding: '1rem',
                                    background: 'rgba(99, 102, 241, 0.1)',
                                    borderRadius: '8px'
                                }}>
                                    <span style={{ color: '#818cf8', marginRight: '0.5rem' }}>💡</span>
                                    {lesson}
                                </div>
                            ))}
                        </div>

                        {/* Bonnes pratiques */}
                        <h3 style={{ color: '#f8fafc', marginBottom: '1rem' }}>✅ Bonnes pratiques</h3>
                        <div style={{ marginBottom: '2rem' }}>
                            {activeScenario.debriefing.bestPractices.map((practice, idx) => (
                                <div key={idx} style={{
                                    padding: '0.75rem 1rem',
                                    color: '#94a3b8'
                                }}>
                                    <span style={{ color: '#10b981', marginRight: '0.5rem' }}>✓</span>
                                    {practice}
                                </div>
                            ))}
                        </div>

                        {/* Actions */}
                        <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center' }}>
                            <button
                                onClick={() => startScenario(activeScenario)}
                                style={{
                                    padding: '1rem 2rem',
                                    background: 'linear-gradient(135deg, #818cf8, #6366f1)',
                                    border: 'none',
                                    borderRadius: '12px',
                                    color: 'white',
                                    fontWeight: 'bold',
                                    cursor: 'pointer'
                                }}
                            >
                                🔄 Recommencer
                            </button>
                            <button
                                onClick={resetSimulator}
                                style={{
                                    padding: '1rem 2rem',
                                    background: 'rgba(148, 163, 184, 0.2)',
                                    border: '1px solid rgba(148, 163, 184, 0.3)',
                                    borderRadius: '12px',
                                    color: '#e2e8f0',
                                    fontWeight: 'bold',
                                    cursor: 'pointer'
                                }}
                            >
                                📋 Autres scénarios
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default CyberKineticSimulator;
