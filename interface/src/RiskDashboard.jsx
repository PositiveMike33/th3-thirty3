import React, { useState } from 'react';

/**
 * Dashboard de Suivi des Risques IT/OT
 * Visualisation des risques identifiés dans l'analyse de sécurité hybride
 */

const RISKS_DATA = [
    {
        id: 'RISK-001',
        title: 'Fiabilité des algorithmes de sécurité',
        description: 'Les algorithmes de sécurité actuels manquent de fiabilité critique, nécessitant une intervention humaine pour les cas limites',
        level: 'critical',
        category: 'Technique',
        probability: 75,
        impact: 95,
        status: 'open',
        mitigation: 'Implémenter des contrôles manuels de validation',
        owner: 'RSSI',
        dueDate: '2025-02-15',
        progress: 25
    },
    {
        id: 'RISK-002',
        title: 'Attaques cyber-cinétiques',
        description: 'Risque immédiat pour la sécurité physique des employés et l\'intégrité des infrastructures par des attaques combinant cyber et physique',
        level: 'critical',
        category: 'Cyber-Physique',
        probability: 60,
        impact: 100,
        status: 'in_progress',
        mitigation: 'Simulations de crise régulières, isolation réseau OT',
        owner: 'Directeur Sécurité',
        dueDate: '2025-01-30',
        progress: 45
    },
    {
        id: 'RISK-003',
        title: 'Ingénierie sociale sur personnel industriel',
        description: 'Exploitation du manque de sensibilisation aux menaces numériques dans les environnements opérationnels',
        level: 'high',
        category: 'Humain',
        probability: 80,
        impact: 70,
        status: 'in_progress',
        mitigation: 'Formation manipulation psychologique pour cadres',
        owner: 'DRH',
        dueDate: '2025-03-01',
        progress: 30
    },
    {
        id: 'RISK-004',
        title: 'Interprétation erronée des données critiques',
        description: 'Mauvaise interprétation des données numériques lors d\'une crise physique pouvant entraîner des décisions catastrophiques',
        level: 'critical',
        category: 'Décisionnel',
        probability: 55,
        impact: 90,
        status: 'open',
        mitigation: 'Définir autorité décisionnelle humain vs capteurs',
        owner: 'COO',
        dueDate: '2025-02-01',
        progress: 10
    },
    {
        id: 'RISK-005',
        title: 'Protocoles non traduits pour opérateurs',
        description: 'L\'absence de protocoles de sécurité traduits en langage opérationnel laisse le personnel de terrain vulnérable',
        level: 'high',
        category: 'Communication',
        probability: 70,
        impact: 65,
        status: 'in_progress',
        mitigation: 'Créer lexique commun cyber/opérations',
        owner: 'Responsable Formation',
        dueDate: '2025-02-28',
        progress: 60
    },
    {
        id: 'RISK-006',
        title: 'Canaux de communication compromis',
        description: 'Absence de canaux de communication hors bande pour la gestion de crise lorsque les réseaux numériques sont compromis',
        level: 'high',
        category: 'Infrastructure',
        probability: 45,
        impact: 85,
        status: 'in_progress',
        mitigation: 'Établir communications radio/satellite de secours + Failover Cloud→Local automatique',
        owner: 'IT Manager',
        dueDate: '2025-04-01',
        progress: 50
    },
    {
        id: 'RISK-007',
        title: 'Interfaces IHM non intuitives',
        description: 'Les interfaces homme-machine ne présentent pas les anomalies de sécurité de manière suffisamment intuitive',
        level: 'medium',
        category: 'UX/Sécurité',
        probability: 65,
        impact: 55,
        status: 'planned',
        mitigation: 'Audit ergonomique des IHM critiques',
        owner: 'Responsable Automatisme',
        dueDate: '2025-05-01',
        progress: 0
    },
    {
        id: 'RISK-008',
        title: 'Commandes critiques non validées',
        description: 'Absence de mécanismes de vérification manuelle pour les commandes critiques envoyées aux systèmes industriels',
        level: 'critical',
        category: 'Contrôle',
        probability: 50,
        impact: 95,
        status: 'in_progress',
        mitigation: 'Implémenter double validation SCADA',
        owner: 'RSSI',
        dueDate: '2025-01-15',
        progress: 70
    }
];

const RECOMMENDATIONS_STATUS = [
    { id: 1, text: 'Intégrer protocoles cyber aux procédures SSE', status: 'in_progress', completion: 35 },
    { id: 2, text: 'Organiser simulations de crise IT/OT', status: 'planned', completion: 10 },
    { id: 3, text: 'Définir autorité décisionnelle humain/capteurs', status: 'open', completion: 0 },
    { id: 4, text: 'Renforcer contrôles d\'accès post Red Team', status: 'in_progress', completion: 55 },
    { id: 5, text: 'Former cadres manipulation psychologique', status: 'in_progress', completion: 25 },
    { id: 6, text: 'Établir canaux communication hors bande + Failover auto', status: 'in_progress', completion: 50 },
    { id: 7, text: 'Auditer interfaces homme-machine', status: 'planned', completion: 5 },
    { id: 8, text: 'Créer lexique commun cyber/opérations', status: 'in_progress', completion: 60 },
    { id: 9, text: 'Implémenter vérifications manuelles SCADA', status: 'in_progress', completion: 70 },
    { id: 10, text: 'Développer indicateurs compromission physique', status: 'planned', completion: 15 }
];

const RiskDashboard = () => {
    const [selectedRisk, setSelectedRisk] = useState(null);
    const [filterLevel, setFilterLevel] = useState('all');
    const [filterStatus, setFilterStatus] = useState('all');
    const [viewMode, setViewMode] = useState('matrix'); // matrix, list, recommendations

    const getLevelColor = (level) => {
        switch(level) {
            case 'critical': return '#ef4444';
            case 'high': return '#f97316';
            case 'medium': return '#eab308';
            case 'low': return '#22c55e';
            default: return '#64748b';
        }
    };

    const getLevelLabel = (level) => {
        switch(level) {
            case 'critical': return 'Critique';
            case 'high': return 'Élevé';
            case 'medium': return 'Moyen';
            case 'low': return 'Faible';
            default: return level;
        }
    };

    const getStatusColor = (status) => {
        switch(status) {
            case 'open': return '#ef4444';
            case 'in_progress': return '#3b82f6';
            case 'planned': return '#8b5cf6';
            case 'resolved': return '#22c55e';
            default: return '#64748b';
        }
    };

    const getStatusLabel = (status) => {
        switch(status) {
            case 'open': return 'Ouvert';
            case 'in_progress': return 'En cours';
            case 'planned': return 'Planifié';
            case 'resolved': return 'Résolu';
            default: return status;
        }
    };

    const filteredRisks = RISKS_DATA.filter(risk => {
        if (filterLevel !== 'all' && risk.level !== filterLevel) return false;
        if (filterStatus !== 'all' && risk.status !== filterStatus) return false;
        return true;
    });

    // Calculs pour le dashboard
    const riskScore = RISKS_DATA.reduce((sum, r) => sum + (r.probability * r.impact / 100), 0) / RISKS_DATA.length;
    const criticalCount = RISKS_DATA.filter(r => r.level === 'critical').length;
    const openCount = RISKS_DATA.filter(r => r.status === 'open').length;
    const avgProgress = RISKS_DATA.reduce((sum, r) => sum + r.progress, 0) / RISKS_DATA.length;

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
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '2rem',
                padding: '1.5rem',
                background: 'rgba(30, 41, 59, 0.8)',
                borderRadius: '16px',
                border: '1px solid rgba(239, 68, 68, 0.3)'
            }}>
                <div>
                    <h1 style={{
                        fontSize: '2rem',
                        fontWeight: 'bold',
                        background: 'linear-gradient(90deg, #ef4444, #f97316)',
                        WebkitBackgroundClip: 'text',
                        WebkitTextFillColor: 'transparent',
                        marginBottom: '0.5rem'
                    }}>
                        🛡️ Dashboard Risques IT/OT
                    </h1>
                    <p style={{ color: '#94a3b8' }}>
                        Suivi des risques de l'analyse de sécurité hybride
                    </p>
                </div>
                
                {/* View Mode Toggle */}
                <div style={{
                    display: 'flex',
                    background: 'rgba(15, 23, 42, 0.8)',
                    borderRadius: '12px',
                    padding: '0.25rem'
                }}>
                    {[
                        { id: 'matrix', label: '📊 Matrice', icon: '📊' },
                        { id: 'list', label: '📋 Liste', icon: '📋' },
                        { id: 'recommendations', label: '✅ Actions', icon: '✅' }
                    ].map(mode => (
                        <button
                            key={mode.id}
                            onClick={() => setViewMode(mode.id)}
                            style={{
                                padding: '0.75rem 1.5rem',
                                background: viewMode === mode.id ? 'linear-gradient(135deg, #6366f1, #8b5cf6)' : 'transparent',
                                border: 'none',
                                borderRadius: '10px',
                                color: viewMode === mode.id ? 'white' : '#94a3b8',
                                cursor: 'pointer',
                                fontWeight: 'bold',
                                transition: 'all 0.3s ease'
                            }}
                        >
                            {mode.label}
                        </button>
                    ))}
                </div>
            </div>

            {/* KPI Cards */}
            <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(4, 1fr)',
                gap: '1.5rem',
                marginBottom: '2rem'
            }}>
                <div style={{
                    padding: '1.5rem',
                    background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.2), rgba(239, 68, 68, 0.1))',
                    borderRadius: '16px',
                    border: '1px solid rgba(239, 68, 68, 0.3)'
                }}>
                    <div style={{ fontSize: '0.9rem', color: '#94a3b8', marginBottom: '0.5rem' }}>
                        Score de Risque Global
                    </div>
                    <div style={{
                        fontSize: '3rem',
                        fontWeight: 'bold',
                        color: riskScore > 60 ? '#ef4444' : riskScore > 40 ? '#f97316' : '#22c55e'
                    }}>
                        {riskScore.toFixed(0)}
                    </div>
                    <div style={{ fontSize: '0.8rem', color: '#64748b' }}>/ 100</div>
                </div>

                <div style={{
                    padding: '1.5rem',
                    background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.2), rgba(239, 68, 68, 0.1))',
                    borderRadius: '16px',
                    border: '1px solid rgba(239, 68, 68, 0.3)'
                }}>
                    <div style={{ fontSize: '0.9rem', color: '#94a3b8', marginBottom: '0.5rem' }}>
                        Risques Critiques
                    </div>
                    <div style={{ fontSize: '3rem', fontWeight: 'bold', color: '#ef4444' }}>
                        {criticalCount}
                    </div>
                    <div style={{ fontSize: '0.8rem', color: '#64748b' }}>sur {RISKS_DATA.length} total</div>
                </div>

                <div style={{
                    padding: '1.5rem',
                    background: 'linear-gradient(135deg, rgba(249, 115, 22, 0.2), rgba(249, 115, 22, 0.1))',
                    borderRadius: '16px',
                    border: '1px solid rgba(249, 115, 22, 0.3)'
                }}>
                    <div style={{ fontSize: '0.9rem', color: '#94a3b8', marginBottom: '0.5rem' }}>
                        Risques Ouverts
                    </div>
                    <div style={{ fontSize: '3rem', fontWeight: 'bold', color: '#f97316' }}>
                        {openCount}
                    </div>
                    <div style={{ fontSize: '0.8rem', color: '#64748b' }}>à traiter en priorité</div>
                </div>

                <div style={{
                    padding: '1.5rem',
                    background: 'linear-gradient(135deg, rgba(34, 197, 94, 0.2), rgba(34, 197, 94, 0.1))',
                    borderRadius: '16px',
                    border: '1px solid rgba(34, 197, 94, 0.3)'
                }}>
                    <div style={{ fontSize: '0.9rem', color: '#94a3b8', marginBottom: '0.5rem' }}>
                        Progression Moyenne
                    </div>
                    <div style={{ fontSize: '3rem', fontWeight: 'bold', color: '#22c55e' }}>
                        {avgProgress.toFixed(0)}%
                    </div>
                    <div style={{ fontSize: '0.8rem', color: '#64748b' }}>des mitigations</div>
                </div>
            </div>

            {/* Risk Matrix View */}
            {viewMode === 'matrix' && (
                <div style={{
                    background: 'rgba(30, 41, 59, 0.8)',
                    borderRadius: '16px',
                    padding: '2rem',
                    border: '1px solid rgba(148, 163, 184, 0.2)'
                }}>
                    <h2 style={{ fontSize: '1.5rem', marginBottom: '1.5rem', color: '#f8fafc' }}>
                        📊 Matrice Probabilité × Impact
                    </h2>
                    
                    <div style={{
                        display: 'grid',
                        gridTemplateColumns: '60px repeat(5, 1fr)',
                        gridTemplateRows: 'repeat(5, 80px) 40px',
                        gap: '4px',
                        marginBottom: '1rem'
                    }}>
                        {/* Y-axis label */}
                        <div style={{
                            gridRow: '1 / 6',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            writingMode: 'vertical-rl',
                            transform: 'rotate(180deg)',
                            fontWeight: 'bold',
                            color: '#94a3b8'
                        }}>
                            PROBABILITÉ →
                        </div>
                        
                        {/* Matrix cells - 5x5 grid */}
                        {[5, 4, 3, 2, 1].map(prob => (
                            [1, 2, 3, 4, 5].map(impact => {
                                const cellRisks = RISKS_DATA.filter(r => {
                                    const pBucket = Math.ceil(r.probability / 20);
                                    const iBucket = Math.ceil(r.impact / 20);
                                    return pBucket === prob && iBucket === impact;
                                });
                                
                                const riskLevel = prob * impact;
                                const bgColor = riskLevel >= 20 ? 'rgba(239, 68, 68, 0.3)' :
                                               riskLevel >= 12 ? 'rgba(249, 115, 22, 0.3)' :
                                               riskLevel >= 6 ? 'rgba(234, 179, 8, 0.3)' :
                                               'rgba(34, 197, 94, 0.3)';
                                
                                return (
                                    <div
                                        key={`${prob}-${impact}`}
                                        style={{
                                            background: bgColor,
                                            borderRadius: '8px',
                                            display: 'flex',
                                            flexWrap: 'wrap',
                                            alignItems: 'center',
                                            justifyContent: 'center',
                                            gap: '4px',
                                            padding: '4px',
                                            cursor: cellRisks.length > 0 ? 'pointer' : 'default'
                                        }}
                                    >
                                        {cellRisks.map(risk => (
                                            <div
                                                key={risk.id}
                                                onClick={() => setSelectedRisk(risk)}
                                                title={risk.title}
                                                style={{
                                                    width: '24px',
                                                    height: '24px',
                                                    borderRadius: '50%',
                                                    background: getLevelColor(risk.level),
                                                    display: 'flex',
                                                    alignItems: 'center',
                                                    justifyContent: 'center',
                                                    fontSize: '0.7rem',
                                                    fontWeight: 'bold',
                                                    color: 'white',
                                                    cursor: 'pointer',
                                                    border: '2px solid white',
                                                    boxShadow: '0 2px 4px rgba(0,0,0,0.3)'
                                                }}
                                            >
                                                {risk.id.split('-')[1]}
                                            </div>
                                        ))}
                                    </div>
                                );
                            })
                        ))}
                        
                        {/* X-axis labels */}
                        <div></div>
                        {[1, 2, 3, 4, 5].map(n => (
                            <div
                                key={n}
                                style={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    justifyContent: 'center',
                                    color: '#94a3b8',
                                    fontSize: '0.9rem'
                                }}
                            >
                                {n * 20}%
                            </div>
                        ))}
                    </div>
                    
                    <div style={{ textAlign: 'center', color: '#94a3b8', fontWeight: 'bold' }}>
                        IMPACT →
                    </div>

                    {/* Legend */}
                    <div style={{
                        display: 'flex',
                        justifyContent: 'center',
                        gap: '2rem',
                        marginTop: '1.5rem',
                        paddingTop: '1.5rem',
                        borderTop: '1px solid rgba(148, 163, 184, 0.2)'
                    }}>
                        {[
                            { level: 'critical', label: 'Critique' },
                            { level: 'high', label: 'Élevé' },
                            { level: 'medium', label: 'Moyen' },
                            { level: 'low', label: 'Faible' }
                        ].map(item => (
                            <div key={item.level} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                <div style={{
                                    width: '16px',
                                    height: '16px',
                                    borderRadius: '50%',
                                    background: getLevelColor(item.level)
                                }} />
                                <span style={{ color: '#94a3b8' }}>{item.label}</span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* List View */}
            {viewMode === 'list' && (
                <div style={{
                    background: 'rgba(30, 41, 59, 0.8)',
                    borderRadius: '16px',
                    padding: '2rem',
                    border: '1px solid rgba(148, 163, 184, 0.2)'
                }}>
                    <div style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        marginBottom: '1.5rem'
                    }}>
                        <h2 style={{ fontSize: '1.5rem', color: '#f8fafc' }}>
                            📋 Liste des Risques
                        </h2>
                        <div style={{ display: 'flex', gap: '1rem' }}>
                            <select
                                value={filterLevel}
                                onChange={(e) => setFilterLevel(e.target.value)}
                                style={{
                                    padding: '0.5rem 1rem',
                                    background: 'rgba(15, 23, 42, 0.8)',
                                    border: '1px solid rgba(148, 163, 184, 0.3)',
                                    borderRadius: '8px',
                                    color: '#e2e8f0'
                                }}
                            >
                                <option value="all">Tous niveaux</option>
                                <option value="critical">Critique</option>
                                <option value="high">Élevé</option>
                                <option value="medium">Moyen</option>
                            </select>
                            <select
                                value={filterStatus}
                                onChange={(e) => setFilterStatus(e.target.value)}
                                style={{
                                    padding: '0.5rem 1rem',
                                    background: 'rgba(15, 23, 42, 0.8)',
                                    border: '1px solid rgba(148, 163, 184, 0.3)',
                                    borderRadius: '8px',
                                    color: '#e2e8f0'
                                }}
                            >
                                <option value="all">Tous statuts</option>
                                <option value="open">Ouvert</option>
                                <option value="in_progress">En cours</option>
                                <option value="planned">Planifié</option>
                            </select>
                        </div>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                        {filteredRisks.map(risk => (
                            <div
                                key={risk.id}
                                onClick={() => setSelectedRisk(risk)}
                                style={{
                                    padding: '1.5rem',
                                    background: 'rgba(15, 23, 42, 0.8)',
                                    borderRadius: '12px',
                                    border: `2px solid ${getLevelColor(risk.level)}40`,
                                    cursor: 'pointer',
                                    transition: 'all 0.3s ease'
                                }}
                                onMouseEnter={e => e.currentTarget.style.borderColor = getLevelColor(risk.level)}
                                onMouseLeave={e => e.currentTarget.style.borderColor = `${getLevelColor(risk.level)}40`}
                            >
                                <div style={{
                                    display: 'flex',
                                    justifyContent: 'space-between',
                                    alignItems: 'flex-start',
                                    marginBottom: '1rem'
                                }}>
                                    <div>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '0.5rem' }}>
                                            <span style={{
                                                padding: '0.25rem 0.75rem',
                                                background: `${getLevelColor(risk.level)}20`,
                                                color: getLevelColor(risk.level),
                                                borderRadius: '999px',
                                                fontSize: '0.75rem',
                                                fontWeight: 'bold'
                                            }}>
                                                {getLevelLabel(risk.level).toUpperCase()}
                                            </span>
                                            <span style={{
                                                padding: '0.25rem 0.75rem',
                                                background: `${getStatusColor(risk.status)}20`,
                                                color: getStatusColor(risk.status),
                                                borderRadius: '999px',
                                                fontSize: '0.75rem'
                                            }}>
                                                {getStatusLabel(risk.status)}
                                            </span>
                                            <span style={{ color: '#64748b', fontSize: '0.9rem' }}>
                                                {risk.id}
                                            </span>
                                        </div>
                                        <h3 style={{ fontSize: '1.2rem', fontWeight: 'bold', color: '#f8fafc' }}>
                                            {risk.title}
                                        </h3>
                                    </div>
                                    <div style={{
                                        display: 'flex',
                                        flexDirection: 'column',
                                        alignItems: 'flex-end',
                                        gap: '0.25rem'
                                    }}>
                                        <div style={{ fontSize: '0.8rem', color: '#64748b' }}>
                                            📊 {risk.probability}% × {risk.impact}%
                                        </div>
                                        <div style={{ fontSize: '0.8rem', color: '#64748b' }}>
                                            📅 {risk.dueDate}
                                        </div>
                                    </div>
                                </div>
                                
                                <p style={{ color: '#94a3b8', marginBottom: '1rem' }}>
                                    {risk.description}
                                </p>
                                
                                <div style={{
                                    display: 'flex',
                                    justifyContent: 'space-between',
                                    alignItems: 'center'
                                }}>
                                    <div style={{ display: 'flex', gap: '2rem' }}>
                                        <span style={{ color: '#64748b', fontSize: '0.9rem' }}>
                                            👤 {risk.owner}
                                        </span>
                                        <span style={{ color: '#64748b', fontSize: '0.9rem' }}>
                                            📁 {risk.category}
                                        </span>
                                    </div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', width: '200px' }}>
                                        <div style={{
                                            flex: 1,
                                            height: '8px',
                                            background: 'rgba(148, 163, 184, 0.2)',
                                            borderRadius: '4px',
                                            overflow: 'hidden'
                                        }}>
                                            <div style={{
                                                width: `${risk.progress}%`,
                                                height: '100%',
                                                background: risk.progress > 70 ? '#22c55e' : risk.progress > 30 ? '#3b82f6' : '#f97316',
                                                borderRadius: '4px'
                                            }} />
                                        </div>
                                        <span style={{ color: '#94a3b8', fontSize: '0.9rem', width: '40px' }}>
                                            {risk.progress}%
                                        </span>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Recommendations View */}
            {viewMode === 'recommendations' && (
                <div style={{
                    background: 'rgba(30, 41, 59, 0.8)',
                    borderRadius: '16px',
                    padding: '2rem',
                    border: '1px solid rgba(148, 163, 184, 0.2)'
                }}>
                    <h2 style={{ fontSize: '1.5rem', marginBottom: '1.5rem', color: '#f8fafc' }}>
                        ✅ Suivi des 10 Recommandations
                    </h2>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                        {RECOMMENDATIONS_STATUS.map(rec => (
                            <div
                                key={rec.id}
                                style={{
                                    padding: '1.25rem',
                                    background: 'rgba(15, 23, 42, 0.8)',
                                    borderRadius: '12px',
                                    border: '1px solid rgba(148, 163, 184, 0.2)'
                                }}
                            >
                                <div style={{
                                    display: 'flex',
                                    justifyContent: 'space-between',
                                    alignItems: 'center',
                                    marginBottom: '0.75rem'
                                }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                                        <span style={{
                                            width: '28px',
                                            height: '28px',
                                            display: 'flex',
                                            alignItems: 'center',
                                            justifyContent: 'center',
                                            background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
                                            borderRadius: '8px',
                                            fontWeight: 'bold',
                                            fontSize: '0.9rem'
                                        }}>
                                            {rec.id}
                                        </span>
                                        <span style={{ color: '#f8fafc' }}>{rec.text}</span>
                                    </div>
                                    <span style={{
                                        padding: '0.25rem 0.75rem',
                                        background: `${getStatusColor(rec.status)}20`,
                                        color: getStatusColor(rec.status),
                                        borderRadius: '999px',
                                        fontSize: '0.75rem'
                                    }}>
                                        {getStatusLabel(rec.status)}
                                    </span>
                                </div>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                                    <div style={{
                                        flex: 1,
                                        height: '10px',
                                        background: 'rgba(148, 163, 184, 0.2)',
                                        borderRadius: '5px',
                                        overflow: 'hidden'
                                    }}>
                                        <div style={{
                                            width: `${rec.completion}%`,
                                            height: '100%',
                                            background: rec.completion === 100 ? '#22c55e' : 
                                                       rec.completion > 50 ? '#3b82f6' : 
                                                       rec.completion > 0 ? '#f97316' : '#64748b',
                                            borderRadius: '5px',
                                            transition: 'width 0.5s ease'
                                        }} />
                                    </div>
                                    <span style={{
                                        color: rec.completion === 100 ? '#22c55e' : '#94a3b8',
                                        fontWeight: 'bold',
                                        minWidth: '50px',
                                        textAlign: 'right'
                                    }}>
                                        {rec.completion}%
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* Summary */}
                    <div style={{
                        marginTop: '2rem',
                        padding: '1.5rem',
                        background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.2), rgba(139, 92, 246, 0.2))',
                        borderRadius: '12px',
                        display: 'flex',
                        justifyContent: 'space-around'
                    }}>
                        <div style={{ textAlign: 'center' }}>
                            <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#ef4444' }}>
                                {RECOMMENDATIONS_STATUS.filter(r => r.status === 'open').length}
                            </div>
                            <div style={{ color: '#94a3b8' }}>À démarrer</div>
                        </div>
                        <div style={{ textAlign: 'center' }}>
                            <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#3b82f6' }}>
                                {RECOMMENDATIONS_STATUS.filter(r => r.status === 'in_progress').length}
                            </div>
                            <div style={{ color: '#94a3b8' }}>En cours</div>
                        </div>
                        <div style={{ textAlign: 'center' }}>
                            <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#8b5cf6' }}>
                                {RECOMMENDATIONS_STATUS.filter(r => r.status === 'planned').length}
                            </div>
                            <div style={{ color: '#94a3b8' }}>Planifiées</div>
                        </div>
                        <div style={{ textAlign: 'center' }}>
                            <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#22c55e' }}>
                                {Math.round(RECOMMENDATIONS_STATUS.reduce((s, r) => s + r.completion, 0) / 10)}%
                            </div>
                            <div style={{ color: '#94a3b8' }}>Progression globale</div>
                        </div>
                    </div>
                </div>
            )}

            {/* Risk Detail Modal */}
            {selectedRisk && (
                <div
                    style={{
                        position: 'fixed',
                        top: 0,
                        left: 0,
                        right: 0,
                        bottom: 0,
                        background: 'rgba(0, 0, 0, 0.8)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        zIndex: 1000
                    }}
                    onClick={() => setSelectedRisk(null)}
                >
                    <div
                        style={{
                            background: 'linear-gradient(135deg, #1e293b, #0f172a)',
                            borderRadius: '20px',
                            padding: '2rem',
                            maxWidth: '600px',
                            width: '90%',
                            border: `2px solid ${getLevelColor(selectedRisk.level)}`,
                            maxHeight: '80vh',
                            overflow: 'auto'
                        }}
                        onClick={e => e.stopPropagation()}
                    >
                        <div style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'flex-start',
                            marginBottom: '1.5rem'
                        }}>
                            <div>
                                <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
                                    <span style={{
                                        padding: '0.25rem 0.75rem',
                                        background: `${getLevelColor(selectedRisk.level)}20`,
                                        color: getLevelColor(selectedRisk.level),
                                        borderRadius: '999px',
                                        fontSize: '0.8rem',
                                        fontWeight: 'bold'
                                    }}>
                                        {getLevelLabel(selectedRisk.level).toUpperCase()}
                                    </span>
                                    <span style={{
                                        padding: '0.25rem 0.75rem',
                                        background: `${getStatusColor(selectedRisk.status)}20`,
                                        color: getStatusColor(selectedRisk.status),
                                        borderRadius: '999px',
                                        fontSize: '0.8rem'
                                    }}>
                                        {getStatusLabel(selectedRisk.status)}
                                    </span>
                                </div>
                                <h2 style={{ fontSize: '1.5rem', color: '#f8fafc' }}>
                                    {selectedRisk.id}: {selectedRisk.title}
                                </h2>
                            </div>
                            <button
                                onClick={() => setSelectedRisk(null)}
                                style={{
                                    background: 'none',
                                    border: 'none',
                                    color: '#94a3b8',
                                    fontSize: '1.5rem',
                                    cursor: 'pointer'
                                }}
                            >
                                ×
                            </button>
                        </div>

                        <p style={{ color: '#94a3b8', marginBottom: '1.5rem', lineHeight: 1.7 }}>
                            {selectedRisk.description}
                        </p>

                        <div style={{
                            display: 'grid',
                            gridTemplateColumns: 'repeat(2, 1fr)',
                            gap: '1rem',
                            marginBottom: '1.5rem'
                        }}>
                            <div style={{
                                padding: '1rem',
                                background: 'rgba(239, 68, 68, 0.1)',
                                borderRadius: '12px'
                            }}>
                                <div style={{ color: '#94a3b8', fontSize: '0.8rem', marginBottom: '0.25rem' }}>
                                    Probabilité
                                </div>
                                <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#ef4444' }}>
                                    {selectedRisk.probability}%
                                </div>
                            </div>
                            <div style={{
                                padding: '1rem',
                                background: 'rgba(249, 115, 22, 0.1)',
                                borderRadius: '12px'
                            }}>
                                <div style={{ color: '#94a3b8', fontSize: '0.8rem', marginBottom: '0.25rem' }}>
                                    Impact
                                </div>
                                <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#f97316' }}>
                                    {selectedRisk.impact}%
                                </div>
                            </div>
                        </div>

                        <div style={{
                            padding: '1rem',
                            background: 'rgba(34, 197, 94, 0.1)',
                            borderRadius: '12px',
                            marginBottom: '1.5rem'
                        }}>
                            <div style={{ color: '#22c55e', fontWeight: 'bold', marginBottom: '0.5rem' }}>
                                🛡️ Plan de mitigation
                            </div>
                            <p style={{ color: '#94a3b8' }}>{selectedRisk.mitigation}</p>
                        </div>

                        <div style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            paddingTop: '1rem',
                            borderTop: '1px solid rgba(148, 163, 184, 0.2)'
                        }}>
                            <div>
                                <span style={{ color: '#64748b' }}>👤 Responsable: </span>
                                <span style={{ color: '#f8fafc' }}>{selectedRisk.owner}</span>
                            </div>
                            <div>
                                <span style={{ color: '#64748b' }}>📅 Échéance: </span>
                                <span style={{ color: '#f8fafc' }}>{selectedRisk.dueDate}</span>
                            </div>
                        </div>

                        <div style={{ marginTop: '1rem' }}>
                            <div style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                marginBottom: '0.5rem'
                            }}>
                                <span style={{ color: '#94a3b8' }}>Progression</span>
                                <span style={{ color: '#f8fafc', fontWeight: 'bold' }}>{selectedRisk.progress}%</span>
                            </div>
                            <div style={{
                                height: '12px',
                                background: 'rgba(148, 163, 184, 0.2)',
                                borderRadius: '6px',
                                overflow: 'hidden'
                            }}>
                                <div style={{
                                    width: `${selectedRisk.progress}%`,
                                    height: '100%',
                                    background: selectedRisk.progress > 70 ? '#22c55e' : selectedRisk.progress > 30 ? '#3b82f6' : '#f97316',
                                    borderRadius: '6px'
                                }} />
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default RiskDashboard;
