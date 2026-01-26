/**
 * EliteScenarios.jsx
 * 
 * Dashboard for 33 Elite Hacker Scenarios 2026
 * Layout: Grid Widgets + Detail Modal
 */

import React, { useState, useEffect } from 'react';
import apiService from '../services/apiService';
import './EliteScenarios.css';

const EliteScenarios = () => {
    const [scenarios, setScenarios] = useState([]);
    const [categories, setCategories] = useState([]);
    const [selectedScenario, setSelectedScenario] = useState(null);
    const [trainingPrompt, setTrainingPrompt] = useState('');
    const [activeMissions, setActiveMissions] = useState({}); // Track active scenario missions
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [debugInfo, setDebugInfo] = useState('');
    const [filter, setFilter] = useState('all');

    useEffect(() => {
        fetchScenarios();
    }, []);

    const fetchScenarios = async () => {
        try {
            const res = await apiService.get('/api/elite-scenarios');
            // apiService returns JSON directly, not wrapped in .data
            const scenariosData = res?.scenarios || [];
            setScenarios(scenariosData);

            const catRes = await apiService.get('/api/elite-scenarios/categories');
            setCategories(catRes?.categories || []);
            setDebugInfo(`Loaded ${scenariosData.length} scenarios from ${apiService.baseUrl}`);
        } catch (err) {
            console.error('[EliteScenarios] Fetch error:', err);
            setError(err.message + (err.cause ? ` (${err.cause})` : ''));
            setDebugInfo(`Failed to load from ${apiService.baseUrl}/api/elite-scenarios`);
        } finally {
            setLoading(false);
        }
    };

    const loadTrainingPrompt = async (id) => {
        setTrainingPrompt(''); // Reset
        try {
            const res = await apiService.get(`/api/elite-scenarios/${id}/training-prompt`);
            setTrainingPrompt(res.data.prompt || '');
        } catch (err) {
            console.error('[EliteScenarios] Training prompt error:', err);
        }
    };

    const handleSelect = async (scenario) => {
        setSelectedScenario(scenario);
        await loadTrainingPrompt(scenario.id);
    };

    const handleCloseDetail = () => {
        setSelectedScenario(null);
    };

    const handleActivate = async (e, scenario) => {
        e.stopPropagation();
        if (activeMissions[scenario.id]) return; // Already active or starting

        try {
            // Optimistic update
            setActiveMissions(prev => ({ ...prev, [scenario.id]: 'starting' }));

            const res = await apiService.post('/api/elite-scenarios/execute', {
                scenarioId: scenario.id,
                target: 'SIMULATION_ENVIRONMENT'
            });

            if (res.success) {
                // In a real app, socket updates would handle this, but here we set to running
                setActiveMissions(prev => ({ ...prev, [scenario.id]: 'running' }));
            } else {
                setActiveMissions(prev => ({ ...prev, [scenario.id]: 'error' }));
            }
        } catch (err) {
            console.error('Activation failed:', err);
            setActiveMissions(prev => ({ ...prev, [scenario.id]: 'error' }));
        }
    };

    // Filter Logic
    const filteredScenarios = filter === 'all'
        ? scenarios
        : scenarios.filter(s => s.difficulty === filter);

    if (loading) {
        return (
            <div className="elite-scenarios loading">
                <div className="loader">⚡ CHARGEMENT DU SYSTÈME...</div>
                <div style={{ marginTop: 20, color: '#666', fontSize: '0.8rem' }}>Connection à {apiService.baseUrl}...</div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="elite-scenarios error" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100vh' }}>
                <h2 style={{ color: '#ff4444' }}>❌ ERREUR DE CONNEXION</h2>
                <p style={{ color: '#fff', fontSize: '1.2rem', margin: '20px 0' }}>{error}</p>
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: 15, borderRadius: 8, fontFamily: 'monospace', color: '#aaa' }}>
                    DEBUG: {debugInfo}
                </div>
                <button
                    onClick={() => { setLoading(true); setError(null); fetchScenarios(); }}
                    style={{ marginTop: 30, padding: '12px 30px', background: '#ff4444', border: 'none', borderRadius: 8, color: 'white', fontWeight: 'bold', cursor: 'pointer' }}
                >
                    🔄 RÉESSAYER
                </button>
            </div>
        );
    }

    return (
        <div className="elite-scenarios">
            <div className="es-header">
                <div className="es-logo">🎯</div>
                <h1>ELITE HACKER SCENARIOS</h1>
                <p className="es-subtitle">33 SCÉNARIOS D'ATTAQUE QUÉBEC 2026</p>
            </div>

            {/* Stats Bar */}
            <div className="es-stats">
                <div className="stat">
                    <span className="stat-value">{scenarios.length}</span>
                    <span className="stat-label">TOTAL SCENARIOS</span>
                </div>
                <div className="stat">
                    <span className="stat-value">{scenarios.filter(s => s.difficulty === 'Expert').length}</span>
                    <span className="stat-label">NIVEAU EXPERT</span>
                </div>
                <div className="stat">
                    <span className="stat-value">{scenarios.filter(s => s.difficulty === 'Avancé').length}</span>
                    <span className="stat-label">NIVEAU AVANCÉ</span>
                </div>
            </div>

            {/* Filter Buttons */}
            <div className="es-filters">
                <button
                    className={`filter-btn ${filter === 'all' ? 'active' : ''}`}
                    onClick={() => setFilter('all')}
                >
                    TOUS ({scenarios.length})
                </button>
                <button
                    className={`filter-btn ${filter === 'Expert' ? 'active' : ''}`}
                    onClick={() => setFilter('Expert')}
                >
                    🔥 EXPERT
                </button>
                <button
                    className={`filter-btn ${filter === 'Avancé' ? 'active' : ''}`}
                    onClick={() => setFilter('Avancé')}
                >
                    ⚡ AVANCÉ
                </button>
            </div>

            {/* Scenarios Grid List */}
            <div className="es-content">
                <div className="es-list">
                    {filteredScenarios.map(scenario => (
                        <div
                            key={scenario.id}
                            className={`scenario-card ${activeMissions[scenario.id] === 'running' ? 'active-mission' : ''}`}
                            onClick={() => handleSelect(scenario)}
                        >
                            {/* Card Header */}
                            <div className="scenario-header">
                                <span className="scenario-id">#{scenario.id}</span>
                                <span className="scenario-difficulty">{scenario.difficulty}</span>
                            </div>

                            {/* Card Content */}
                            <h3>{scenario.title}</h3>
                            <div className="scenario-category">{scenario.category}</div>

                            {/* Tool Tags */}
                            <div className="scenario-tools">
                                {scenario.tools?.slice(0, 3).map((tool, i) => (
                                    <span key={i} className="tool-tag">{tool}</span>
                                ))}
                                {scenario.tools?.length > 3 && (
                                    <span className="tool-tag more">+{scenario.tools.length - 3}</span>
                                )}
                            </div>

                            {/* Activation Widget Area */}
                            <div className="scenario-actions">
                                {activeMissions[scenario.id] === 'running' ? (
                                    <div className="mission-status running">
                                        <span className="pulse">●</span> EN COURS
                                    </div>
                                ) : activeMissions[scenario.id] === 'starting' ? (
                                    <div className="mission-status starting">
                                        <span className="pulse">○</span> DÉMARRAGE...
                                    </div>
                                ) : (
                                    <>
                                        <span className="detail-hint">Cliquez pour détails</span>
                                        <button
                                            className="activate-btn"
                                            onClick={(e) => handleActivate(e, scenario)}
                                        >
                                            ▶ ACTIVER
                                        </button>
                                    </>
                                )}
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Scenario Detail Modal */}
            {selectedScenario && (
                <div className="es-modal-overlay" onClick={handleCloseDetail}>
                    <div className="es-modal-content" onClick={e => e.stopPropagation()}>
                        <button className="close-modal-btn" onClick={handleCloseDetail}>×</button>

                        <div className="es-modal-body">
                            <div className="detail-header">
                                <span className="detail-id">SCÉNARIO #{selectedScenario.id}</span>
                                <span className="detail-difficulty-badge">{selectedScenario.difficulty}</span>
                            </div>

                            <h2>{selectedScenario.title}</h2>
                            <div className="detail-category-large">{selectedScenario.category}</div>

                            <div className="detail-section">
                                <h4>🎯 OBJECTIF & QUESTION</h4>
                                <div className="question-box">{selectedScenario.question}</div>
                            </div>

                            <div className="detail-section">
                                <h4>🛠️ ARSENAL REQUIS ({selectedScenario.tools?.length})</h4>
                                <div className="tools-grid">
                                    {selectedScenario.tools?.map((tool, i) => (
                                        <span key={i} className="tool-chip">{tool}</span>
                                    ))}
                                </div>
                            </div>

                            {trainingPrompt && (
                                <div className="detail-section training">
                                    <h4>📋 PLAN D'ATTAQUE (ORCHESTRATOR PROMPT)</h4>
                                    <pre className="training-box">{trainingPrompt}</pre>
                                </div>
                            )}

                            <div className="modal-actions">
                                {activeMissions[selectedScenario.id] === 'running' ? (
                                    <div className="mission-status running">
                                        <span className="pulse">●</span> MISSION EN COURS
                                    </div>
                                ) : (
                                    <button
                                        className="modal-activate-btn"
                                        onClick={(e) => handleActivate(e, selectedScenario)}
                                    >
                                        ▶ LANCER L'ATTAQUE
                                    </button>
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default EliteScenarios;
