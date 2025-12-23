import React, { useState, useEffect, useCallback } from 'react';
import { API_URL } from '../config';
import './AgentEvolutionDashboard.css';

/**
 * Agent Evolution Dashboard
 * 
 * Real-time visualization of AI agents learning and evolving
 * Shows: skill levels, domain expertise, training progress, Fibonacci sync
 */
const AgentEvolutionDashboard = () => {
    const [agents, setAgents] = useState([]);
    const [evolutionStatus, setEvolutionStatus] = useState(null);
    const [trainingLog, setTrainingLog] = useState([]);
    const [isTraining, setIsTraining] = useState(false);
    const [selectedAgent, setSelectedAgent] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    // Agent icons and colors
    const agentThemes = {
        'sadiq-bd/llama3.2-3b-uncensored': { icon: '🎭', color: '#9b59b6', name: 'Sadiq', specialty: 'Social Engineering & OSINT' },
        'uandinotai/dolphin-uncensored': { icon: '🐬', color: '#3498db', name: 'Dolphin', specialty: 'Pentesting & Kernel' },
        'nidumai/nidum-llama-3.2-3b-uncensored': { icon: '⚡', color: '#f39c12', name: 'Nidum', specialty: 'Exploit Dev & Precision' }
    };

    // Fetch evolution status
    const fetchEvolutionStatus = useCallback(async () => {
        try {
            const response = await fetch(`${API_URL}/api/evolution/evolution-status`);
            if (response.ok) {
                const data = await response.json();
                setEvolutionStatus(data);
                setAgents(data.models || []);
            }
        } catch (err) {
            console.error('Failed to fetch evolution status:', err);
        }
    }, []);

    // Fetch training logs
    const fetchTrainingLogs = useCallback(async () => {
        try {
            const response = await fetch(`${API_URL}/api/evolution/training-log`);
            if (response.ok) {
                const data = await response.json();
                setTrainingLog(data.logs || []);
                setIsTraining(data.isTraining || false);
            }
        } catch (err) {
            console.error('Failed to fetch training logs:', err);
        }
    }, []);

    // Initial load
    useEffect(() => {
        const loadData = async () => {
            setLoading(true);
            await Promise.all([fetchEvolutionStatus(), fetchTrainingLogs()]);
            setLoading(false);
        };
        loadData();

        // Poll for updates every 5 seconds
        const interval = setInterval(() => {
            fetchEvolutionStatus();
            fetchTrainingLogs();
        }, 5000);

        return () => clearInterval(interval);
    }, [fetchEvolutionStatus, fetchTrainingLogs]);

    // Start training
    const startTraining = async (modelName, domain) => {
        try {
            setIsTraining(true);
            const response = await fetch(`${API_URL}/api/evolution/train`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ modelName, domain, useRAG: true })
            });
            
            if (response.ok) {
                addToLog(`Started training ${modelName} on ${domain}`);
                fetchEvolutionStatus();
            }
        } catch (err) {
            setError(err.message);
        } finally {
            setIsTraining(false);
        }
    };

    // Add to log
    const addToLog = (message) => {
        setTrainingLog(prev => [
            { timestamp: new Date().toISOString(), message },
            ...prev.slice(0, 49)
        ]);
    };

    // Render skill bar
    const SkillBar = ({ value, label, color }) => (
        <div className="skill-bar-container">
            <div className="skill-bar-label">
                <span>{label}</span>
                <span>{value.toFixed(1)}%</span>
            </div>
            <div className="skill-bar-track">
                <div 
                    className="skill-bar-fill" 
                    style={{ width: `${Math.min(100, value)}%`, backgroundColor: color }}
                />
            </div>
        </div>
    );

    // Render agent card
    const AgentCard = ({ agent }) => {
        const theme = agentThemes[agent.fullName] || { icon: '🤖', color: '#666', name: agent.name };
        const isSelected = selectedAgent === agent.fullName;
        
        return (
            <div 
                className={`agent-card ${isSelected ? 'selected' : ''}`}
                onClick={() => setSelectedAgent(isSelected ? null : agent.fullName)}
                style={{ borderColor: theme.color }}
            >
                <div className="agent-header">
                    <span className="agent-icon">{theme.icon}</span>
                    <div className="agent-info">
                        <h3>{theme.name}</h3>
                        <span className="agent-level">Level {agent.evolutionLevel} - {agent.levelName}</span>
                    </div>
                    <div className="agent-status">
                        {agent.prodigyScore && (
                            <span className="prodigy-badge">⭐ {agent.prodigyScore}/10</span>
                        )}
                    </div>
                </div>

                <div className="agent-specialty">{theme.specialty}</div>

                <div className="agent-stats">
                    <div className="stat">
                        <span className="stat-value">{agent.stats?.sessions || 0}</span>
                        <span className="stat-label">Sessions</span>
                    </div>
                    <div className="stat">
                        <span className="stat-value">{agent.stats?.passed || 0}</span>
                        <span className="stat-label">Passed</span>
                    </div>
                    <div className="stat">
                        <span className="stat-value">{agent.stats?.xp || 0}</span>
                        <span className="stat-label">XP</span>
                    </div>
                    <div className="stat">
                        <span className="stat-value">{(agent.stats?.momentum || 1).toFixed(2)}x</span>
                        <span className="stat-label">Momentum</span>
                    </div>
                </div>

                {isSelected && agent.domainExpertise && (
                    <div className="agent-expertise">
                        <h4>Domain Expertise</h4>
                        {Object.entries(agent.domainExpertise)
                            .sort((a, b) => b[1] - a[1])
                            .slice(0, 6)
                            .map(([domain, value]) => (
                                <SkillBar 
                                    key={domain} 
                                    label={domain} 
                                    value={value} 
                                    color={theme.color}
                                />
                            ))
                        }
                    </div>
                )}

                <div className="agent-actions">
                    <button 
                        className="train-btn"
                        onClick={(e) => {
                            e.stopPropagation();
                            startTraining(agent.fullName, 'pentesting');
                        }}
                        disabled={isTraining}
                    >
                        {isTraining ? '⏳ Training...' : '🎓 Train'}
                    </button>
                </div>
            </div>
        );
    };

    // Render training log
    const TrainingLog = () => (
        <div className="training-log">
            <div className="log-header">
                <h3>📜 Training Log</h3>
                {isTraining && <span className="training-indicator">🔄 Training in progress...</span>}
            </div>
            <div className="log-entries">
                {trainingLog.length === 0 ? (
                    <p className="no-logs">No training activity yet</p>
                ) : (
                    trainingLog.map((entry, i) => (
                        <div key={i} className={`log-entry ${entry.type || ''}`}>
                            <span className="log-time">
                                {new Date(entry.timestamp).toLocaleTimeString()}
                            </span>
                            <span className="log-message">{entry.message}</span>
                        </div>
                    ))
                )}
            </div>
        </div>
    );

    // Render evolution levels legend
    const EvolutionLegend = () => (
        <div className="evolution-legend">
            <h4>🧬 Evolution Levels</h4>
            <div className="levels-grid">
                {[
                    { level: 1, name: 'Script Kiddie', emoji: '👶' },
                    { level: 2, name: 'Junior Pentester', emoji: '🔰' },
                    { level: 3, name: 'Security Analyst', emoji: '🔍' },
                    { level: 4, name: 'Red Team Operator', emoji: '🎯' },
                    { level: 5, name: 'Elite Hacker', emoji: '💀' },
                    { level: 6, name: 'APT Specialist', emoji: '🕵️' },
                    { level: 7, name: 'Ghost', emoji: '👻' },
                    { level: 8, name: 'Legendary', emoji: '🏆' },
                    { level: 9, name: 'Prodigy', emoji: '⭐' },
                    { level: 10, name: 'Transcendent', emoji: '🌟' }
                ].map(l => (
                    <div key={l.level} className="level-item">
                        <span className="level-emoji">{l.emoji}</span>
                        <span className="level-number">{l.level}</span>
                        <span className="level-name">{l.name}</span>
                    </div>
                ))}
            </div>
        </div>
    );

    if (loading) {
        return (
            <div className="evolution-dashboard loading">
                <div className="loader">
                    <span className="loader-icon">🧬</span>
                    <p>Loading Evolution Dashboard...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="evolution-dashboard">
            <header className="dashboard-header">
                <div className="header-content">
                    <h1>🧬 Agent Evolution Dashboard</h1>
                    <p>Real-time visualization of AI agents learning and evolving</p>
                </div>
                <div className="header-stats">
                    <div className="header-stat">
                        <span className="stat-value">{agents.length}</span>
                        <span className="stat-label">Agents</span>
                    </div>
                    <div className="header-stat">
                        <span className="stat-value">{evolutionStatus?.isActive ? '🟢' : '⏸️'}</span>
                        <span className="stat-label">Status</span>
                    </div>
                    <div className="header-stat">
                        <span className="stat-value">φ</span>
                        <span className="stat-label">1.618</span>
                    </div>
                </div>
            </header>

            {error && (
                <div className="error-banner">
                    ⚠️ {error}
                    <button onClick={() => setError(null)}>✕</button>
                </div>
            )}

            <div className="dashboard-content">
                <section className="agents-section">
                    <h2>🤖 AI Agents</h2>
                    <div className="agents-grid">
                        {agents.map(agent => (
                            <AgentCard key={agent.fullName || agent.name} agent={agent} />
                        ))}
                    </div>
                </section>

                <aside className="dashboard-sidebar">
                    <TrainingLog />
                    <EvolutionLegend />
                </aside>
            </div>
        </div>
    );
};

export default AgentEvolutionDashboard;
