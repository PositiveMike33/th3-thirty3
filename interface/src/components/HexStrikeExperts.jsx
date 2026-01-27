/**
 * HexStrikeExperts.jsx
 * 
 * Dashboard component for HexStrike tool experts visualization and interaction
 * Features Live Threat Feed for continuous learning
 */

import React, { useState, useEffect, useRef } from 'react';
import apiService from '../services/apiService';
import './HexStrikeExperts.css';

// Live Monitor Component
const LiveMonitorDisplay = () => {
    const [lesson, setLesson] = useState(null);
    const [polling, setPolling] = useState(true);

    useEffect(() => {
        let interval;
        if (polling) {
            const fetchLesson = async () => {
                try {
                    const res = await apiService.get('/api/live-monitor/lessons/latest');
                    if (res && res.lesson && (!lesson || res.lesson.timestamp !== lesson.timestamp)) {
                        setLesson(res.lesson);
                    }
                } catch (e) {
                    console.error("Monitor poll error", e);
                }
            };
            fetchLesson(); // Initial fetch
            interval = setInterval(fetchLesson, 5000); // Poll every 5s
        }
        return () => clearInterval(interval);
    }, [polling, lesson]);

    if (!lesson) return (
        <div className="live-monitor-placeholder">
            <span className="animate-pulse">📡 Initializing Neural Uplink...</span>
        </div>
    );

    return (
        <div className="live-monitor-feed">
            <div className="feed-header">
                <span className="feed-badge">🔴 LIVE TRAINING FEED</span>
                <span className="feed-expert">{lesson.emoji} {lesson.expert}</span>
            </div>
            <div className="feed-content">
                <div className="feed-command">
                    <span className="cmd-prompt">$</span>
                    <code>{lesson.command}</code>
                </div>
                <div className="feed-explanation">
                    {lesson.lesson ? (
                        <div dangerouslySetInnerHTML={{ __html: lesson.lesson.replace(/\n/g, '<br/>').replace(/## (.*)/g, '<strong>$1</strong>') }} />
                    ) : (
                        <span className="typing">Decyphering methodology...</span>
                    )}
                </div>
            </div>
        </div>
    );
};

const HexStrikeExperts = () => {
    const [experts, setExperts] = useState({});
    const [selectedExpert, setSelectedExpert] = useState(null);
    const [question, setQuestion] = useState('');
    const [response, setResponse] = useState(null);
    const [loading, setLoading] = useState(false);
    const [activeCategory, setActiveCategory] = useState(null);
    const [currentCmdIdx, setCurrentCmdIdx] = useState(0);

    useEffect(() => {
        setCurrentCmdIdx(0);
    }, [response]);

    useEffect(() => {
        fetchExperts();
    }, []);

    const fetchExperts = async () => {
        try {
            const res = await apiService.get('/api/hexstrike-experts/categories');
            // apiService returns JSON directly, not wrapped in .data
            const data = res || {};
            setExperts(data);
            // Set first category as active
            const categories = Object.keys(data);
            if (categories.length > 0) {
                setActiveCategory(categories[0]);
            }
        } catch (err) {
            console.error('[HexStrikeExperts] Fetch error:', err);
            setExperts({});
        }
    };

    const consultExpert = async () => {
        if (!selectedExpert || !question.trim()) return;

        setLoading(true);
        setResponse(null);

        try {
            const res = await apiService.post('/api/hexstrike-experts/consult', {
                toolId: selectedExpert.id,
                question: question,
                context: {}
            });
            setResponse(res);
        } catch (err) {
            setResponse({ error: err.message });
        } finally {
            setLoading(false);
        }
    };

    const categories = Object.keys(experts || {});

    return (
        <div className="hexstrike-experts">
            <div className="hex-header">
                <div className="hex-logo">🔥</div>
                <div className="header-text">
                    <h1>HexStrike Expert Agents</h1>
                    <p className="hex-subtitle">35 Tool-Specialized Security Experts</p>
                </div>
            </div>

            {/* LIVE FEED INTEGRATION */}
            <LiveMonitorDisplay />

            {/* Category Tabs */}
            <div className="hex-categories">
                {categories.map(cat => (
                    <button
                        key={cat}
                        className={`hex-cat-btn ${activeCategory === cat ? 'active' : ''}`}
                        onClick={() => setActiveCategory(cat)}
                    >
                        {cat}
                        <span className="cat-count">{experts[cat]?.length || 0}</span>
                    </button>
                ))}
            </div>

            {/* Expert Grid */}
            <div className="hex-grid">
                {activeCategory && experts[activeCategory]?.map(expert => (
                    <div
                        key={expert.id}
                        className={`hex-expert-card ${selectedExpert?.id === expert.id ? 'selected' : ''}`}
                        onClick={() => setSelectedExpert(expert)}
                    >
                        <span className="expert-emoji">{expert.emoji}</span>
                        <div className="expert-info">
                            <h3>{expert.name}</h3>
                            <code>{expert.tool}</code>
                        </div>
                    </div>
                ))}
            </div>

            {/* Consultation Panel */}
            {selectedExpert && (
                <div className="hex-consult-panel">
                    <div className="consult-header">
                        <span className="consult-emoji">{selectedExpert.emoji}</span>
                        <div>
                            <h2>{selectedExpert.name}</h2>
                            <p>Expert: <code>{selectedExpert.tool}</code></p>
                        </div>
                    </div>

                    <div className="consult-input">
                        <textarea
                            value={question}
                            onChange={(e) => setQuestion(e.target.value)}
                            placeholder={`Ask ${selectedExpert.name} anything about ${selectedExpert.tool}...`}
                            rows={3}
                        />
                        <button
                            onClick={consultExpert}
                            disabled={loading || !question.trim()}
                            className="consult-btn"
                        >
                            {loading ? '⏳ Consulting...' : '🎯 Consult Expert'}
                        </button>
                    </div>

                    {response && (
                        <div className={`consult-response ${response.error ? 'error' : 'success'}`}>
                            {response.error ? (
                                <div className="response-error">❌ {response.error}</div>
                            ) : (
                                <>
                                    <div className="response-header">
                                        <span>✅ Response from {response.expert}</span>
                                    </div>
                                    <div className="response-content">
                                        <pre>{response.response}</pre>
                                    </div>
                                    {response.commands && response.commands.length > 0 && (
                                        <div className="response-commands">
                                            <div className="commands-header">
                                                <h4>📋 Recommended Tools & Commands</h4>
                                                <span className="cmd-counter">
                                                    Step {currentCmdIdx + 1} of {response.commands.length}
                                                </span>
                                            </div>

                                            <div className="command-stepper-container">
                                                <div className="stepper-content">
                                                    <code className="active-command">
                                                        {response.commands[currentCmdIdx]}
                                                    </code>
                                                </div>

                                                <div className="stepper-controls">
                                                    <button
                                                        className="step-btn prev"
                                                        disabled={currentCmdIdx === 0}
                                                        onClick={() => setCurrentCmdIdx(prev => Math.max(0, prev - 1))}
                                                    >
                                                        ⬅️ Précédent
                                                    </button>

                                                    {/* Manual Download / Action Indicator */}
                                                    <div className="manual-action-hint">
                                                        {response.commands[currentCmdIdx].includes('wget') || response.commands[currentCmdIdx].includes('curl') || response.commands[currentCmdIdx].includes('git clone')
                                                            ? '⚠️ Download Detected: Execute Manually'
                                                            : 'Ready to Execute'}
                                                    </div>

                                                    <button
                                                        className="step-btn next"
                                                        disabled={currentCmdIdx === response.commands.length - 1}
                                                        onClick={() => setCurrentCmdIdx(prev => Math.min(response.commands.length - 1, prev + 1))}
                                                    >
                                                        Suivant ➡️
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                </>
                            )}
                        </div>
                    )}
                </div>
            )}

            {/* Stats Footer */}
            <div className="hex-stats">
                <div className="stat">
                    <span className="stat-value">{categories.length}</span>
                    <span className="stat-label">Categories</span>
                </div>
                <div className="stat">
                    <span className="stat-value">
                        {Object.values(experts || {}).reduce((sum, arr) => sum + (arr?.length || 0), 0)}
                    </span>
                    <span className="stat-label">Experts</span>
                </div>
                <div className="stat">
                    <span className="stat-value">🔐</span>
                    <span className="stat-label">AES-256</span>
                </div>
            </div>
        </div>
    );
};

export default HexStrikeExperts;
