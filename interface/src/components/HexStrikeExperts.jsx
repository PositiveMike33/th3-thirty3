/**
 * HexStrikeExperts.jsx
 * 
 * Dashboard component for HexStrike tool experts visualization and interaction
 */

import React, { useState, useEffect } from 'react';
import apiService from '../services/apiService';
import './HexStrikeExperts.css';

const HexStrikeExperts = () => {
    const [experts, setExperts] = useState({});
    const [selectedExpert, setSelectedExpert] = useState(null);
    const [question, setQuestion] = useState('');
    const [response, setResponse] = useState(null);
    const [loading, setLoading] = useState(false);
    const [activeCategory, setActiveCategory] = useState(null);

    useEffect(() => {
        fetchExperts();
    }, []);

    const fetchExperts = async () => {
        try {
            const res = await apiService.get('/api/hexstrike-experts/categories');
            setExperts(res.data);
            // Set first category as active
            const categories = Object.keys(res.data);
            if (categories.length > 0) {
                setActiveCategory(categories[0]);
            }
        } catch (err) {
            console.error('[HexStrikeExperts] Fetch error:', err);
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
            setResponse(res.data);
        } catch (err) {
            setResponse({ error: err.message });
        } finally {
            setLoading(false);
        }
    };

    const categories = Object.keys(experts);

    return (
        <div className="hexstrike-experts">
            <div className="hex-header">
                <div className="hex-logo">🔥</div>
                <h1>HexStrike Expert Agents</h1>
                <p className="hex-subtitle">35 Tool-Specialized Security Experts</p>
            </div>

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
                                    {response.commands && (
                                        <div className="response-commands">
                                            <h4>📋 Quick Commands</h4>
                                            {response.commands.map((cmd, i) => (
                                                <code key={i}>{cmd}</code>
                                            ))}
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
                        {Object.values(experts).reduce((sum, arr) => sum + arr.length, 0)}
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
