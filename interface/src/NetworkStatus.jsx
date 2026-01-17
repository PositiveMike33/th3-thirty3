import React, { useState, useEffect, useCallback } from 'react';
import {
    Wifi, WifiOff, Cloud, Server, AlertTriangle,
    RefreshCw, Activity, Zap, Globe, HardDrive, ArrowRightLeft
} from 'lucide-react';
import { API_URL } from './config';
import api from './services/apiService';

/**
 * NetworkStatus Component - RISK-006 Mitigation UI
 * Displays network connectivity status and failover state
 * Allows manual control of cloud/local model switching
 */

const NetworkStatus = ({ compact = false, onStatusChange }) => {
    const [status, setStatus] = useState({
        state: 'UNKNOWN',
        mode: 'AUTO',
        isOnline: false,
        isOllamaAvailable: false,
        failoverActive: false,
        lastCheck: null,
        stats: { uptime: 100, failovers: 0, recoveries: 0 }
    });
    const [loading, setLoading] = useState(true);
    const [showDetails, setShowDetails] = useState(false);
    const [error, setError] = useState(null);

    // Fetch network status from backend
    const fetchStatus = useCallback(async () => {
        try {
            const data = await api.get('/api/network/status');
            setStatus(data);
            setError(null);
            if (onStatusChange) {
                onStatusChange(data);
            }
        } catch {
            setError('Network monitor unavailable');
            // Try to detect connectivity locally
            const online = navigator.onLine;
            setStatus(prev => ({
                ...prev,
                isOnline: online,
                state: online ? 'ONLINE' : 'OFFLINE'
            }));
        } finally {
            setLoading(false);
        }
    }, [onStatusChange]);

    // Set failover mode
    const setMode = async (mode) => {
        try {
            await api.post('/api/network/mode', { mode });
            fetchStatus();
        } catch (err) {
            console.error('Failed to set mode:', err);
        }
    };

    // Force failover (for testing)
    const handleForceFailover = async () => {
        try {
            await api.post('/api/network/force-failover', {});
            fetchStatus();
        } catch (err) {
            console.error('Failed to force failover:', err);
        }
    };

    // Initial fetch and polling
    useEffect(() => {
        fetchStatus();
        const interval = setInterval(fetchStatus, 10000); // Poll every 10s

        // Listen for online/offline events
        const handleOnline = () => {
            setStatus(prev => ({ ...prev, isOnline: true, state: 'ONLINE' }));
            fetchStatus();
        };
        const handleOffline = () => {
            setStatus(prev => ({ ...prev, isOnline: false, state: 'OFFLINE' }));
        };

        window.addEventListener('online', handleOnline);
        window.addEventListener('offline', handleOffline);

        return () => {
            clearInterval(interval);
            window.removeEventListener('online', handleOnline);
            window.removeEventListener('offline', handleOffline);
        };
    }, [fetchStatus]);

    // Get status color and icon
    const getStatusIndicator = () => {
        switch (status.state) {
            case 'ONLINE':
                return {
                    color: '#22c55e',
                    bgColor: 'rgba(34, 197, 94, 0.1)',
                    borderColor: 'rgba(34, 197, 94, 0.3)',
                    icon: <Wifi size={16} />,
                    label: 'En ligne',
                    description: 'Modèles cloud actifs'
                };
            case 'OFFLINE':
                return {
                    color: '#ef4444',
                    bgColor: 'rgba(239, 68, 68, 0.1)',
                    borderColor: 'rgba(239, 68, 68, 0.3)',
                    icon: <WifiOff size={16} />,
                    label: 'Hors ligne',
                    description: 'Basculement local actif'
                };
            case 'DEGRADED':
                return {
                    color: '#f59e0b',
                    bgColor: 'rgba(245, 158, 11, 0.1)',
                    borderColor: 'rgba(245, 158, 11, 0.3)',
                    icon: <AlertTriangle size={16} />,
                    label: 'Dégradé',
                    description: 'Connectivité partielle'
                };
            case 'CHECKING':
                return {
                    color: '#3b82f6',
                    bgColor: 'rgba(59, 130, 246, 0.1)',
                    borderColor: 'rgba(59, 130, 246, 0.3)',
                    icon: <RefreshCw size={16} className="animate-spin" />,
                    label: 'Vérification...',
                    description: 'Test de connectivité'
                };
            default:
                return {
                    color: '#64748b',
                    bgColor: 'rgba(100, 116, 139, 0.1)',
                    borderColor: 'rgba(100, 116, 139, 0.3)',
                    icon: <Activity size={16} />,
                    label: 'Inconnu',
                    description: 'État non déterminé'
                };
        }
    };

    const indicator = getStatusIndicator();

    // Compact mode - just a small indicator
    if (compact) {
        return (
            <div
                onClick={() => setShowDetails(!showDetails)}
                style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    padding: '0.5rem 0.75rem',
                    background: indicator.bgColor,
                    border: `1px solid ${indicator.borderColor}`,
                    borderRadius: '8px',
                    cursor: 'pointer',
                    transition: 'all 0.3s ease'
                }}
                title={`${indicator.label}: ${indicator.description}`}
            >
                <span style={{ color: indicator.color }}>{indicator.icon}</span>
                <span style={{
                    color: indicator.color,
                    fontSize: '0.75rem',
                    fontWeight: 'bold'
                }}>
                    {status.state === 'OFFLINE' ? 'LOCAL' : 'CLOUD'}
                </span>
                {status.state === 'OFFLINE' && (
                    <ArrowRightLeft size={12} style={{ color: '#f59e0b' }} />
                )}
            </div>
        );
    }

    // Full mode - detailed panel
    return (
        <div style={{
            background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.9), rgba(15, 23, 42, 0.95))',
            borderRadius: '16px',
            border: `1px solid ${indicator.borderColor}`,
            overflow: 'hidden'
        }}>
            {/* Header */}
            <div style={{
                padding: '1rem 1.5rem',
                background: indicator.bgColor,
                borderBottom: `1px solid ${indicator.borderColor}`,
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
            }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <div style={{
                        width: '40px',
                        height: '40px',
                        borderRadius: '10px',
                        background: `linear-gradient(135deg, ${indicator.color}40, ${indicator.color}20)`,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: indicator.color
                    }}>
                        {indicator.icon}
                    </div>
                    <div>
                        <h3 style={{
                            color: '#f8fafc',
                            fontWeight: 'bold',
                            fontSize: '1rem',
                            margin: 0
                        }}>
                            État Réseau: {indicator.label}
                        </h3>
                        <p style={{
                            color: '#94a3b8',
                            fontSize: '0.8rem',
                            margin: 0
                        }}>
                            {indicator.description}
                        </p>
                    </div>
                </div>

                <button
                    onClick={fetchStatus}
                    disabled={loading}
                    style={{
                        padding: '0.5rem',
                        background: 'rgba(255, 255, 255, 0.1)',
                        border: 'none',
                        borderRadius: '8px',
                        color: '#94a3b8',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center'
                    }}
                >
                    <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
                </button>
            </div>

            {/* Status indicators */}
            <div style={{
                padding: '1rem 1.5rem',
                display: 'grid',
                gridTemplateColumns: 'repeat(3, 1fr)',
                gap: '1rem'
            }}>
                {/* Internet */}
                <div style={{
                    padding: '0.75rem',
                    background: status.isOnline
                        ? 'rgba(34, 197, 94, 0.1)'
                        : 'rgba(239, 68, 68, 0.1)',
                    borderRadius: '10px',
                    textAlign: 'center'
                }}>
                    <Globe
                        size={24}
                        style={{
                            color: status.isOnline ? '#22c55e' : '#ef4444',
                            marginBottom: '0.5rem'
                        }}
                    />
                    <div style={{
                        color: status.isOnline ? '#22c55e' : '#ef4444',
                        fontSize: '0.75rem',
                        fontWeight: 'bold'
                    }}>
                        INTERNET
                    </div>
                    <div style={{ color: '#94a3b8', fontSize: '0.7rem' }}>
                        {status.isOnline ? 'Connecté' : 'Déconnecté'}
                    </div>
                </div>

                {/* Ollama */}
                <div style={{
                    padding: '0.75rem',
                    background: status.isOllamaAvailable
                        ? 'rgba(34, 197, 94, 0.1)'
                        : 'rgba(239, 68, 68, 0.1)',
                    borderRadius: '10px',
                    textAlign: 'center'
                }}>
                    <HardDrive
                        size={24}
                        style={{
                            color: status.isOllamaAvailable ? '#22c55e' : '#ef4444',
                            marginBottom: '0.5rem'
                        }}
                    />
                    <div style={{
                        color: status.isOllamaAvailable ? '#22c55e' : '#ef4444',
                        fontSize: '0.75rem',
                        fontWeight: 'bold'
                    }}>
                        OLLAMA
                    </div>
                    <div style={{ color: '#94a3b8', fontSize: '0.7rem' }}>
                        {status.isOllamaAvailable ? 'Disponible' : 'Indisponible'}
                    </div>
                </div>

                {/* Current Mode */}
                <div style={{
                    padding: '0.75rem',
                    background: status.state === 'OFFLINE'
                        ? 'rgba(249, 115, 22, 0.1)'
                        : 'rgba(99, 102, 241, 0.1)',
                    borderRadius: '10px',
                    textAlign: 'center'
                }}>
                    {status.state === 'OFFLINE' ? (
                        <Server
                            size={24}
                            style={{ color: '#f97316', marginBottom: '0.5rem' }}
                        />
                    ) : (
                        <Cloud
                            size={24}
                            style={{ color: '#6366f1', marginBottom: '0.5rem' }}
                        />
                    )}
                    <div style={{
                        color: status.state === 'OFFLINE' ? '#f97316' : '#6366f1',
                        fontSize: '0.75rem',
                        fontWeight: 'bold'
                    }}>
                        {status.state === 'OFFLINE' ? 'LOCAL' : 'CLOUD'}
                    </div>
                    <div style={{ color: '#94a3b8', fontSize: '0.7rem' }}>
                        Mode actif
                    </div>
                </div>
            </div>

            {/* Stats */}
            <div style={{
                padding: '0.75rem 1.5rem',
                background: 'rgba(0, 0, 0, 0.2)',
                display: 'flex',
                justifyContent: 'space-around',
                borderTop: '1px solid rgba(148, 163, 184, 0.1)'
            }}>
                <div style={{ textAlign: 'center' }}>
                    <div style={{
                        color: '#22c55e',
                        fontWeight: 'bold',
                        fontSize: '1.25rem'
                    }}>
                        {status.stats?.uptime || 100}%
                    </div>
                    <div style={{ color: '#64748b', fontSize: '0.7rem' }}>Uptime</div>
                </div>
                <div style={{ textAlign: 'center' }}>
                    <div style={{
                        color: '#f97316',
                        fontWeight: 'bold',
                        fontSize: '1.25rem'
                    }}>
                        {status.stats?.failovers || 0}
                    </div>
                    <div style={{ color: '#64748b', fontSize: '0.7rem' }}>Failovers</div>
                </div>
                <div style={{ textAlign: 'center' }}>
                    <div style={{
                        color: '#3b82f6',
                        fontWeight: 'bold',
                        fontSize: '1.25rem'
                    }}>
                        {status.stats?.recoveries || 0}
                    </div>
                    <div style={{ color: '#64748b', fontSize: '0.7rem' }}>Récupérations</div>
                </div>
            </div>

            {/* Mode Controls */}
            <div style={{
                padding: '1rem 1.5rem',
                borderTop: '1px solid rgba(148, 163, 184, 0.1)'
            }}>
                <div style={{
                    color: '#94a3b8',
                    fontSize: '0.75rem',
                    marginBottom: '0.5rem'
                }}>
                    Mode de basculement:
                </div>
                <div style={{
                    display: 'flex',
                    gap: '0.5rem'
                }}>
                    {['AUTO', 'LOCAL_ONLY', 'CLOUD_ONLY'].map(mode => (
                        <button
                            key={mode}
                            onClick={() => setMode(mode)}
                            style={{
                                flex: 1,
                                padding: '0.5rem',
                                background: status.mode === mode
                                    ? 'linear-gradient(135deg, #6366f1, #8b5cf6)'
                                    : 'rgba(255, 255, 255, 0.05)',
                                border: status.mode === mode
                                    ? 'none'
                                    : '1px solid rgba(148, 163, 184, 0.2)',
                                borderRadius: '8px',
                                color: status.mode === mode ? '#fff' : '#94a3b8',
                                fontSize: '0.7rem',
                                fontWeight: 'bold',
                                cursor: 'pointer',
                                transition: 'all 0.3s ease'
                            }}
                        >
                            {mode === 'AUTO' && <Zap size={12} style={{ marginRight: '4px' }} />}
                            {mode === 'LOCAL_ONLY' && <Server size={12} style={{ marginRight: '4px' }} />}
                            {mode === 'CLOUD_ONLY' && <Cloud size={12} style={{ marginRight: '4px' }} />}
                            {mode.replace('_', ' ')}
                        </button>
                    ))}
                </div>
                {/* Test Failover Button */}
                <button
                    onClick={handleForceFailover}
                    style={{
                        marginTop: '0.5rem',
                        padding: '0.5rem',
                        width: '100%',
                        background: 'rgba(239, 68, 68, 0.1)',
                        border: '1px solid rgba(239, 68, 68, 0.3)',
                        borderRadius: '8px',
                        color: '#ef4444',
                        fontSize: '0.7rem',
                        cursor: 'pointer',
                        transition: 'all 0.3s ease'
                    }}
                >
                    🧪 Tester Basculement Local
                </button>
            </div>

            {/* Failover Alert Banner */}
            {status.state === 'OFFLINE' && (
                <div style={{
                    padding: '0.75rem 1.5rem',
                    background: 'linear-gradient(90deg, rgba(249, 115, 22, 0.2), rgba(239, 68, 68, 0.2))',
                    borderTop: '1px solid rgba(249, 115, 22, 0.3)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.75rem'
                }}>
                    <AlertTriangle size={18} style={{ color: '#f97316' }} />
                    <div>
                        <div style={{
                            color: '#f97316',
                            fontWeight: 'bold',
                            fontSize: '0.8rem'
                        }}>
                            ⚡ Mode Secours Actif
                        </div>
                        <div style={{ color: '#94a3b8', fontSize: '0.7rem' }}>
                            Les modèles locaux (Ollama) sont utilisés. Pas de dépendance internet.
                        </div>
                    </div>
                </div>
            )}

            {error && (
                <div style={{
                    padding: '0.5rem 1.5rem',
                    background: 'rgba(239, 68, 68, 0.1)',
                    color: '#ef4444',
                    fontSize: '0.75rem'
                }}>
                    ⚠️ {error}
                </div>
            )}
        </div>
    );
};

export default NetworkStatus;
