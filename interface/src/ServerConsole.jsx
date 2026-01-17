import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import {
    Terminal, X, Maximize2, Minimize2,
    ChevronDown, ChevronUp, Trash2, GripHorizontal,
    Wifi, Server, AlertTriangle, CheckCircle
} from 'lucide-react';
import { API_URL } from './config';
import api from './services/apiService';
import { io } from 'socket.io-client';

/**
 * ServerConsole Component - DRAGGABLE VERSION
 * Displays real-time server logs via WebSocket
 * Can be dragged and positioned anywhere on screen
 */

const ServerConsole = ({ initialExpanded = false }) => {
    const [logs, setLogs] = useState([]);
    const [expanded, setExpanded] = useState(initialExpanded);
    const [minimized, setMinimized] = useState(true);
    const [filter, setFilter] = useState('all');
    const [autoScroll, setAutoScroll] = useState(true);
    const [, setConnected] = useState(false); // Used for status tracking
    const [socketConnected, setSocketConnected] = useState(false);

    // Drag state
    const [position, setPosition] = useState({ x: 20, y: window.innerHeight - 470 });
    const [isDragging, setIsDragging] = useState(false);
    const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });

    const logEndRef = useRef(null);
    const socketRef = useRef(null);
    const consoleRef = useRef(null);

    // Log types with colors - memoized to prevent re-renders
    const logTypes = useMemo(() => ({
        info: { color: '#22c55e', icon: <CheckCircle size={12} /> },
        warn: { color: '#f59e0b', icon: <AlertTriangle size={12} /> },
        error: { color: '#ef4444', icon: <AlertTriangle size={12} /> },
        system: { color: '#6366f1', icon: <Server size={12} /> },
        network: { color: '#3b82f6', icon: <Wifi size={12} /> },
        default: { color: '#94a3b8', icon: null }
    }), []);

    // Parse log line to extract type
    const parseLogType = useCallback((message) => {
        const lowerMsg = message.toLowerCase();
        if (lowerMsg.includes('[error]') || lowerMsg.includes('error:')) return 'error';
        if (lowerMsg.includes('[warn]') || lowerMsg.includes('warning')) return 'warn';
        if (lowerMsg.includes('[system]') || lowerMsg.includes('[init]')) return 'system';
        if (lowerMsg.includes('[network]') || lowerMsg.includes('[socket]') || lowerMsg.includes('[mcp]')) return 'network';
        if (lowerMsg.includes('[info]') || lowerMsg.includes('✅') || lowerMsg.includes('initialized')) return 'info';
        return 'default';
    }, []);

    // Format log line with colors
    const formatLog = useCallback((logEntry) => {
        const message = logEntry.message || logEntry;
        const type = parseLogType(message);
        const style = logTypes[type] || logTypes.default;

        return {
            id: logEntry.id || Date.now() + Math.random(),
            message,
            timestamp: logEntry.timestamp || new Date().toISOString(),
            level: logEntry.level || 'log',
            type,
            color: style.color,
            icon: style.icon
        };
    }, [parseLogType, logTypes]);

    // Drag handlers
    const handleMouseDown = (e) => {
        if (expanded) return; // Don't drag when expanded
        setIsDragging(true);
        const rect = consoleRef.current?.getBoundingClientRect();
        if (rect) {
            setDragOffset({
                x: e.clientX - rect.left,
                y: e.clientY - rect.top
            });
        }
    };

    const handleMouseMove = useCallback((e) => {
        if (!isDragging) return;

        const newX = Math.max(0, Math.min(e.clientX - dragOffset.x, window.innerWidth - 700));
        const newY = Math.max(0, Math.min(e.clientY - dragOffset.y, window.innerHeight - 450));

        setPosition({ x: newX, y: newY });
    }, [isDragging, dragOffset]);

    const handleMouseUp = useCallback(() => {
        setIsDragging(false);
    }, []);

    // Add/remove mouse event listeners for dragging
    useEffect(() => {
        if (isDragging) {
            window.addEventListener('mousemove', handleMouseMove);
            window.addEventListener('mouseup', handleMouseUp);
        }
        return () => {
            window.removeEventListener('mousemove', handleMouseMove);
            window.removeEventListener('mouseup', handleMouseUp);
        };
    }, [isDragging, handleMouseMove, handleMouseUp]);

    // Add demo logs (defined before useEffect)
    const addDemoLogs = useCallback(() => {
        const demoLogs = [
            { message: '[SYSTEM] Th3 Thirty3 v1.2.1-debug initialized', level: 'log' },
            { message: '[SOCKET] Real-time streaming enabled', level: 'log' }
        ].map((log, idx) => ({
            ...log,
            id: idx,
            timestamp: new Date().toISOString()
        }));
        setLogs(demoLogs.map(log => formatLog(log)));
    }, [formatLog]);

    // Connect to Socket.io for real-time logs
    useEffect(() => {
        const socket = io(API_URL.replace('/api', ''), {
            transports: ['websocket', 'polling'],
            reconnection: true,
            reconnectionDelay: 1000,
            reconnectionAttempts: 10
        });

        socketRef.current = socket;

        socket.on('connect', () => {
            setSocketConnected(true);
            setConnected(true);
        });

        socket.on('disconnect', () => {
            setSocketConnected(false);
        });

        socket.on('server:log', (logEntry) => {
            const formattedLog = formatLog(logEntry);
            setLogs(prev => [...prev.slice(-499), formattedLog]);
        });

        socket.on('server:logs-cleared', () => {
            setLogs([]);
        });

        const fetchInitialLogs = async () => {
            try {
                const data = await api.get('/api/logs/recent?limit=100');
                if (data.logs?.length > 0) {
                    setLogs(data.logs.map(log => formatLog(log)));
                }
                setConnected(true);
            } catch {
                addDemoLogs();
            }
        };

        fetchInitialLogs();

        return () => socket.disconnect();
    }, [formatLog, addDemoLogs]);

    // Auto-scroll
    useEffect(() => {
        if (autoScroll && logEndRef.current && !minimized) {
            logEndRef.current.scrollIntoView({ behavior: 'smooth' });
        }
    }, [logs, autoScroll, minimized]);

    const filteredLogs = filter === 'all' ? logs : logs.filter(log => log.type === filter);

    const clearLogs = async () => {
        try { await api.delete('/api/logs/clear'); } catch { /* Ignore */ }
        setLogs([]);
    };

    // Minimized view
    if (minimized) {
        return (
            <div
                onClick={() => setMinimized(false)}
                style={{
                    position: 'fixed',
                    bottom: '20px',
                    left: '20px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    padding: '0.75rem 1rem',
                    background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.95), rgba(15, 23, 42, 0.98))',
                    border: socketConnected ? '1px solid rgba(34, 197, 94, 0.4)' : '1px solid rgba(99, 102, 241, 0.3)',
                    borderRadius: '12px',
                    cursor: 'pointer',
                    zIndex: 9999,
                    backdropFilter: 'blur(10px)',
                    boxShadow: '0 4px 20px rgba(0, 0, 0, 0.5)'
                }}
                title="Ouvrir la console"
            >
                <Terminal size={18} style={{ color: socketConnected ? '#22c55e' : '#6366f1' }} />
                <span style={{ color: '#e2e8f0', fontSize: '0.8rem', fontFamily: 'monospace' }}>Console</span>
                <div style={{
                    width: '8px', height: '8px', borderRadius: '50%',
                    background: socketConnected ? '#22c55e' : '#f59e0b',
                    animation: 'pulse 2s infinite'
                }} />
                {logs.length > 0 && (
                    <span style={{ color: '#64748b', fontSize: '0.7rem', background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: '4px' }}>
                        {logs.length}
                    </span>
                )}
                <ChevronUp size={14} style={{ color: '#94a3b8' }} />
            </div>
        );
    }

    // Full console view
    return (
        <div
            ref={consoleRef}
            style={{
                position: 'fixed',
                top: expanded ? 0 : position.y,
                left: expanded ? 0 : position.x,
                width: expanded ? '100%' : '700px',
                height: expanded ? '100vh' : '450px',
                background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.98), rgba(0, 0, 0, 0.99))',
                border: expanded ? 'none' : '1px solid rgba(99, 102, 241, 0.3)',
                borderRadius: expanded ? '0' : '16px',
                overflow: 'hidden',
                zIndex: 9999,
                display: 'flex',
                flexDirection: 'column',
                backdropFilter: 'blur(20px)',
                boxShadow: '0 8px 40px rgba(0, 0, 0, 0.6)',
                cursor: isDragging ? 'grabbing' : 'default'
            }}
        >
            {/* Draggable Header */}
            <div
                onMouseDown={handleMouseDown}
                style={{
                    padding: '0.75rem 1rem',
                    background: socketConnected
                        ? 'linear-gradient(90deg, rgba(34, 197, 94, 0.2), rgba(99, 102, 241, 0.2))'
                        : 'linear-gradient(90deg, rgba(99, 102, 241, 0.2), rgba(139, 92, 246, 0.2))',
                    borderBottom: '1px solid rgba(99, 102, 241, 0.3)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    cursor: expanded ? 'default' : 'grab',
                    userSelect: 'none'
                }}
            >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    {!expanded && <GripHorizontal size={16} style={{ color: '#64748b' }} />}
                    <Terminal size={18} style={{ color: socketConnected ? '#22c55e' : '#6366f1' }} />
                    <span style={{ color: '#f8fafc', fontWeight: 'bold', fontSize: '0.9rem', fontFamily: 'monospace' }}>
                        Server Console {socketConnected ? '(LIVE)' : ''}
                    </span>
                    <div style={{
                        width: '8px', height: '8px', borderRadius: '50%',
                        background: socketConnected ? '#22c55e' : '#f59e0b',
                        animation: socketConnected ? 'pulse 1s infinite' : 'none'
                    }} />
                    <span style={{ color: '#64748b', fontSize: '0.75rem' }}>
                        {logs.length} logs
                    </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <select
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                        style={{
                            padding: '0.25rem 0.5rem', background: 'rgba(0, 0, 0, 0.3)',
                            border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '6px',
                            color: '#94a3b8', fontSize: '0.7rem', cursor: 'pointer'
                        }}
                    >
                        <option value="all">Tous</option>
                        <option value="system">Système</option>
                        <option value="info">Info</option>
                        <option value="warn">Warnings</option>
                        <option value="error">Erreurs</option>
                        <option value="network">Réseau</option>
                    </select>

                    <button onClick={() => setAutoScroll(!autoScroll)} style={{
                        padding: '0.25rem 0.5rem',
                        background: autoScroll ? 'rgba(34, 197, 94, 0.2)' : 'rgba(0, 0, 0, 0.3)',
                        border: autoScroll ? '1px solid rgba(34, 197, 94, 0.3)' : '1px solid rgba(148, 163, 184, 0.2)',
                        borderRadius: '6px', color: autoScroll ? '#22c55e' : '#94a3b8', fontSize: '0.7rem', cursor: 'pointer'
                    }}>Auto↓</button>

                    <button onClick={clearLogs} style={{
                        padding: '0.25rem', background: 'rgba(239, 68, 68, 0.1)',
                        border: '1px solid rgba(239, 68, 68, 0.2)', borderRadius: '6px',
                        color: '#ef4444', cursor: 'pointer', display: 'flex', alignItems: 'center'
                    }}><Trash2 size={14} /></button>

                    <button onClick={() => setExpanded(!expanded)} style={{
                        padding: '0.25rem', background: 'rgba(255, 255, 255, 0.05)',
                        border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '6px',
                        color: '#94a3b8', cursor: 'pointer', display: 'flex', alignItems: 'center'
                    }}>{expanded ? <Minimize2 size={14} /> : <Maximize2 size={14} />}</button>

                    <button onClick={() => setMinimized(true)} style={{
                        padding: '0.25rem', background: 'rgba(255, 255, 255, 0.05)',
                        border: '1px solid rgba(148, 163, 184, 0.2)', borderRadius: '6px',
                        color: '#94a3b8', cursor: 'pointer', display: 'flex', alignItems: 'center'
                    }}><ChevronDown size={14} /></button>

                    <button onClick={() => setMinimized(true)} style={{
                        padding: '0.25rem', background: 'rgba(239, 68, 68, 0.1)',
                        border: '1px solid rgba(239, 68, 68, 0.2)', borderRadius: '6px',
                        color: '#ef4444', cursor: 'pointer', display: 'flex', alignItems: 'center'
                    }}><X size={14} /></button>
                </div>
            </div>

            {/* Log content */}
            <div style={{
                flex: 1, overflowY: 'auto', padding: '0.5rem',
                fontFamily: 'Consolas, Monaco, monospace', fontSize: '0.75rem', lineHeight: '1.6',
                background: 'rgba(0, 0, 0, 0.3)'
            }}>
                {filteredLogs.length === 0 ? (
                    <div style={{ color: '#64748b', textAlign: 'center', padding: '2rem', fontStyle: 'italic' }}>
                        {socketConnected ? '⏳ En attente de logs...' : 'Connexion...'}
                    </div>
                ) : (
                    filteredLogs.map((log) => (
                        <div key={log.id} style={{
                            display: 'flex', alignItems: 'flex-start', gap: '0.5rem',
                            padding: '0.25rem 0.5rem', borderBottom: '1px solid rgba(148, 163, 184, 0.05)'
                        }}>
                            <span style={{ color: '#475569', flexShrink: 0, fontSize: '0.65rem' }}>
                                {new Date(log.timestamp).toLocaleTimeString('fr-FR')}
                            </span>
                            {log.icon && <span style={{ color: log.color, flexShrink: 0 }}>{log.icon}</span>}
                            <span style={{ color: log.color, wordBreak: 'break-word' }}>{log.message}</span>
                        </div>
                    ))
                )}
                <div ref={logEndRef} />
            </div>

            {/* Footer */}
            <div style={{
                padding: '0.5rem 1rem', background: 'rgba(0, 0, 0, 0.4)',
                borderTop: '1px solid rgba(148, 163, 184, 0.1)',
                display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: '#64748b'
            }}>
                <span>{socketConnected ? '🟢 WebSocket LIVE' : '🟡 Polling'} | Drag to move</span>
                <span>Th3 Thirty3 Console</span>
            </div>

            <style>{`@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }`}</style>
        </div>
    );
};

export default ServerConsole;
