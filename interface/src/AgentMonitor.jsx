import React, { useEffect, useState, useRef, useCallback } from 'react';
import { io } from 'socket.io-client';
import { Terminal, Activity, Cpu, Shield, RotateCcw } from 'lucide-react';

const AgentMonitor = () => {
    const [logs, setLogs] = useState([]);
    const [status, setStatus] = useState("Idle");
    const [activeTool, setActiveTool] = useState(null);
    const logsEndRef = useRef(null);
    const socketRef = useRef(null);

    const addLog = (type, message) => {
        setLogs(prev => [...prev.slice(-50), { type, message, timestamp: new Date() }]);
    };

    const handleReset = (e) => {
        e.stopPropagation(); // Prevent drag
        setLogs([]);
        setStatus("Idle");
        setActiveTool(null);
        addLog('SYSTEM', 'Monitor reset.');
    };

    useEffect(() => {
        // Connect to Socket.io
        socketRef.current = io('http://localhost:3000');

        socketRef.current.on('connect', () => {
            addLog('SYSTEM', 'Connected to Neural Network');
        });

        socketRef.current.on('agent:start', (data) => {
            setStatus("Processing");
            addLog('AGENT', `Starting generation [${data.model}]`);
        });

        socketRef.current.on('agent:thought', (data) => {
            addLog('THOUGHT', data.thought);
        });

        socketRef.current.on('agent:tool', (data) => {
            setActiveTool(data.toolName);
            addLog('TOOL', `Executing: ${data.toolName}`);
            setTimeout(() => setActiveTool(null), 3000);
        });

        socketRef.current.on('agent:end', () => {
            setStatus("Idle");
            addLog('AGENT', 'Task completed');
        });

        socketRef.current.on('agent:status', (data) => {
            setStatus(data.status);
        });

        return () => {
            if (socketRef.current) socketRef.current.disconnect();
        };
    }, []);

    useEffect(() => {
        logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [logs]);

    // Dragging Logic
    const [position, setPosition] = useState({ x: window.innerWidth - 400, y: window.innerHeight - 300 });
    const [isDragging, setIsDragging] = useState(false);
    const dragOffset = useRef({ x: 0, y: 0 });

    const handleMouseDown = useCallback((e) => {
        setIsDragging(true);
        dragOffset.current = {
            x: e.clientX - position.x,
            y: e.clientY - position.y
        };
    }, [position]);

    const handleMouseMove = useCallback((e) => {
        if (isDragging) {
            setPosition({
                x: e.clientX - dragOffset.current.x,
                y: e.clientY - dragOffset.current.y
            });
        }
    }, [isDragging]);

    const handleMouseUp = useCallback(() => {
        setIsDragging(false);
    }, []);

    useEffect(() => {
        if (isDragging) {
            window.addEventListener('mousemove', handleMouseMove);
            window.addEventListener('mouseup', handleMouseUp);
        } else {
            window.removeEventListener('mousemove', handleMouseMove);
            window.removeEventListener('mouseup', handleMouseUp);
        }
        return () => {
            window.removeEventListener('mousemove', handleMouseMove);
            window.removeEventListener('mouseup', handleMouseUp);
        };
    }, [isDragging, handleMouseMove, handleMouseUp]);

    return (
        <div
            className="fixed w-96 bg-black/90 border border-cyan-500/50 rounded-lg shadow-2xl overflow-hidden backdrop-blur-md z-50 font-mono text-xs"
            style={{ left: position.x, top: position.y, cursor: isDragging ? 'grabbing' : 'auto' }}
        >
            {/* Header - Draggable Handle */}
            <div
                className="bg-gray-900/80 p-2 border-b border-cyan-900 flex justify-between items-center cursor-grab active:cursor-grabbing select-none"
                onMouseDown={handleMouseDown}
            >
                <div className="flex items-center gap-2 text-cyan-400 pointer-events-none">
                    <Activity size={14} className={status !== 'Idle' ? 'animate-pulse' : ''} />
                    <span className="font-bold tracking-wider">AGENT MONITOR</span>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        onMouseDown={handleReset}
                        onClick={handleReset}
                        className="text-gray-500 hover:text-red-400 transition-colors"
                        title="Reset Monitor"
                    >
                        <RotateCcw size={12} />
                    </button>
                    <div className={`px-2 py-0.5 rounded text-[10px] font-bold ${status === 'Idle' ? 'bg-gray-800 text-gray-400' : 'bg-cyan-900 text-cyan-300 animate-pulse'}`}>
                        {status.toUpperCase()}
                    </div>
                </div>
            </div>

            {/* Active Tool Overlay */}
            {activeTool && (
                <div className="bg-cyan-900/20 p-2 border-b border-cyan-900/50 flex items-center gap-2 text-cyan-300 animate-in slide-in-from-top duration-300">
                    <Cpu size={14} className="animate-spin-slow" />
                    <span>Using: {activeTool}</span>
                </div>
            )}

            {/* Logs Area */}
            <div className="h-48 overflow-y-auto p-2 space-y-1 scrollbar-thin scrollbar-thumb-cyan-900" onMouseDown={(e) => e.stopPropagation()}>
                {logs.map((log, i) => (
                    <div key={i} className="flex gap-2 text-gray-300">
                        <span className="text-gray-600">[{log.timestamp.toLocaleTimeString().split(' ')[0]}]</span>
                        <span className={`font-bold ${log.type === 'SYSTEM' ? 'text-green-500' :
                            log.type === 'AGENT' ? 'text-blue-400' :
                                log.type === 'TOOL' ? 'text-yellow-400' :
                                    'text-gray-400'
                            }`}>
                            {log.type}:
                        </span>
                        <span className="break-words">{log.message}</span>
                    </div>
                ))}
                <div ref={logsEndRef} />
            </div>

            {/* Footer */}
            <div className="bg-gray-900/80 p-1 text-[10px] text-gray-500 text-center border-t border-gray-800 flex justify-center gap-4 select-none" onMouseDown={handleMouseDown}>
                <span className="flex items-center gap-1"><Shield size={10} /> SECURE</span>
                <span className={`flex items-center gap-1 transition-colors ${status.includes('Private Web') ? 'text-green-400 animate-pulse' : ''}`}>
                    <Terminal size={10} /> {status.includes('Private Web') ? 'PRIVATE WEB ACTIVE' : 'SOCKET.IO'}
                </span>
            </div>
        </div>
    );
};

export default AgentMonitor;
