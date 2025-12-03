import React, { useState, useEffect } from 'react';
import { Globe, Server, User, Shield, Terminal, AlertTriangle } from 'lucide-react';

const API_URL = 'http://localhost:3000';

const OsintDashboard = () => {
    const [tools, setTools] = useState([]);
    const [selectedTool, setSelectedTool] = useState(null);
    const [target, setTarget] = useState("");
    const [output, setOutput] = useState("");
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        fetch(`${API_URL}/osint/tools`)
            .then(res => res.json())
            .then(data => {
                setTools(data);
                if (data.length > 0) setSelectedTool(data[0].id);
            })
            .catch(err => console.error("Failed to load tools:", err));
    }, []);

    const handleRun = async () => {
        if (!target || !selectedTool) return;
        setLoading(true);
        setOutput(prev => prev + `\n> Running ${selectedTool} on ${target}...\n`);

        try {
            const res = await fetch(`${API_URL}/osint/run`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ toolId: selectedTool, target })
            });
            const data = await res.json();
            setOutput(prev => prev + data.result + "\n\n");
        } catch (error) {
            setOutput(prev => prev + `[ERROR] ${error.message}\n\n`);
        }
        setLoading(false);
    };

    return (
        <div className="flex h-full bg-black text-green-400 font-mono p-6 gap-6 bg-[url('/grid.png')]">

            {/* Sidebar / Tool Selection */}
            <div className="w-64 flex flex-col gap-4">
                <div className="flex items-center gap-2 text-green-500 mb-4 border-b border-green-900 pb-2">
                    <Shield size={24} />
                    <h1 className="text-xl font-bold tracking-widest">OSINT OPS</h1>
                </div>

                <div className="flex flex-col gap-2">
                    {tools.map(tool => (
                        <button
                            key={tool.id}
                            onClick={() => setSelectedTool(tool.id)}
                            className={`text-left p-3 rounded border transition-all flex items-center gap-3 ${selectedTool === tool.id
                                ? 'bg-green-900/30 border-green-500 text-green-300'
                                : 'bg-gray-900/30 border-gray-800 text-gray-500 hover:border-green-700 hover:text-green-400'
                                }`}
                        >
                            {tool.id === 'whois' && <Globe size={16} />}
                            {tool.id === 'nslookup' && <Server size={16} />}
                            {tool.id === 'sherlock' && <User size={16} />}
                            {tool.id === 'ping' && <ActivityIcon />}
                            <div>
                                <div className="font-bold text-sm uppercase">{tool.name}</div>
                                <div className="text-[10px] opacity-70">{tool.description}</div>
                            </div>
                        </button>
                    ))}
                </div>

                <div className="mt-auto p-4 bg-red-900/10 border border-red-900/30 rounded text-xs text-red-400 flex gap-2">
                    <AlertTriangle size={16} className="shrink-0" />
                    <p>Authorized use only. All actions are logged.</p>
                </div>
            </div>

            {/* Main Terminal Area */}
            <div className="flex-1 flex flex-col gap-4">

                {/* Input Bar */}
                <div className="bg-gray-900/50 border border-green-900 p-4 rounded-lg flex gap-4 items-center">
                    <Terminal size={20} className="text-green-600" />
                    <input
                        type="text"
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && handleRun()}
                        placeholder="Enter target (IP, Domain, Username)..."
                        className="flex-1 bg-transparent border-none outline-none text-green-300 placeholder-green-900"
                    />
                    <button
                        onClick={handleRun}
                        disabled={loading}
                        className="bg-green-900/30 hover:bg-green-800 text-green-300 px-6 py-2 rounded border border-green-700 disabled:opacity-50"
                    >
                        {loading ? 'EXECUTING...' : 'RUN SCAN'}
                    </button>
                </div>

                {/* Output Console */}
                <div className="flex-1 bg-black border border-gray-800 rounded-lg p-4 overflow-y-auto font-mono text-sm shadow-inner shadow-black">
                    <pre className="whitespace-pre-wrap text-green-500/80">
                        {output || "// OSINT Console Ready...\n// Select a tool and enter a target to begin."}
                    </pre>
                </div>
            </div>
        </div>
    );
};

const ActivityIcon = () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
    </svg>
);

export default OsintDashboard;
