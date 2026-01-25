import React, { useState, useEffect } from 'react';
import { Globe, Server, User, Terminal, Map, Shield } from 'lucide-react';
import { API_URL } from './config';
import WWTMapComponent from './components/WWTMapComponent';

const OsintDashboard = () => {
    const [tools, setTools] = useState([]);
    const [selectedTool, setSelectedTool] = useState(null);
    const [target, setTarget] = useState("");
    const [loading, setLoading] = useState(false);
    const [activeTab, setActiveTab] = useState('framework'); // Default to Framework (MindMap)

    // Spiderfoot Status
    const [spiderfootStatus, setSpiderfootStatus] = useState("Unknown");

    // Initialize
    useEffect(() => {
        const defaultTools = [
            { id: 'sherlock', name: 'Sherlock', description: 'Usernames Search' },
            { id: 'theharvester', name: 'TheHarvester', description: 'Emails/Subdomains' },
            { id: 'nslookup', name: 'NSLookup', description: 'DNS Records' },
            { id: 'whois', name: 'Whois', description: 'Domain Info' }
        ];

        fetch(`${API_URL}/osint/tools`)
            .then(res => res.json())
            .then(data => {
                const toolsArray = Array.isArray(data) ? data : (data.tools || []);
                setTools(toolsArray.length > 0 ? toolsArray : defaultTools);
                if (toolsArray.length > 0) setSelectedTool(toolsArray[0].id);
            })
            .catch(err => {
                console.warn("Failed to load tools, using defaults");
                setTools(defaultTools);
                setSelectedTool(defaultTools[0].id);
            });

        checkSpiderfootStatus();
    }, []);

    // --- Logging Helper ---
    // Sends output to the GLOBAL AgentMonitor (bottom left corner)
    const logOutput = (message, type = 'TOOL') => {
        window.dispatchEvent(new CustomEvent('agent-log', {
            detail: { message, type }
        }));
    };

    // --- Actions ---

    const checkSpiderfootStatus = async () => {
        try {
            const res = await fetch(`${API_URL}/osint/spiderfoot/status`);
            const data = await res.json();
            setSpiderfootStatus(data.status);
        } catch {
            setSpiderfootStatus("Error");
        }
    };

    const toggleSpiderfoot = async (action) => {
        logOutput(`[SPIDERFOOT] Requesting ${action}...`, 'SYSTEM');
        try {
            const res = await fetch(`${API_URL}/osint/spiderfoot/${action}`, { method: 'POST' });
            const data = await res.json();
            logOutput(`[SPIDERFOOT] ${data.result}`, 'SYSTEM');
            checkSpiderfootStatus();
        } catch (e) {
            logOutput(`[ERROR] Spiderfoot: ${e.message}`, 'SYSTEM');
        }
    };

    const handleRun = async () => {
        if (!target || !selectedTool) {
            logOutput("Please enter a target and select a tool.", 'WARNING');
            return;
        }

        setLoading(true);
        logOutput(`Running ${selectedTool} on ${target}...`, 'TOOL');

        const BRIDGE_API_URL = "http://localhost:8000";

        // Hybrid Logic: Bridge (Python) vs Node API
        if (['sherlock', 'theharvester'].includes(selectedTool)) {
            try {
                let endpoint = selectedTool === 'sherlock' ? "/scan/sherlock" : "/scan/theharvester";
                let payload = selectedTool === 'sherlock' ? { username: target } : { domain: target, limit: 100, source: "all" };

                const response = await fetch(`${BRIDGE_API_URL}${endpoint}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                if (!response.ok) throw new Error(`Bridge Error: ${response.statusText}`);

                const reader = response.body.getReader();
                const decoder = new TextDecoder();

                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    const chunk = decoder.decode(value);
                    // Stream chunks to log (maybe split by line to look better in monitor)
                    const lines = chunk.split('\n');
                    lines.forEach(line => {
                        if (line.trim()) logOutput(line, 'TOOL');
                    });
                }
                logOutput(`[${selectedTool}] Scan Completed.`, 'SUCCESS');

            } catch (err) {
                logOutput(`Bridge connection failed: ${err.message}`, 'ERROR');
                // Fallback or just stop
            }
        } else {
            // Legacy Node.js Tools
            try {
                const res = await fetch(`${API_URL}/osint/run`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ toolId: selectedTool, target })
                });
                const data = await res.json();
                const result = data.result || data.error || 'No output';
                logOutput(result, 'TOOL');
            } catch (err) {
                logOutput(`API Error: ${err.message}`, 'ERROR');
            }
        }
        setLoading(false);
    };

    return (
        <div className="flex h-full w-full bg-black overflow-hidden font-mono">
            {/* 
               LEFT COLUMN (85%) - MAIN VISUALIZATION 
               Includes MindMap (Framework) or WWT Satellite View
            */}
            <div className="flex-[0.85] h-full relative border-r border-green-900/30 overflow-hidden bg-gray-900/10">
                {/* Background Grid */}
                <div className="absolute inset-0 bg-[url('/grid.png')] opacity-5 pointer-events-none"></div>

                {/* Content */}
                {activeTab === 'satellite' ? (
                    <WWTMapComponent />
                ) : (
                    <div className="w-full h-full overflow-y-auto scrollbar-thin scrollbar-thumb-green-900">
                        {/* Header Overlay */}
                        <div className="absolute top-4 left-4 z-10 bg-black/80 border border-green-500/50 px-4 py-2 rounded backdrop-blur-sm pointer-events-none">
                            <h2 className="text-xl font-bold text-green-400 tracking-widest flex items-center gap-2">
                                <Globe size={20} /> GLOBAL INTELLIGENCE MAP
                            </h2>
                            <p className="text-[10px] text-green-600 font-bold uppercase mt-1">
                                OSINT FRAMEWORK VISUALIZER
                            </p>
                        </div>

                        {/* THE MIND MAP IFRAME */}
                        <iframe
                            src="https://osintframework.com/"
                            title="OSINT Framework"
                            className="w-full h-full min-h-[1000px] border-none opacity-90 invert-[0.9] hue-rotate-180 contrast-125 bg-black"
                            style={{ filter: 'invert(1) hue-rotate(180deg) contrast(1.2) brightness(0.8)' }}
                        />
                    </div>
                )}
            </div>

            {/* 
               RIGHT COLUMN (15%) - SIDEBAR 
               Tools at top, Containers below.
            */}
            <div className="flex-[0.15] h-full bg-gray-900/40 backdrop-blur-md border-l border-green-500/20 flex flex-col min-w-[200px] z-20 shadow-[-10px_0_20px_rgba(0,0,0,0.5)]">

                {/* TOOLBAR HEADER */}
                <div className="p-3 border-b border-green-900/50 bg-black/40">
                    <div className="flex items-center gap-2 text-green-400 mb-2">
                        <Terminal size={16} />
                        <span className="font-bold tracking-wider text-xs">TOOLS</span>
                    </div>

                    {/* View Switcher */}
                    <div className="flex bg-black/60 p-1 rounded gap-1 mb-2">
                        <button
                            onClick={() => setActiveTab('framework')}
                            className={`flex-1 py-1 text-[10px] uppercase font-bold rounded ${activeTab !== 'satellite' ? 'bg-green-700 text-white' : 'text-gray-500 hover:text-green-300'}`}
                        >
                            MindMap
                        </button>
                        <button
                            onClick={() => setActiveTab('satellite')}
                            className={`flex-1 py-1 text-[10px] uppercase font-bold rounded ${activeTab === 'satellite' ? 'bg-blue-700 text-white' : 'text-gray-500 hover:text-blue-300'}`}
                        >
                            Sat-View
                        </button>
                    </div>

                    {/* Target Input */}
                    <div className="space-y-1">
                        <input
                            type="text"
                            value={target}
                            onChange={(e) => setTarget(e.target.value)}
                            onKeyDown={(e) => e.key === 'Enter' && handleRun()}
                            placeholder="Target (IP/User)"
                            className="w-full bg-black/50 border border-green-800 rounded px-2 py-1 text-green-300 text-xs focus:border-green-500 focus:outline-none"
                        />
                        <button
                            onClick={handleRun}
                            disabled={loading}
                            className="w-full bg-green-800/80 hover:bg-green-700 text-white py-1 rounded text-xs font-bold disabled:opacity-50"
                        >
                            {loading ? 'SCANNING...' : 'RUN SCAN'}
                        </button>
                    </div>
                </div>

                {/* TOOLS LIST (Scrollable) */}
                <div className="flex-1 overflow-y-auto p-3 space-y-2 scrollbar-thin scrollbar-thumb-green-900">
                    <label className="text-[10px] text-gray-500 font-bold uppercase">Available Utilities</label>
                    {tools.map(tool => (
                        <button
                            key={tool.id}
                            onClick={() => setSelectedTool(tool.id)}
                            className={`w-full text-left p-2 rounded border text-xs transition-all ${selectedTool === tool.id
                                ? 'bg-green-900/40 border-green-500 text-green-300'
                                : 'bg-transparent border-gray-800 text-gray-400 hover:border-green-800'
                                }`}
                        >
                            <div className="font-bold truncate">{tool.name}</div>
                            <div className="text-[9px] opacity-60 truncate">{tool.description}</div>
                        </button>
                    ))}
                </div>

                {/* CONTAINERS STATUS (Fixed at bottom of sidebar) */}
                <div className="p-3 border-t border-green-900/50 bg-black/40">
                    <div className="flex items-center gap-2 text-blue-400 mb-2">
                        <Server size={14} />
                        <span className="font-bold tracking-wider text-[10px]">CONTAINERS</span>
                    </div>

                    {/* Spiderfoot Control */}
                    <div className="bg-gray-900/50 p-2 rounded border border-gray-800 mb-2">
                        <div className="flex justify-between items-center mb-1">
                            <span className="text-[10px] text-gray-400">SpiderFoot</span>
                            <span className={`text-[9px] px-1 rounded ${spiderfootStatus === 'Running' ? 'bg-green-900 text-green-400' : 'bg-red-900 text-red-400'}`}>
                                {spiderfootStatus}
                            </span>
                        </div>
                        <div className="flex gap-1">
                            {spiderfootStatus !== 'Running' ? (
                                <button onClick={() => toggleSpiderfoot('start')} className="flex-1 bg-green-800 py-1 text-[9px] rounded hover:bg-green-700">Start</button>
                            ) : (
                                <button onClick={() => toggleSpiderfoot('stop')} className="flex-1 bg-red-800 py-1 text-[9px] rounded hover:bg-red-700">Stop</button>
                            )}
                            {spiderfootStatus === 'Running' && (
                                <a href="http://localhost:5001" target="_blank" rel="noopener noreferrer" className="flex-1 bg-blue-800 py-1 text-[9px] rounded text-center hover:bg-blue-700">Open</a>
                            )}
                        </div>
                    </div>

                    {/* Placeholder for other containers */}
                    <div className="bg-gray-900/30 p-2 rounded border border-gray-800 opacity-50">
                        <div className="flex justify-between items-center">
                            <span className="text-[10px] text-gray-500">Maltego (Stub)</span>
                            <div className="w-2 h-2 rounded-full bg-gray-600"></div>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    );
};

export default OsintDashboard;
