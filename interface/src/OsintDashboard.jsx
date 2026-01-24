import React, { useState, useEffect } from 'react';
import { Globe, Server, User, Shield, Terminal, AlertTriangle, Activity, Map } from 'lucide-react';
import { API_URL } from './config';
import WWTMapComponent from './components/WWTMapComponent';
import AgentMonitor from './components/AgentMonitor';

const OsintDashboard = () => {
    const [tools, setTools] = useState([]);
    const [selectedTool, setSelectedTool] = useState(null);
    const [target, setTarget] = useState("");
    const [output, setOutput] = useState("");
    const [loading, setLoading] = useState(false);
    const [activeTab, setActiveTab] = useState('tools'); // tools, spiderfoot, framework, maltego, satellite
    const [spiderfootStatus, setSpiderfootStatus] = useState("Unknown");

    useEffect(() => {
        const defaultTools = [
            { id: 'sherlock', name: 'Sherlock', description: 'Find usernames across social networks' },
            { id: 'theharvester', name: 'TheHarvester', description: 'Gather emails, subdomains, hosts' },
            { id: 'nslookup', name: 'NSLookup', description: 'Query DNS records' },
            { id: 'whois', name: 'Whois', description: 'Domain registration info' }
        ];

        fetch(`${API_URL}/osint/tools`)
            .then(res => res.json())
            .then(data => {
                const toolsArray = Array.isArray(data) ? data : (data.tools || []);
                if (toolsArray.length > 0) {
                    setTools(toolsArray);
                    setSelectedTool(toolsArray[0].id);
                } else {
                    setTools(defaultTools);
                    setSelectedTool(defaultTools[0].id);
                }
            })
            .catch(err => {
                console.warn("Failed to load tools from backend, using defaults:", err);
                setTools(defaultTools);
                setSelectedTool(defaultTools[0].id);
            });

        checkSpiderfootStatus();
    }, []);

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
        setLoading(true);
        try {
            const res = await fetch(`${API_URL}/osint/spiderfoot/${action}`, { method: 'POST' });
            const data = await res.json();
            setOutput(prev => prev + `\n[SPIDERFOOT] ${data.result}\n`);
            checkSpiderfootStatus();
        } catch (e) {
            setOutput(prev => prev + `\n[ERROR] ${e.message}\n`);
        }
        setLoading(false);
    };

    const [analysis, setAnalysis] = useState("");
    const [analyzing, setAnalyzing] = useState(false);

    const BRIDGE_API_URL = "http://localhost:8000";

    const handleRun = async () => {
        if (!target || !selectedTool) {
            setOutput(prev => prev + `\n[WARNING] Please enter a target and select a tool.\n`);
            return;
        }

        setLoading(true);
        setAnalysis(""); // Clear previous analysis
        setOutput(prev => prev + `\n> Running ${selectedTool} on ${target}...\n`);

        // --- NEW: Python Bridge Logic for Specific Tools ---
        if (['sherlock', 'theharvester'].includes(selectedTool)) {
            try {
                let endpoint = "";
                let payload = {};

                if (selectedTool === 'sherlock') {
                    endpoint = "/scan/sherlock";
                    payload = { username: target };
                } else if (selectedTool === 'theharvester') {
                    endpoint = "/scan/theharvester";
                    payload = { domain: target, limit: 100, source: "all" };
                }

                const response = await fetch(`${BRIDGE_API_URL}${endpoint}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                if (!response.ok) throw new Error(`Bridge Error: ${response.statusText}`);

                // Real-time Streaming Reader
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                let toolOutput = "";

                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;

                    const chunk = decoder.decode(value);
                    toolOutput += chunk;

                    // Direct state update for real-time effect
                    setOutput(prev => prev + chunk);
                }

                // Append newline at end
                setOutput(prev => prev + "\n[SCAN COMPLETED]\n\n");

                // Trigger Analysis if successful
                triggerAnalysis(selectedTool, toolOutput);

            } catch (err) {
                console.error("Bridge Connection Error:", err);
                setOutput(prev => prev + `\n[ERROR] Could not connect to OSINT Bridge. Is the Python service running?\n${err.message}\n\n`);
            } finally {
                setLoading(false);
            }
            return; // Exit early, do not run legacy logic
        }

        // --- OLD: Node.js Legacy Logic ---
        try {
            // 1. Run the Tool
            const res = await fetch(`${API_URL}/osint/run`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ toolId: selectedTool, target })
            });

            if (!res.ok) {
                const errorData = await res.json().catch(() => ({}));
                throw new Error(errorData.error || `Server error: ${res.status}`);
            }

            const data = await res.json();
            const toolOutput = data.result || data.error || '[No output received]';
            setOutput(prev => prev + toolOutput + "\n\n");

            if (!toolOutput.includes('[ERROR]')) {
                triggerAnalysis(selectedTool, toolOutput);
            }

        } catch (error) {
            console.error('OSINT Error:', error);
            let errorMessage = error.message;

            if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
                errorMessage = 'Cannot connect to server. Please ensure the backend is running.';
            }

            setOutput(prev => prev + `[ERROR] ${errorMessage}\n\n`);
        }
        setLoading(false);
        setAnalyzing(false);
    };

    // Helper for Analysis (extracted to avoid code duplication)
    const triggerAnalysis = async (tool, outputText) => {
        setAnalyzing(true);
        try {
            const analyzeRes = await fetch(`${API_URL}/osint/analyze`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ toolId: tool, output: outputText })
            });

            if (analyzeRes.ok) {
                const analyzeData = await analyzeRes.json();
                setAnalysis(analyzeData.analysis || 'Analysis completed.');
            }
        } catch (analyzeError) {
            console.warn('Expert analysis unavailable:', analyzeError.message);
        }
        setAnalyzing(false);
    };

    return (
        <div className="flex h-full bg-transparent text-green-400 font-mono overflow-hidden">

            {/* LEFT COLUMN: MAIN DISPLAY (Mindmap/Map) */}
            <div className="flex-1 relative border-r border-green-900/30 bg-black/40">
                {/* Background Grid Effect */}
                <div className="absolute inset-0 bg-[url('/grid.png')] opacity-10 pointer-events-none"></div>

                {/* Content based on Active Tab */}
                {activeTab === 'satellite' ? (
                    <WWTMapComponent />
                ) : (
                    /* Default to Framework/Mindmap */
                    <div className="w-full h-full flex flex-col">
                        <div className="absolute top-4 left-4 z-10 bg-black/80 border border-green-500/50 px-4 py-2 rounded backdrop-blur-sm">
                            <h2 className="text-xl font-bold text-green-400 tracking-widest flex items-center gap-2">
                                <Globe size={20} /> GLOBAL INTELLIGENCE MAP
                            </h2>
                        </div>
                        <iframe
                            src="https://osintframework.com/"
                            title="OSINT Framework"
                            className="w-full h-full border-none opacity-90 invert-[.9] hue-rotate-180 contrast-125" // Cyberpunk filter attempt
                            style={{ filter: 'invert(1) hue-rotate(180deg) contrast(1.2)' }} // Make it look dark mode-ish
                        />
                    </div>
                )}
            </div>

            {/* RIGHT COLUMN: SIDEBAR (Tools & Control) */}
            <div className="w-96 flex flex-col bg-gray-900/80 backdrop-blur-md border-l border-green-500/30 shadow-[-10px_0_20px_rgba(0,0,0,0.5)] z-20">

                {/* Header */}
                <div className="p-4 border-b border-green-900 flex justify-between items-center bg-black/20">
                    <div className="flex items-center gap-2 text-green-500">
                        <Terminal size={20} />
                        <span className="font-bold tracking-widest">COMMAND CENTER</span>
                    </div>
                    <div className="flex gap-1">
                        <div className="w-2 h-2 rounded-full bg-red-500"></div>
                        <div className="w-2 h-2 rounded-full bg-yellow-500"></div>
                        <div className="w-2 h-2 rounded-full bg-green-500"></div>
                    </div>
                </div>

                {/* Navigation Tabs (Compact) */}
                <div className="flex bg-black/40 p-1 gap-1 overflow-x-auto scrollbar-hide border-b border-green-900/30">
                    <TabButton active={activeTab === 'tools'} onClick={() => setActiveTab('tools')} icon={<Terminal size={14} />} />
                    <TabButton active={activeTab === 'framework'} onClick={() => setActiveTab('framework')} icon={<Server size={14} />} />
                    <TabButton active={activeTab === 'spiderfoot'} onClick={() => setActiveTab('spiderfoot')} icon={<Globe size={14} />} />
                    <TabButton active={activeTab === 'maltego'} onClick={() => setActiveTab('maltego')} icon={<User size={14} />} />
                    <TabButton active={activeTab === 'satellite'} onClick={() => setActiveTab('satellite')} icon={<Map size={14} />} />
                </div>

                <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin scrollbar-thumb-green-900">

                    {/* Dynamic Sidebar Content */}
                    {activeTab === 'tools' || activeTab === 'framework' ? (
                        <>
                            <div className="space-y-2">
                                <label className="text-xs text-green-600 font-bold uppercase">Active Module</label>
                                <div className="grid grid-cols-2 gap-2">
                                    {tools.map(tool => (
                                        <button
                                            key={tool.id}
                                            onClick={() => setSelectedTool(tool.id)}
                                            className={`p-2 text-xs text-left rounded border transition-all truncate hover:scale-105 ${selectedTool === tool.id
                                                ? 'bg-green-900/60 border-green-400 text-green-300 shadow-[0_0_10px_rgba(0,255,0,0.2)]'
                                                : 'bg-black/40 border-gray-800 text-gray-500 hover:border-green-700'
                                                }`}
                                        >
                                            <div className="font-bold">{tool.name}</div>
                                            <div className="opacity-50 text-[10px] truncate">{tool.description}</div>
                                        </button>
                                    ))}
                                </div>
                            </div>

                            <div className="space-y-2 mt-6">
                                <label className="text-xs text-green-600 font-bold uppercase">Target Acquisition</label>
                                <div className="flex gap-2">
                                    <input
                                        type="text"
                                        value={target}
                                        onChange={(e) => setTarget(e.target.value)}
                                        onKeyDown={(e) => e.key === 'Enter' && handleRun()}
                                        placeholder="IP / Domain / User"
                                        className="flex-1 bg-black/50 border border-green-800 rounded px-3 py-2 text-green-300 text-sm focus:border-green-500 focus:outline-none"
                                    />
                                    <button
                                        onClick={handleRun}
                                        disabled={loading}
                                        className="bg-green-700/80 hover:bg-green-600 text-white px-3 py-2 rounded text-xs font-bold disabled:opacity-50"
                                    >
                                        RUN
                                    </button>
                                </div>
                            </div>
                        </>
                    ) : activeTab === 'spiderfoot' ? (
                        <div className="space-y-4">
                            <h3 className="text-lg font-bold text-green-400 border-b border-green-900 pb-2">SpiderFoot Controller</h3>
                            <div className={`p-2 rounded text-center font-bold ${spiderfootStatus === 'Running' ? 'bg-green-900/50 text-green-300' : 'bg-red-900/50 text-red-300'}`}>
                                {spiderfootStatus}
                            </div>
                            <div className="flex flex-col gap-2">
                                {spiderfootStatus !== 'Running' ? (
                                    <button onClick={() => toggleSpiderfoot('start')} className="w-full bg-green-700 py-2 rounded text-white text-sm">Start Service</button>
                                ) : (
                                    <button onClick={() => toggleSpiderfoot('stop')} className="w-full bg-red-700 py-2 rounded text-white text-sm">Stop Service</button>
                                )}
                                {spiderfootStatus === 'Running' && (
                                    <a href="http://localhost:5001" target="_blank" rel="noopener noreferrer" className="w-full bg-blue-700 py-2 rounded text-white text-sm text-center block">
                                        Open Web UI
                                    </a>
                                )}
                            </div>
                        </div>
                    ) : (
                        <div className="text-center text-gray-500 text-xs py-10">
                            Select a tool or modules from the tabs above.
                        </div>
                    )}
                </div>

                {/* MONITOR (Fixed at bottom of sidebar) */}
                <div className="p-4 bg-black/60 border-t border-green-900">
                    <AgentMonitor output={output} analyzing={analyzing} analysis={analysis} />
                </div>
            </div>
        </div>
    );
};

const TabButton = ({ active, onClick, icon }) => (
    <button
        onClick={onClick}
        className={`p-2 flex-1 flex justify-center items-center rounded transition-all ${active ? 'bg-green-800 text-green-100 shadow-[inset_0_0_10px_rgba(0,0,0,0.5)]' : 'text-green-700 hover:bg-green-900/30'
            }`}
    >
        {icon}
    </button>
);

// Import at top if not auto-imported, need to mock or separate


export default OsintDashboard;
