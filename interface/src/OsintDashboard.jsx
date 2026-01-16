import React, { useState, useEffect } from 'react';
import { Globe, Server, User, Shield, Terminal, AlertTriangle, Activity, Map } from 'lucide-react';
import { API_URL } from './config';
import WWTMapComponent from './components/WWTMapComponent';

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
        <div className="flex h-full bg-transparent text-green-400 font-mono p-6 gap-6">

            {/* Sidebar / Tool Selection - Hidden when viewing framework for full mindmap */}
            {activeTab !== 'framework' && (
                <div className="w-64 flex flex-col gap-4">
                    <div className="flex items-center gap-2 text-green-500 mb-4 border-b border-green-900 pb-2">
                        <Shield size={24} />
                        <h1 className="text-xl font-bold tracking-widest">OSINT OPS</h1>
                    </div>

                    {/* Navigation Tabs */}
                    <div className="flex flex-col gap-1 mb-4">
                        <NavButton active={activeTab === 'tools'} onClick={() => setActiveTab('tools')} icon={<Terminal size={16} />} label="CLI TOOLS" />
                        <NavButton active={activeTab === 'spiderfoot'} onClick={() => setActiveTab('spiderfoot')} icon={<Globe size={16} />} label="SPIDERFOOT" />
                        <NavButton active={activeTab === 'framework'} onClick={() => setActiveTab('framework')} icon={<Server size={16} />} label="FRAMEWORK" />
                        <NavButton active={activeTab === 'maltego'} onClick={() => setActiveTab('maltego')} icon={<User size={16} />} label="MALTEGO" />
                        <NavButton active={activeTab === 'satellite'} onClick={() => setActiveTab('satellite')} icon={<Map size={16} />} label="SATELLITE (WWT)" />
                    </div>

                    {activeTab === 'tools' && (
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
                                    {tool.id === 'ping' && <Activity size={16} />}
                                    <div>
                                        <div className="font-bold text-sm uppercase">{tool.name}</div>
                                        <div className="text-[10px] opacity-70">{tool.description}</div>
                                    </div>
                                </button>
                            ))}
                        </div>
                    )}

                    <div className="mt-auto p-4 bg-red-900/10 border border-red-900/30 rounded text-xs text-red-400 flex gap-2">
                        <AlertTriangle size={16} className="shrink-0" />
                        <p>Authorized use only. All actions are logged.</p>
                    </div>
                </div>
            )}

            {/* Main Content Area */}
            <div className="flex-1 flex flex-col gap-4">

                {activeTab === 'tools' && (
                    <>
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
                        <div className="flex-1 bg-black border border-gray-800 rounded-lg p-4 overflow-y-auto font-mono text-sm shadow-inner shadow-black flex flex-col gap-4">
                            <pre className="whitespace-pre-wrap text-green-500/80 flex-1">
                                {output || "// OSINT Console Ready...\n// Select a tool and enter a target to begin."}
                            </pre>

                            {/* Expert Analysis Panel */}
                            {(analyzing || analysis) && (
                                <div className="border-t border-green-900/50 pt-4 mt-2 animate-in fade-in slide-in-from-bottom-4 duration-500">
                                    <div className="flex items-center gap-2 text-cyan-400 mb-2">
                                        <Activity size={16} className={analyzing ? "animate-spin" : ""} />
                                        <h3 className="font-bold tracking-widest text-xs uppercase">
                                            {analyzing ? "EXPERT AGENT ANALYZING..." : "INTELLIGENCE BRIEF"}
                                        </h3>
                                    </div>
                                    <div className="bg-cyan-900/10 border border-cyan-900/30 p-3 rounded text-cyan-300 text-xs leading-relaxed whitespace-pre-wrap font-sans">
                                        {analysis || "Decrypting data patterns..."}
                                    </div>
                                </div>
                            )}
                        </div>
                    </>
                )}

                {activeTab === 'spiderfoot' && (
                    <div className="flex-1 flex flex-col gap-4 p-4 bg-gray-900/30 rounded-lg border border-green-900/30">
                        <h2 className="text-2xl font-bold text-green-400">SpiderFoot Automation</h2>
                        <p className="text-gray-400">Automated OSINT collection and reconnaissance.</p>

                        <div className="flex items-center gap-4 my-4">
                            <div className={`px-3 py-1 rounded text-sm font-bold ${spiderfootStatus === 'Running' ? 'bg-green-900 text-green-300' : 'bg-red-900 text-red-300'}`}>
                                Status: {spiderfootStatus}
                            </div>
                            {spiderfootStatus !== 'Running' ? (
                                <button onClick={() => toggleSpiderfoot('start')} disabled={loading} className="bg-green-700 hover:bg-green-600 px-4 py-2 rounded text-white">Start Server</button>
                            ) : (
                                <button onClick={() => toggleSpiderfoot('stop')} disabled={loading} className="bg-red-700 hover:bg-red-600 px-4 py-2 rounded text-white">Stop Server</button>
                            )}
                            {spiderfootStatus === 'Running' && (
                                <a href="http://localhost:5001" target="_blank" rel="noopener noreferrer" className="bg-blue-700 hover:bg-blue-600 px-4 py-2 rounded text-white flex items-center gap-2">
                                    Open Web UI <Globe size={16} />
                                </a>
                            )}
                        </div>

                        <div className="bg-black p-4 rounded border border-gray-800 text-sm text-gray-400">
                            <h3 className="font-bold text-green-500 mb-2">Best Practices:</h3>
                            <ul className="list-disc pl-5 space-y-1">
                                <li>Launch targeted scans (DNS, Whois) to avoid noise.</li>
                                <li>Export results to CSV/JSON for analysis in Maltego.</li>
                                <li>Use the Web UI for detailed graph visualizations.</li>
                            </ul>
                        </div>
                    </div>
                )}

                {activeTab === 'framework' && (
                    <div className="flex-1 flex flex-col bg-black rounded-lg overflow-hidden border border-green-500/50 shadow-lg shadow-green-900/20">
                        {/* Header Bar */}
                        <div className="flex items-center justify-between bg-gray-900 border-b border-green-900/50 px-4 py-2">
                            <div className="flex items-center gap-3">
                                <Server size={18} className="text-green-500" />
                                <span className="font-bold text-green-400 tracking-wider">OSINT FRAMEWORK MINDMAP</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <button
                                    onClick={() => setActiveTab('tools')}
                                    className="px-3 py-1 bg-gray-800 border border-gray-600 rounded text-gray-300 text-xs hover:bg-gray-700 transition-colors"
                                >
                                    ← Retour
                                </button>
                                <a
                                    href="https://osintframework.com/"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="px-3 py-1 bg-green-900/30 border border-green-700 rounded text-green-400 text-xs hover:bg-green-800/50 transition-colors"
                                >
                                    Ouvrir en plein écran ↗
                                </a>
                            </div>
                        </div>
                        {/* Full Height iFrame */}
                        <div className="flex-1 bg-gray-100" style={{ minHeight: 'calc(100vh - 200px)' }}>
                            <iframe
                                src="https://osintframework.com/"
                                title="OSINT Framework"
                                className="w-full h-full border-none"
                                style={{ minHeight: '100%', height: 'calc(100vh - 200px)' }}
                                allow="fullscreen"
                            />
                        </div>
                    </div>
                )}

                {activeTab === 'maltego' && (
                    <div className="flex-1 flex flex-col gap-4 p-4 bg-gray-900/30 rounded-lg border border-green-900/30 overflow-y-auto">
                        <h2 className="text-2xl font-bold text-green-400">Maltego Intelligence</h2>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div className="bg-black/50 p-4 rounded border border-gray-700">
                                <h3 className="text-lg font-bold text-green-300 mb-2">Setup Guide</h3>
                                <ol className="list-decimal pl-5 space-y-2 text-gray-400 text-sm">
                                    <li>Download Maltego CE (Community Edition).</li>
                                    <li>Create a graph per investigation.</li>
                                    <li>Separate entities (Person, Infra, Org) into layers.</li>
                                    <li>Note sources at every pivot for evidence chain.</li>
                                </ol>
                                <a href="https://www.maltego.com/downloads/" target="_blank" rel="noopener noreferrer" className="mt-4 inline-block text-blue-400 hover:underline">Download Maltego</a>
                            </div>
                            <div className="bg-black/50 p-4 rounded border border-gray-700">
                                <h3 className="text-lg font-bold text-green-300 mb-2">Workflow Integration</h3>
                                <p className="text-gray-400 text-sm mb-2">Combine with SpiderFoot:</p>
                                <ul className="list-disc pl-5 space-y-1 text-gray-400 text-sm">
                                    <li>Run SpiderFoot scan on target.</li>
                                    <li>Export data as CSV.</li>
                                    <li>Import CSV into Maltego.</li>
                                    <li>Visualize relationships and pivot.</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                )}

                {activeTab === 'satellite' && (
                    <WWTMapComponent />
                )}
            </div>
        </div>
    );
};

const NavButton = ({ active, onClick, icon, label }) => (
    <button
        onClick={onClick}
        className={`flex items-center gap-3 p-3 rounded transition-all ${active
            ? 'bg-green-900/50 text-green-300 border-l-4 border-green-500'
            : 'text-gray-500 hover:bg-gray-900/50 hover:text-green-400'
            }`}
    >
        {icon}
        <span className="font-bold text-sm tracking-wider">{label}</span>
    </button>
);

export default OsintDashboard;
