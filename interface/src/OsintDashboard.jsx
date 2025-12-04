import React, { useState, useEffect } from 'react';
import { Globe, Server, User, Shield, Terminal, AlertTriangle, Activity } from 'lucide-react';

const API_URL = 'http://localhost:3000';

const OsintDashboard = () => {
    const [tools, setTools] = useState([]);
    const [selectedTool, setSelectedTool] = useState(null);
    const [target, setTarget] = useState("");
    const [output, setOutput] = useState("");
    const [loading, setLoading] = useState(false);
    const [activeTab, setActiveTab] = useState('tools'); // tools, spiderfoot, framework, maltego
    const [spiderfootStatus, setSpiderfootStatus] = useState("Unknown");

    useEffect(() => {
        fetch(`${API_URL}/osint/tools`)
            .then(res => res.json())
            .then(data => {
                setTools(data);
                if (data.length > 0) setSelectedTool(data[0].id);
            })
            .catch(err => console.error("Failed to load tools:", err));

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

    const handleRun = async () => {
        if (!target || !selectedTool) return;
        setLoading(true);
        setAnalysis(""); // Clear previous analysis
        setOutput(prev => prev + `\n> Running ${selectedTool} on ${target}...\n`);

        try {
            // 1. Run the Tool
            const res = await fetch(`${API_URL}/osint/run`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ toolId: selectedTool, target })
            });
            const data = await res.json();
            const toolOutput = data.result;
            setOutput(prev => prev + toolOutput + "\n\n");

            // 2. Trigger Expert Analysis
            setAnalyzing(true);
            const analyzeRes = await fetch(`${API_URL}/osint/analyze`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ toolId: selectedTool, output: toolOutput })
            });
            const analyzeData = await analyzeRes.json();
            setAnalysis(analyzeData.analysis);

        } catch (error) {
            setOutput(prev => prev + `[ERROR] ${error.message}\n\n`);
        }
        setLoading(false);
        setAnalyzing(false);
    };

    return (
        <div className="flex h-full bg-transparent text-green-400 font-mono p-6 gap-6">

            {/* Sidebar / Tool Selection */}
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
                    <div className="flex-1 bg-white rounded-lg overflow-hidden border border-green-900">
                        <iframe src="https://osintframework.com/" title="OSINT Framework" className="w-full h-full" />
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
