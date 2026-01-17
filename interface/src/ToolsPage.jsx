import React, { useState, useEffect } from 'react';
import {
    Shield, Search, Target, Wifi, Globe, Terminal,
    AlertTriangle, CheckCircle, XCircle, RefreshCw,
    Play, Loader, Crosshair, Database, Lock, Eye,
    Activity, Server, Zap, FileSearch, Box, Power,
    RotateCw, Trash2
} from 'lucide-react';
import { API_URL } from './config';
import { useAuth } from './contexts/AuthContext';

const ToolsPage = () => {
    const { token } = useAuth();
    const [activeCategory, setActiveCategory] = useState('hexstrike');
    const [tools, setTools] = useState([]);
    const [loading, setLoading] = useState(false);
    const [hexstrikeOnline, setHexstrikeOnline] = useState(false);
    const [selectedTool, setSelectedTool] = useState(null);
    const [targetInput, setTargetInput] = useState('');
    const [results, setResults] = useState(null);
    const [executing, setExecuting] = useState(false);

    // Docker & Container state
    const [dockerStatus, setDockerStatus] = useState(null);
    const [containers, setContainers] = useState({});
    const [torStatus, setTorStatus] = useState(null);
    const [standbyStatus, setStandbyStatus] = useState(null);
    const [torEnabled, setTorEnabled] = useState(false);

    // Helper for authorized fetch
    const fetchWithAuth = async (url, options = {}) => {
        const headers = {
            ...options.headers,
            'Authorization': `Bearer ${token}`
        };
        return fetch(url, { ...options, headers });
    };

    // Check Docker status
    const checkDocker = async () => {
        if (!token) return;
        try {
            const res = await fetchWithAuth(`${API_URL}/api/docker/status`);
            if (res.ok) {
                const data = await res.json();
                setDockerStatus(data.docker);
                setContainers(data.containers || {});
            }
        } catch (err) {
            setDockerStatus({ available: false });
        }
    };

    // Check Tor status
    const checkTor = async () => {
        if (!token) return;
        try {
            const res = await fetchWithAuth(`${API_URL}/api/docker/tor/status`);
            if (res.ok) {
                const data = await res.json();
                setTorStatus(data);
                setTorEnabled(data.running && data.usingTor);
            }
        } catch {
            setTorStatus({ running: false });
            setTorEnabled(false);
        }
    };

    // Check Standby status
    const checkStandby = async () => {
        if (!token) return;
        try {
            const res = await fetchWithAuth(`${API_URL}/api/docker/standby/status`);
            if (res.ok) {
                const data = await res.json();
                setStandbyStatus(data);
            }
        } catch {
            setStandbyStatus(null);
        }
    };

    // Toggle Tor (Manual activation)
    const toggleTor = async () => {
        if (!token) return;
        setExecuting(true);
        try {
            const action = torEnabled ? 'disable' : 'enable';
            const res = await fetchWithAuth(`${API_URL}/api/docker/tor/${action}`, { method: 'POST' });
            const data = await res.json();
            setResults(data);
            checkTor();
            checkStandby();
        } catch (err) {
            setResults({ error: err.message });
        }
        setExecuting(false);
    };

    // Check HexStrike health
    const checkHexStrike = async () => {
        if (!token) return;
        try {
            // HexStrike endpoints explicitly mounted at /api/hexstrike are under auth now too?
            // Assuming yes based on global middleware.
            const res = await fetchWithAuth(`${API_URL}/api/hexstrike/health`);
            if (res.ok) {
                const data = await res.json();
                setHexstrikeOnline(data.status === 'online');
            }
        } catch {
            setHexstrikeOnline(false);
        }
    };

    // Load HexStrike tools
    const loadTools = async () => {
        if (!token) return;
        setLoading(true);
        try {
            const res = await fetchWithAuth(`${API_URL}/api/hexstrike/tools`);
            if (res.ok) {
                const data = await res.json();
                setTools(data.tools || []);
            }
        } catch (err) {
            setTools([]);
        }
        setLoading(false);
    };

    useEffect(() => {
        checkDocker();
        checkTor();
        checkStandby();
        checkHexStrike();
        loadTools();
        const interval = setInterval(() => {
            checkDocker();
            checkTor();
            checkStandby();
            checkHexStrike();
        }, 30000);
        return () => clearInterval(interval);
    }, []);

    // Start/Stop container
    const toggleContainer = async (containerName, isRunning) => {
        const action = isRunning ? 'stop' : 'start';
        try {
            await fetch(`${API_URL}/api/docker/container/${containerName}/${action}`, { method: 'POST' });
            checkDocker();
        } catch (err) {
            console.error(err);
        }
    };

    // Execute Kali tool
    const executeKaliTool = async (tool, params = {}) => {
        setExecuting(true);
        setResults(null);
        try {
            const res = await fetch(`${API_URL}/api/docker/kali/${tool}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: targetInput, ...params })
            });
            const data = await res.json();
            setResults(data);
        } catch (err) {
            setResults({ error: err.message });
        }
        setExecuting(false);
    };

    // Execute OSINT tool
    const executeOsintTool = async (tool, params = {}) => {
        setExecuting(true);
        setResults(null);
        try {
            const res = await fetch(`${API_URL}/api/docker/osint/${tool}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: targetInput, domain: targetInput, username: targetInput, ...params })
            });
            const data = await res.json();
            setResults(data);
        } catch (err) {
            setResults({ error: err.message });
        }
        setExecuting(false);
    };

    // Tor actions
    const torNewCircuit = async () => {
        setExecuting(true);
        try {
            const res = await fetch(`${API_URL}/api/docker/tor/new-circuit`, { method: 'POST' });
            const data = await res.json();
            setResults(data);
            checkTor();
        } catch (err) {
            setResults({ error: err.message });
        }
        setExecuting(false);
    };

    const torClearTraces = async () => {
        setExecuting(true);
        try {
            const res = await fetch(`${API_URL}/api/docker/tor/clear-traces`, { method: 'POST' });
            const data = await res.json();
            setResults(data);
        } catch (err) {
            setResults({ error: err.message });
        }
        setExecuting(false);
    };

    // Kali tools list
    const kaliTools = [
        { name: 'nmap', label: 'Nmap', desc: 'Port & Service Scanner', icon: Search },
        { name: 'gobuster', label: 'Gobuster', desc: 'Directory Bruteforce', icon: FileSearch },
        { name: 'nikto', label: 'Nikto', desc: 'Web Vulnerability Scanner', icon: Globe },
        { name: 'sqlmap', label: 'SQLMap', desc: 'SQL Injection Testing', icon: Database }
    ];

    const osintTools = [
        { name: 'sherlock', label: 'Sherlock', desc: 'Username Search', icon: Eye },
        { name: 'harvester', label: 'theHarvester', desc: 'Email/Domain OSINT', icon: Search },
        { name: 'amass', label: 'Amass', desc: 'Subdomain Enumeration', icon: Globe }
    ];

    // Categories
    const categories = {
        hexstrike: { icon: Shield, label: 'HexStrike MCP', color: 'red' },
        kali: { icon: Terminal, label: 'Kali Linux', color: 'green' },
        osint: { icon: Eye, label: 'OSINT', color: 'cyan' },
        tor: { icon: Lock, label: 'Tor Network', color: 'purple' }
    };

    return (
        <div className="h-full flex flex-col bg-gray-900 text-white overflow-hidden">
            {/* Header */}
            <div className="bg-black/80 border-b border-gray-800 p-4">
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                        <Shield size={32} className="text-red-500" />
                        <div>
                            <h1 className="text-2xl font-bold tracking-wider">SECURITY TOOLS</h1>
                            <p className="text-xs text-gray-500">HexStrike • Kali Linux • OSINT • Tor</p>
                        </div>
                    </div>
                    <div className="flex items-center gap-3">
                        {/* Docker Status */}
                        <div className={`flex items-center gap-2 px-3 py-1 rounded-full text-xs ${dockerStatus?.available ? 'bg-blue-900/30 text-blue-400 border border-blue-700' : 'bg-gray-800 text-gray-500 border border-gray-700'}`}>
                            <Box size={12} />
                            Docker: {dockerStatus?.available ? 'OK' : 'N/A'}
                        </div>
                        {/* Kali Container */}
                        <div className={`flex items-center gap-2 px-3 py-1 rounded-full text-xs ${containers.kaliTor?.running ? 'bg-green-900/30 text-green-400 border border-green-700' : 'bg-gray-800 text-gray-500 border border-gray-700'}`}>
                            <Terminal size={12} />
                            Kali: {containers.kaliTor?.running ? 'UP' : 'DOWN'}
                        </div>
                        {/* Tor Status */}
                        <div className={`flex items-center gap-2 px-3 py-1 rounded-full text-xs ${torStatus?.running ? 'bg-purple-900/30 text-purple-400 border border-purple-700' : 'bg-gray-800 text-gray-500 border border-gray-700'}`}>
                            <Lock size={12} />
                            Tor: {torStatus?.running ? (torStatus?.usingTor ? 'ANON' : 'UP') : 'OFF'}
                        </div>
                        {/* HexStrike */}
                        <div className={`flex items-center gap-2 px-3 py-1 rounded-full text-xs ${hexstrikeOnline ? 'bg-red-900/30 text-red-400 border border-red-700' : 'bg-gray-800 text-gray-500 border border-gray-700'}`}>
                            <Zap size={12} />
                            HexStrike: {hexstrikeOnline ? 'ON' : 'OFF'}
                        </div>
                        <button onClick={() => { checkDocker(); checkTor(); checkHexStrike(); loadTools(); }} className="p-2 hover:bg-gray-800 rounded">
                            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
                        </button>
                    </div>
                </div>
            </div>

            {/* Category Tabs */}
            <div className="flex gap-2 p-4 bg-gray-800/50 border-b border-gray-700">
                {Object.entries(categories).map(([key, cat]) => (
                    <button
                        key={key}
                        onClick={() => setActiveCategory(key)}
                        className={`flex items-center gap-2 px-4 py-2 rounded-lg font-mono text-sm transition-all ${activeCategory === key
                            ? `bg-${cat.color}-900/30 text-${cat.color}-400 border border-${cat.color}-500/50`
                            : 'bg-gray-700/50 text-gray-400 hover:bg-gray-600/50 border border-transparent'
                            }`}
                    >
                        <cat.icon size={16} />
                        {cat.label}
                    </button>
                ))}
            </div>

            {/* Main Content */}
            <div className="flex-1 flex overflow-hidden">
                {/* Left Panel - Target & Container Controls */}
                <div className="w-80 bg-black/50 border-r border-gray-800 p-4 flex flex-col gap-4 overflow-y-auto">
                    {/* Target Input */}
                    <div>
                        <label className="text-xs text-gray-500 uppercase tracking-wider mb-2 block">Cible / Target</label>
                        <input
                            type="text"
                            value={targetInput}
                            onChange={(e) => setTargetInput(e.target.value)}
                            placeholder="ex: example.com, 192.168.1.1, @username"
                            className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm focus:border-cyan-500 outline-none"
                        />
                    </div>

                    {/* Container Controls */}
                    <div>
                        <label className="text-xs text-gray-500 uppercase tracking-wider mb-2 block">Conteneurs Docker</label>
                        <div className="space-y-2">
                            {Object.entries(containers).map(([key, container]) => (
                                <div key={key} className="flex items-center justify-between bg-gray-900/50 border border-gray-700 rounded p-2">
                                    <div className="flex items-center gap-2">
                                        <div className={`w-2 h-2 rounded-full ${container.running ? 'bg-green-500' : 'bg-red-500'}`} />
                                        <span className="text-xs font-mono">{container.name}</span>
                                    </div>
                                    <button
                                        onClick={() => toggleContainer(container.name, container.running)}
                                        className={`p-1 rounded ${container.running ? 'hover:bg-red-900/30 text-red-400' : 'hover:bg-green-900/30 text-green-400'}`}
                                    >
                                        <Power size={14} />
                                    </button>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Tor Controls */}
                    {activeCategory === 'tor' && (
                        <div>
                            <label className="text-xs text-gray-500 uppercase tracking-wider mb-2 block">Tor Controls (MANUEL)</label>
                            <div className="space-y-2">
                                {/* Main Tor Toggle */}
                                <button
                                    onClick={toggleTor}
                                    disabled={executing}
                                    className={`w-full flex items-center justify-center gap-2 p-3 rounded font-bold text-sm transition-all ${torEnabled
                                        ? 'bg-green-900/30 border-2 border-green-500 text-green-400 hover:bg-green-900/50'
                                        : 'bg-purple-900/30 border-2 border-purple-500 text-purple-400 hover:bg-purple-900/50'
                                        }`}
                                >
                                    <Power size={18} />
                                    {torEnabled ? '🧅 TOR ACTIF - Cliquez pour désactiver' : '⏸️ ACTIVER TOR'}
                                </button>

                                {torEnabled && (
                                    <>
                                        <button
                                            onClick={torNewCircuit}
                                            disabled={executing}
                                            className="w-full flex items-center gap-2 p-2 bg-purple-900/20 border border-purple-700 rounded hover:bg-purple-900/40 text-purple-400 text-sm"
                                        >
                                            <RotateCw size={14} />
                                            Nouveau Circuit (Nouvelle IP)
                                        </button>
                                        <button
                                            onClick={torClearTraces}
                                            disabled={executing}
                                            className="w-full flex items-center gap-2 p-2 bg-red-900/20 border border-red-700 rounded hover:bg-red-900/40 text-red-400 text-sm"
                                        >
                                            <Trash2 size={14} />
                                            Effacer Traces
                                        </button>
                                    </>
                                )}

                                {torStatus?.ip && (
                                    <div className="bg-gray-900 p-2 rounded text-xs">
                                        <span className="text-gray-500">IP Tor:</span>
                                        <span className="text-green-400 ml-2 font-mono">{torStatus.ip}</span>
                                    </div>
                                )}

                                <div className="bg-yellow-900/20 border border-yellow-700 rounded p-2 text-[10px] text-yellow-400 mt-2">
                                    ⚠️ Tor reste désactivé par défaut. Activez-le manuellement quand nécessaire.
                                </div>
                            </div>
                        </div>
                    )}
                </div>

                {/* Center Panel - Tools */}
                <div className="flex-1 p-4 overflow-y-auto">
                    {/* Kali Tools */}
                    {activeCategory === 'kali' && (
                        <div className="grid grid-cols-2 gap-3">
                            {kaliTools.map((tool) => (
                                <button
                                    key={tool.name}
                                    onClick={() => executeKaliTool(tool.name)}
                                    disabled={!containers.kaliTor?.running || executing || !targetInput}
                                    className="p-4 rounded-lg border bg-green-900/10 border-green-700/50 hover:border-green-500 transition-all text-left disabled:opacity-50 disabled:cursor-not-allowed"
                                >
                                    <div className="flex items-center gap-2 mb-2">
                                        <tool.icon size={18} className="text-green-500" />
                                        <span className="font-bold text-white">{tool.label}</span>
                                    </div>
                                    <p className="text-xs text-gray-400">{tool.desc}</p>
                                </button>
                            ))}
                            {!containers.kaliTor?.running && (
                                <div className="col-span-2 bg-yellow-900/20 border border-yellow-700 rounded p-3 text-xs text-yellow-400">
                                    <AlertTriangle size={14} className="inline mr-2" />
                                    Kali container offline. Démarrez-le depuis le panneau de gauche.
                                </div>
                            )}
                        </div>
                    )}

                    {/* OSINT Tools */}
                    {activeCategory === 'osint' && (
                        <div className="grid grid-cols-2 gap-3">
                            {osintTools.map((tool) => (
                                <button
                                    key={tool.name}
                                    onClick={() => executeOsintTool(tool.name)}
                                    disabled={!containers.kaliTor?.running || executing || !targetInput}
                                    className="p-4 rounded-lg border bg-cyan-900/10 border-cyan-700/50 hover:border-cyan-500 transition-all text-left disabled:opacity-50 disabled:cursor-not-allowed"
                                >
                                    <div className="flex items-center gap-2 mb-2">
                                        <tool.icon size={18} className="text-cyan-500" />
                                        <span className="font-bold text-white">{tool.label}</span>
                                    </div>
                                    <p className="text-xs text-gray-400">{tool.desc}</p>
                                </button>
                            ))}
                        </div>
                    )}

                    {/* Tor Tools */}
                    {activeCategory === 'tor' && (
                        <div className="space-y-4">
                            <div className="bg-purple-900/10 border border-purple-700 rounded-lg p-4">
                                <h3 className="font-bold text-purple-400 mb-2 flex items-center gap-2">
                                    <Lock size={18} />
                                    Tor Network Status
                                </h3>
                                <div className="grid grid-cols-2 gap-4 text-sm">
                                    <div>
                                        <span className="text-gray-500">Connecté:</span>
                                        <span className={`ml-2 ${torStatus?.running ? 'text-green-400' : 'text-red-400'}`}>
                                            {torStatus?.running ? 'Oui' : 'Non'}
                                        </span>
                                    </div>
                                    <div>
                                        <span className="text-gray-500">Anonyme:</span>
                                        <span className={`ml-2 ${torStatus?.usingTor ? 'text-green-400' : 'text-yellow-400'}`}>
                                            {torStatus?.usingTor ? 'Oui' : 'Non vérifié'}
                                        </span>
                                    </div>
                                    <div className="col-span-2">
                                        <span className="text-gray-500">IP Exit:</span>
                                        <span className="ml-2 font-mono text-purple-400">{torStatus?.ip || 'N/A'}</span>
                                    </div>
                                </div>
                            </div>
                            <div className="bg-purple-900/20 border border-purple-500/50 rounded p-4 text-sm">
                                <div className="flex items-center gap-2 text-purple-400 font-bold mb-2">
                                    🧅 Accès Dark Web via Proxy Tor (Docker)
                                </div>
                                <p className="text-gray-400 text-xs mb-3">
                                    Cliquez sur "ACTIVER TOR" pour démarrer le conteneur Tor. Ce proxy permet aux
                                    outils (Kali, OSINT, HexStrike) de router leur trafic via le réseau Tor.
                                </p>
                                <div className="text-[10px] text-gray-500">
                                    Port SOCKS5: 9050 | Control: 9051 | Conteneur: th3-tor
                                </div>
                            </div>
                        </div>
                    )}

                    {/* HexStrike Tools */}
                    {activeCategory === 'hexstrike' && (
                        <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
                            {loading ? (
                                <div className="col-span-full flex items-center justify-center py-20">
                                    <Loader size={32} className="animate-spin text-red-500" />
                                </div>
                            ) : tools.length === 0 ? (
                                <div className="col-span-full text-center py-20 text-gray-500">
                                    <Terminal size={48} className="mx-auto mb-4 opacity-30" />
                                    <p>Aucun outil HexStrike disponible</p>
                                    <p className="text-xs mt-2">Démarrez: python hexstrike_server.py</p>
                                </div>
                            ) : (
                                tools.map((tool, idx) => (
                                    <button
                                        key={idx}
                                        onClick={() => setSelectedTool(tool)}
                                        className={`p-4 rounded-lg border text-left transition-all hover:scale-[1.02] ${selectedTool?.name === tool.name
                                            ? 'bg-red-900/30 border-red-500'
                                            : 'bg-gray-800/50 border-gray-700 hover:border-gray-600'
                                            }`}
                                    >
                                        <div className="flex items-center gap-2 mb-2">
                                            <Terminal size={14} className="text-red-500" />
                                            <span className="font-mono text-sm font-bold">{tool.name}</span>
                                        </div>
                                        <p className="text-[10px] text-gray-400 line-clamp-2">{tool.description}</p>
                                    </button>
                                ))
                            )}
                        </div>
                    )}
                </div>

                {/* Right Panel - Results */}
                <div className="w-96 bg-black/50 border-l border-gray-800 p-4 flex flex-col">
                    <div className="flex items-center justify-between mb-4">
                        <span className="text-xs text-gray-500 uppercase tracking-wider">Résultats</span>
                        {executing && <Loader size={14} className="animate-spin text-cyan-500" />}
                    </div>

                    <div className="flex-1 bg-gray-900/50 rounded border border-gray-800 p-3 overflow-y-auto font-mono text-xs">
                        {executing ? (
                            <div className="flex flex-col items-center justify-center h-full text-gray-500">
                                <Activity size={32} className="animate-pulse mb-4" />
                                <p>Exécution en cours...</p>
                            </div>
                        ) : results ? (
                            <pre className="whitespace-pre-wrap text-gray-300">
                                {typeof results === 'string' ? results : JSON.stringify(results, null, 2)}
                            </pre>
                        ) : (
                            <div className="text-gray-600 text-center py-10">
                                Sélectionnez un outil et lancez un scan
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ToolsPage;
