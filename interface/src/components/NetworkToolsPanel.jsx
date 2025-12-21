import React, { useState, useEffect } from 'react';
import { 
    Network, Wifi, Shield, Terminal, Upload, Link, Monitor, Eye,
    Play, CheckCircle, XCircle, Loader, ExternalLink, RefreshCw
} from 'lucide-react';
import { API_URL } from '../config';

const TOOLS = [
    {
        id: 'nmap',
        name: 'Nmap',
        description: 'Scanner de ports réseau',
        icon: Network,
        color: 'cyan',
        hasApi: true,
        winApp: false
    },
    {
        id: 'wireshark',
        name: 'Wireshark',
        description: 'Analyseur de trafic',
        icon: Eye,
        color: 'blue',
        hasApi: true,
        winApp: 'wireshark'
    },
    {
        id: 'wireguard',
        name: 'WireGuard',
        description: 'VPN moderne et rapide',
        icon: Shield,
        color: 'purple',
        hasApi: false,
        winApp: 'wireguard'
    },
    {
        id: 'winscp',
        name: 'WinSCP',
        description: 'Transfert SFTP/SCP',
        icon: Upload,
        color: 'green',
        hasApi: false,
        winApp: 'WinSCP'
    },
    {
        id: 'netbird',
        name: 'NetBird',
        description: 'VPN mesh P2P',
        icon: Link,
        color: 'orange',
        hasApi: false,
        winApp: 'netbird-ui'
    },
    {
        id: 'mremoteng',
        name: 'mRemoteNG',
        description: 'Gestionnaire de connexions',
        icon: Monitor,
        color: 'pink',
        hasApi: false,
        winApp: 'mRemoteNG'
    },
    {
        id: 'portmaster',
        name: 'Portmaster',
        description: 'Pare-feu applicatif',
        icon: Shield,
        color: 'red',
        hasApi: false,
        winApp: null,
        webUrl: 'http://localhost:817/'
    },
    {
        id: 'advanced-ip-scanner',
        name: 'Advanced IP Scanner',
        description: 'Découverte réseau',
        icon: Wifi,
        color: 'teal',
        hasApi: false,
        winApp: 'Advanced IP Scanner'
    }
];

const NetworkToolsPanel = () => {
    const [selectedTool, setSelectedTool] = useState(null);
    const [nmapStatus, setNmapStatus] = useState(null);
    const [tsharkStatus, setTsharkStatus] = useState(null);
    const [scanResult, setScanResult] = useState(null);
    const [scanning, setScanning] = useState(false);
    const [scanTarget, setScanTarget] = useState('');
    const [scanType, setScanType] = useState('quick');
    
    // Check API status on mount
    useEffect(() => {
        checkApiStatus();
    }, []);
    
    const checkApiStatus = async () => {
        try {
            const nmapRes = await fetch(`${API_URL}/network/nmap/status`);
            const nmapData = await nmapRes.json();
            setNmapStatus(nmapData);
            
            const tsharkRes = await fetch(`${API_URL}/network/tshark/status`);
            const tsharkData = await tsharkRes.json();
            setTsharkStatus(tsharkData);
        } catch (error) {
            console.error('Failed to check API status:', error);
        }
    };
    
    const runNmapScan = async () => {
        if (!scanTarget || scanning) return;
        setScanning(true);
        setScanResult(null);
        
        try {
            const res = await fetch(`${API_URL}/network/nmap/scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: scanTarget, scanType })
            });
            const data = await res.json();
            setScanResult(data);
        } catch (error) {
            setScanResult({ success: false, error: error.message });
        } finally {
            setScanning(false);
        }
    };
    
    const launchApp = (tool) => {
        if (tool.webUrl) {
            window.open(tool.webUrl, '_blank');
        } else if (tool.winApp) {
            // Signal to open Windows app (handled by backend or shell)
            fetch(`${API_URL}/system/launch-app`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ app: tool.winApp })
            }).catch(() => {
                // Fallback: show instructions
                alert(`Lancez ${tool.name} depuis le menu Démarrer Windows`);
            });
        }
    };
    
    const getColorClass = (color) => {
        const colors = {
            cyan: 'bg-cyan-900/30 border-cyan-700 text-cyan-400',
            blue: 'bg-blue-900/30 border-blue-700 text-blue-400',
            purple: 'bg-purple-900/30 border-purple-700 text-purple-400',
            green: 'bg-green-900/30 border-green-700 text-green-400',
            orange: 'bg-orange-900/30 border-orange-700 text-orange-400',
            pink: 'bg-pink-900/30 border-pink-700 text-pink-400',
            red: 'bg-red-900/30 border-red-700 text-red-400',
            teal: 'bg-teal-900/30 border-teal-700 text-teal-400'
        };
        return colors[color] || colors.cyan;
    };
    
    return (
        <div className="p-6 bg-black text-cyan-300 min-h-full">
            {/* Header */}
            <div className="flex justify-between items-center mb-6">
                <div>
                    <h1 className="text-2xl font-bold tracking-widest flex items-center gap-3">
                        <Network className="text-cyan-500" />
                        OUTILS RÉSEAU
                    </h1>
                    <p className="text-xs text-gray-500 mt-1">
                        Nmap + Wireshark + VPN + Utilitaires réseau
                    </p>
                </div>
                <button 
                    onClick={checkApiStatus}
                    className="p-2 bg-gray-800 border border-gray-700 rounded hover:border-cyan-500"
                >
                    <RefreshCw size={16} />
                </button>
            </div>
            
            {/* Tools Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                {TOOLS.map(tool => {
                    const Icon = tool.icon;
                    const isSelected = selectedTool?.id === tool.id;
                    
                    return (
                        <button
                            key={tool.id}
                            onClick={() => setSelectedTool(tool)}
                            className={`p-4 rounded-xl border transition-all text-left ${
                                isSelected 
                                    ? getColorClass(tool.color) + ' shadow-lg' 
                                    : 'bg-gray-900/50 border-gray-700 hover:border-gray-500'
                            }`}
                        >
                            <div className="flex items-center gap-3 mb-2">
                                <Icon size={24} className={isSelected ? '' : 'text-gray-500'} />
                                <span className="font-bold">{tool.name}</span>
                            </div>
                            <p className="text-xs text-gray-400">{tool.description}</p>
                            <div className="flex gap-2 mt-2">
                                {tool.hasApi && (
                                    <span className="text-xs px-2 py-0.5 bg-green-900/50 text-green-400 rounded">
                                        API
                                    </span>
                                )}
                                {(tool.winApp || tool.webUrl) && (
                                    <span className="text-xs px-2 py-0.5 bg-blue-900/50 text-blue-400 rounded">
                                        App
                                    </span>
                                )}
                            </div>
                        </button>
                    );
                })}
            </div>
            
            {/* API Status */}
            <div className="grid grid-cols-2 gap-4 mb-6">
                <div className={`p-3 rounded-lg border ${nmapStatus?.available ? 'bg-green-900/20 border-green-700' : 'bg-red-900/20 border-red-700'}`}>
                    <div className="flex items-center gap-2">
                        {nmapStatus?.available ? <CheckCircle size={16} className="text-green-400" /> : <XCircle size={16} className="text-red-400" />}
                        <span className="font-bold">Nmap</span>
                    </div>
                    <p className="text-xs text-gray-400 mt-1">
                        {nmapStatus?.version || 'Non disponible'}
                    </p>
                </div>
                <div className={`p-3 rounded-lg border ${tsharkStatus?.available ? 'bg-green-900/20 border-green-700' : 'bg-red-900/20 border-red-700'}`}>
                    <div className="flex items-center gap-2">
                        {tsharkStatus?.available ? <CheckCircle size={16} className="text-green-400" /> : <XCircle size={16} className="text-red-400" />}
                        <span className="font-bold">TShark</span>
                    </div>
                    <p className="text-xs text-gray-400 mt-1">
                        {tsharkStatus?.version || 'Non disponible'}
                    </p>
                </div>
            </div>
            
            {/* Selected Tool Panel */}
            {selectedTool && (
                <div className={`p-6 rounded-xl border ${getColorClass(selectedTool.color)}`}>
                    <div className="flex justify-between items-start mb-4">
                        <div>
                            <h2 className="text-xl font-bold flex items-center gap-2">
                                {React.createElement(selectedTool.icon, { size: 24 })}
                                {selectedTool.name}
                            </h2>
                            <p className="text-sm text-gray-400">{selectedTool.description}</p>
                        </div>
                        {(selectedTool.winApp || selectedTool.webUrl) && (
                            <button
                                onClick={() => launchApp(selectedTool)}
                                className="px-3 py-1.5 bg-black/50 rounded border border-white/20 text-sm flex items-center gap-2 hover:bg-white/10"
                            >
                                <ExternalLink size={14} />
                                Ouvrir
                            </button>
                        )}
                    </div>
                    
                    {/* Nmap Scanner */}
                    {selectedTool.id === 'nmap' && (
                        <div className="space-y-4">
                            <div className="flex gap-3">
                                <input
                                    type="text"
                                    placeholder="Cible (IP ou domaine)"
                                    value={scanTarget}
                                    onChange={(e) => setScanTarget(e.target.value)}
                                    className="flex-1 bg-black/50 border border-gray-700 rounded px-3 py-2 text-sm"
                                />
                                <select
                                    value={scanType}
                                    onChange={(e) => setScanType(e.target.value)}
                                    className="bg-black/50 border border-gray-700 rounded px-3 py-2 text-sm"
                                >
                                    <option value="quick">Rapide</option>
                                    <option value="service">Services</option>
                                    <option value="camera">Caméras IP</option>
                                    <option value="vuln">Vulnérabilités</option>
                                    <option value="full">Complet</option>
                                </select>
                                <button
                                    onClick={runNmapScan}
                                    disabled={scanning || !scanTarget}
                                    className="px-4 py-2 bg-cyan-900/50 border border-cyan-600 rounded text-sm flex items-center gap-2 disabled:opacity-50"
                                >
                                    {scanning ? <Loader size={14} className="animate-spin" /> : <Play size={14} />}
                                    Scanner
                                </button>
                            </div>
                            
                            {scanResult && (
                                <div className="bg-black/50 p-4 rounded border border-gray-700">
                                    {scanResult.success ? (
                                        <div>
                                            <div className="text-sm text-green-400 mb-2">
                                                ✅ Scan terminé - {scanResult.parsed?.openPorts?.length || 0} ports ouverts
                                            </div>
                                            {scanResult.parsed?.openPorts?.map((port, i) => (
                                                <div key={i} className="text-xs text-gray-300 flex gap-4">
                                                    <span className="text-cyan-400">{port.port}/{port.protocol}</span>
                                                    <span>{port.service}</span>
                                                    <span className="text-gray-500">{port.version}</span>
                                                </div>
                                            ))}
                                        </div>
                                    ) : (
                                        <div className="text-sm text-red-400">
                                            ❌ Erreur: {scanResult.error}
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    )}
                    
                    {/* Generic Tool Info */}
                    {!selectedTool.hasApi && (
                        <div className="bg-black/30 p-4 rounded border border-gray-700">
                            <p className="text-sm text-gray-400 mb-3">
                                Cet outil doit être lancé comme application Windows.
                            </p>
                            <div className="text-xs text-gray-500">
                                📖 Voir le guide complet: <code className="text-cyan-400">docs/GUIDE_OUTILS_RESEAU.md</code>
                            </div>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

export default NetworkToolsPanel;
