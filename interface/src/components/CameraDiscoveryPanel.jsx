import React, { useState, useEffect, useCallback } from 'react';
import { API_URL } from '../config';

/**
 * CameraDiscoveryPanel - Passive camera discovery for personal EasyLife/Tuya cameras
 * ⚠️ For authorized use on YOUR OWN network only!
 */
const CameraDiscoveryPanel = ({ onCameraFound, compact = false }) => {
    const [status, setStatus] = useState(null);
    const [isScanning, setIsScanning] = useState(false);
    const [scanResults, setScanResults] = useState(null);
    const [error, setError] = useState(null);
    const [networkRange, setNetworkRange] = useState('');
    const [quickScanIp, setQuickScanIp] = useState('');
    const [quickScanResult, setQuickScanResult] = useState(null);

    // Load status on mount
    useEffect(() => {
        loadStatus();
    }, []);

    const loadStatus = async () => {
        try {
            const res = await fetch(`${API_URL}/api/camera-discovery/status`);
            const data = await res.json();
            if (data.success) {
                setStatus(data);
                if (data.cameras?.length > 0) {
                    setScanResults({ cameras: data.cameras });
                }
            }
        } catch (err) {
            console.error('[CameraDiscovery] Status error:', err);
        }
    };

    const getDefaultRange = async () => {
        try {
            const res = await fetch(`${API_URL}/api/camera-discovery/network-range`);
            const data = await res.json();
            if (data.success) {
                setNetworkRange(data.networkRange);
            }
        } catch (err) {
            console.error('[CameraDiscovery] Network range error:', err);
        }
    };

    const startScan = async () => {
        setIsScanning(true);
        setError(null);
        setScanResults(null);

        try {
            const res = await fetch(`${API_URL}/api/camera-discovery/scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ networkRange: networkRange || null })
            });
            
            const data = await res.json();
            
            if (data.success) {
                setScanResults(data);
                // Notify parent of found cameras
                if (data.cameras?.length > 0 && onCameraFound) {
                    data.cameras.forEach(cam => onCameraFound(cam));
                }
            } else {
                setError(data.error || 'Scan failed');
            }
        } catch (err) {
            setError(err.message);
        } finally {
            setIsScanning(false);
            loadStatus();
        }
    };

    const quickScan = async () => {
        if (!quickScanIp) return;
        
        setQuickScanResult(null);
        setError(null);

        try {
            const res = await fetch(`${API_URL}/api/camera-discovery/quick-scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: quickScanIp })
            });
            
            const data = await res.json();
            setQuickScanResult(data);
            
            if (data.success && data.isCamera && onCameraFound) {
                onCameraFound(data);
            }
        } catch (err) {
            setError(err.message);
        }
    };

    const runPythonDiscovery = async () => {
        setIsScanning(true);
        setError(null);

        try {
            const res = await fetch(`${API_URL}/api/camera-discovery/python`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ networkRange: networkRange || null })
            });
            
            const data = await res.json();
            
            if (data.success) {
                setScanResults({ cameras: data.cameras || [] });
            } else {
                setError(data.error || 'Python scan failed');
            }
        } catch (err) {
            setError(err.message);
        } finally {
            setIsScanning(false);
            loadStatus();
        }
    };

    // Compact mode - just show camera count and quick actions
    if (compact) {
        return (
            <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700">
                <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-cyan-400 flex items-center gap-2">
                        📹 Camera Discovery
                    </span>
                    <span className={`text-xs px-2 py-0.5 rounded ${
                        status?.discoveredCameras > 0 ? 'bg-green-500/20 text-green-400' : 'bg-slate-600 text-slate-400'
                    }`}>
                        {status?.discoveredCameras || 0} found
                    </span>
                </div>
                
                <div className="flex gap-2">
                    <button
                        onClick={startScan}
                        disabled={isScanning}
                        className="flex-1 text-xs px-2 py-1.5 bg-cyan-600 hover:bg-cyan-700 rounded transition disabled:opacity-50"
                    >
                        {isScanning ? '🔍 Scanning...' : '🔍 Scan Network'}
                    </button>
                    <button
                        onClick={() => window.open('/camera-discovery', '_blank')}
                        className="text-xs px-2 py-1.5 bg-slate-600 hover:bg-slate-500 rounded transition"
                    >
                        ⚙️
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
            {/* Header */}
            <div className="bg-gradient-to-r from-cyan-600/20 to-blue-600/20 px-4 py-3 border-b border-slate-700">
                <div className="flex items-center justify-between">
                    <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                        📹 Camera Discovery
                        <span className="text-xs font-normal text-slate-400">(Passive Scanner)</span>
                    </h3>
                    <span className="text-xs text-slate-400">
                        ⚠️ YOUR network only
                    </span>
                </div>
            </div>

            <div className="p-4 space-y-4">
                {/* Network Range Input */}
                <div className="space-y-2">
                    <label className="text-sm text-slate-400">Network Range</label>
                    <div className="flex gap-2">
                        <input
                            type="text"
                            value={networkRange}
                            onChange={(e) => setNetworkRange(e.target.value)}
                            placeholder="192.168.1.0/24 (auto-detect)"
                            className="flex-1 bg-slate-700 border border-slate-600 rounded px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
                        />
                        <button
                            onClick={getDefaultRange}
                            className="px-3 py-2 bg-slate-600 hover:bg-slate-500 rounded text-sm transition"
                            title="Auto-detect network range"
                        >
                            🔄
                        </button>
                    </div>
                </div>

                {/* Scan Buttons */}
                <div className="grid grid-cols-2 gap-2">
                    <button
                        onClick={startScan}
                        disabled={isScanning}
                        className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 rounded font-medium transition disabled:opacity-50 flex items-center justify-center gap-2"
                    >
                        {isScanning ? (
                            <>
                                <span className="animate-spin">⏳</span>
                                Scanning...
                            </>
                        ) : (
                            <>🔍 Full Scan</>
                        )}
                    </button>
                    <button
                        onClick={runPythonDiscovery}
                        disabled={isScanning}
                        className="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded font-medium transition disabled:opacity-50"
                    >
                        🐍 Python ONVIF
                    </button>
                </div>

                {/* Quick Scan */}
                <div className="space-y-2">
                    <label className="text-sm text-slate-400">Quick Scan (Single IP)</label>
                    <div className="flex gap-2">
                        <input
                            type="text"
                            value={quickScanIp}
                            onChange={(e) => setQuickScanIp(e.target.value)}
                            placeholder="192.168.1.100"
                            className="flex-1 bg-slate-700 border border-slate-600 rounded px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
                        />
                        <button
                            onClick={quickScan}
                            disabled={!quickScanIp}
                            className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded font-medium transition disabled:opacity-50"
                        >
                            ⚡ Scan
                        </button>
                    </div>
                </div>

                {/* Quick Scan Result */}
                {quickScanResult && (
                    <div className={`p-3 rounded ${
                        quickScanResult.isCamera 
                            ? 'bg-green-500/10 border border-green-500/30' 
                            : 'bg-slate-700/50 border border-slate-600'
                    }`}>
                        <div className="flex items-center gap-2 mb-2">
                            <span className={quickScanResult.isCamera ? 'text-green-400' : 'text-slate-400'}>
                                {quickScanResult.isCamera ? '✅ Camera Detected!' : '❌ Not a camera'}
                            </span>
                            <span className="text-sm text-slate-500">{quickScanResult.ip}</span>
                        </div>
                        {quickScanResult.isCamera && (
                            <div className="text-sm space-y-1">
                                <div className="flex justify-between">
                                    <span className="text-slate-400">Type:</span>
                                    <span className="text-cyan-400">{quickScanResult.type}</span>
                                </div>
                                <div className="flex justify-between">
                                    <span className="text-slate-400">Manufacturer:</span>
                                    <span className="text-white">{quickScanResult.manufacturer}</span>
                                </div>
                                <div className="flex justify-between">
                                    <span className="text-slate-400">Confidence:</span>
                                    <span className={`${quickScanResult.confidence >= 80 ? 'text-green-400' : 'text-yellow-400'}`}>
                                        {quickScanResult.confidence}%
                                    </span>
                                </div>
                                <div className="flex justify-between">
                                    <span className="text-slate-400">Ports:</span>
                                    <span className="text-slate-300">{quickScanResult.ports?.join(', ')}</span>
                                </div>
                            </div>
                        )}
                    </div>
                )}

                {/* Error Display */}
                {error && (
                    <div className="p-3 bg-red-500/10 border border-red-500/30 rounded text-red-400 text-sm">
                        ❌ {error}
                    </div>
                )}

                {/* Scan Results */}
                {scanResults && (
                    <div className="space-y-3">
                        <div className="flex items-center justify-between">
                            <h4 className="text-sm font-medium text-cyan-400">
                                Discovered Cameras ({scanResults.cameras?.length || 0})
                            </h4>
                            {scanResults.elapsedSeconds && (
                                <span className="text-xs text-slate-500">
                                    {scanResults.elapsedSeconds.toFixed(1)}s
                                </span>
                            )}
                        </div>

                        {scanResults.cameras?.length > 0 ? (
                            <div className="space-y-2 max-h-60 overflow-y-auto">
                                {scanResults.cameras.map((cam, idx) => (
                                    <div 
                                        key={idx}
                                        className="p-3 bg-slate-700/50 rounded border border-slate-600 hover:border-cyan-500/50 transition cursor-pointer"
                                        onClick={() => onCameraFound?.(cam)}
                                    >
                                        <div className="flex items-center gap-2 mb-2">
                                            <span className="text-cyan-400">📹</span>
                                            <span className="font-medium text-white">{cam.ip}</span>
                                            {cam.tuyaPort && (
                                                <span className="text-xs px-1.5 py-0.5 bg-purple-500/20 text-purple-400 rounded">
                                                    Tuya
                                                </span>
                                            )}
                                            {cam.rtspSupported && (
                                                <span className="text-xs px-1.5 py-0.5 bg-blue-500/20 text-blue-400 rounded">
                                                    RTSP
                                                </span>
                                            )}
                                        </div>
                                        <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                                            <div className="flex justify-between">
                                                <span className="text-slate-400">Type:</span>
                                                <span className="text-slate-200">{cam.type}</span>
                                            </div>
                                            <div className="flex justify-between">
                                                <span className="text-slate-400">Brand:</span>
                                                <span className="text-slate-200">{cam.manufacturer}</span>
                                            </div>
                                            <div className="flex justify-between">
                                                <span className="text-slate-400">Ports:</span>
                                                <span className="text-slate-200">{cam.ports?.join(', ')}</span>
                                            </div>
                                            <div className="flex justify-between">
                                                <span className="text-slate-400">Confidence:</span>
                                                <span className={`${cam.confidence >= 80 ? 'text-green-400' : 'text-yellow-400'}`}>
                                                    {cam.confidence}%
                                                </span>
                                            </div>
                                        </div>
                                        {cam.ports?.includes(80) && (
                                            <a 
                                                href={`http://${cam.ip}`}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="mt-2 inline-block text-xs text-cyan-400 hover:text-cyan-300"
                                                onClick={(e) => e.stopPropagation()}
                                            >
                                                🌐 Open Web Interface →
                                            </a>
                                        )}
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <div className="text-center py-4 text-slate-500">
                                No cameras found on this network
                            </div>
                        )}
                    </div>
                )}

                {/* Status Bar */}
                {status && (
                    <div className="pt-3 border-t border-slate-700 text-xs text-slate-500 flex justify-between">
                        <span>
                            {status.isScanning ? '🔄 Scan in progress...' : '✓ Ready'}
                        </span>
                        {status.lastScan && (
                            <span>
                                Last scan: {new Date(status.lastScan.time).toLocaleTimeString()}
                            </span>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
};

export default CameraDiscoveryPanel;
