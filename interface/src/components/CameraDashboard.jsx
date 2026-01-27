import React, { useState, useEffect, useRef } from 'react';
import {
    Camera, Video, Activity, RefreshCw, Power,
    Settings, Maximize2, Mic, MicOff,
    ChevronUp, ChevronDown, ChevronLeft, ChevronRight,
    ZoomIn, ZoomOut, Save, MoreVertical,
    PlayCircle, PauseCircle, Film
} from 'lucide-react';
import { API_URL } from '../config';
import { useAuth } from '../contexts/AuthContext';

const CameraDashboard = () => {
    const { token } = useAuth();
    const [cameras, setCameras] = useState([]);
    const [selectedCamera, setSelectedCamera] = useState(null);
    const [systemStatus, setSystemStatus] = useState(null);
    const [loading, setLoading] = useState(false);
    const [connected, setConnected] = useState(false);
    const [viewMode, setViewMode] = useState('grid'); // grid, single
    const [ptzControlling, setPtzControlling] = useState(false);

    // Initial connection and load
    useEffect(() => {
        checkSystemStatus();
        const interval = setInterval(checkSystemStatus, 30000); // Poll status every 30s
        return () => clearInterval(interval);
    }, []);

    useEffect(() => {
        if (connected) {
            loadCameras();
        }
    }, [connected]);

    const fetchWithAuth = async (url, options = {}) => {
        const headers = {
            ...options.headers,
            'Authorization': `Bearer ${token}`
        };
        return fetch(url, { ...options, headers });
    };

    const checkSystemStatus = async () => {
        try {
            const res = await fetchWithAuth(`${API_URL}/api/netcam/status`);
            const data = await res.json();
            if (data.success) {
                setConnected(true);
                // Also get detailed system info
                const sysRes = await fetchWithAuth(`${API_URL}/api/netcam/system`);
                const sysData = await sysRes.json();
                if (sysData.success) {
                    setSystemStatus(sysData.server);
                }
            } else {
                setConnected(false);
            }
        } catch (error) {
            console.error("Status check failed", error);
            setConnected(false);
        }
    };

    const loadCameras = async () => {
        setLoading(true);
        try {
            const res = await fetchWithAuth(`${API_URL}/api/netcam/cameras`);
            const data = await res.json();
            if (data.success) {
                setCameras(data.cameras);
                if (!selectedCamera && data.cameras.length > 0) {
                    setSelectedCamera(data.cameras[0]);
                }
            }
        } catch (error) {
            console.error("Failed to load cameras", error);
        }
        setLoading(false);
    };

    const handlePtz = async (command) => {
        if (!selectedCamera || ptzControlling) return;
        setPtzControlling(true);
        try {
            await fetchWithAuth(`${API_URL}/api/netcam/cameras/${selectedCamera.id}/ptz`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command })
            });
        } catch (error) {
            console.error("PTZ failed", error);
        }
        setTimeout(() => setPtzControlling(false), 500);
    };

    const toggleRecording = async (camId, currentStatus) => {
        try {
            await fetchWithAuth(`${API_URL}/api/netcam/cameras/${camId}/recording`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ start: !currentStatus })
            });
            loadCameras(); // Refresh state
        } catch (error) {
            console.error("Recording toggle failed", error);
        }
    };

    if (!connected) {
        return (
            <div className="flex flex-col items-center justify-center h-full p-8 text-center bg-gray-900/50 rounded-xl border border-gray-800 backdrop-blur-sm">
                <Camera size={64} className="text-gray-600 mb-4" />
                <h2 className="text-2xl font-bold text-white mb-2">Surveillance System Offline</h2>
                <p className="text-gray-400 max-w-md mb-6">
                    Unable to connect to Netcam Studio server. Please ensure the service is running on the host machine.
                </p>
                <button
                    onClick={checkSystemStatus}
                    className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg flex items-center gap-2 transition-colors"
                >
                    <RefreshCw size={18} />
                    Retry Connection
                </button>
            </div>
        );
    }

    return (
        <div className="flex flex-col h-full bg-black/20 text-white">
            {/* Toolbar */}
            <div className="flex items-center justify-between p-4 border-b border-gray-800 bg-black/40 backdrop-blur-md">
                <div className="flex items-center gap-4">
                    <div className="flex items-center gap-2 px-3 py-1 bg-green-900/30 border border-green-700/50 rounded-full">
                        <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                        <span className="text-xs font-mono text-green-400">SYSTEM ONLINE</span>
                    </div>
                    {systemStatus && (
                        <div className="flex gap-4 text-xs text-gray-400 font-mono hidden md:flex">
                            <span>CPU: {systemStatus.cpu}%</span>
                            <span>RAM: {systemStatus.memory}%</span>
                            <span>Active Sources: {systemStatus.activeSources}</span>
                        </div>
                    )}
                </div>

                <div className="flex items-center gap-2">
                    <button
                        onClick={() => setViewMode(viewMode === 'grid' ? 'single' : 'grid')}
                        className="p-2 hover:bg-gray-800 rounded-lg text-gray-400 hover:text-white transition-colors"
                        title={viewMode === 'grid' ? "Switch to Single View" : "Switch to Grid View"}
                    >
                        {viewMode === 'grid' ? <Maximize2 size={20} /> : <Settings size={20} />}
                    </button>
                    <button
                        onClick={loadCameras}
                        className={`p-2 hover:bg-gray-800 rounded-lg text-gray-400 hover:text-white transition-colors ${loading ? 'animate-spin' : ''}`}
                    >
                        <RefreshCw size={20} />
                    </button>
                </div>
            </div>

            <div className="flex flex-1 overflow-hidden">
                {/* Camera Grid / View */}
                <div className={`flex-1 p-4 overflow-y-auto ${viewMode === 'grid' ? 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4' : 'flex flex-col'}`}>

                    {viewMode === 'single' && selectedCamera && (
                        <div className="relative flex-1 bg-black rounded-xl overflow-hidden border border-gray-800 shadow-2xl">
                            <img
                                src={selectedCamera.streamUrl}
                                alt={selectedCamera.name}
                                className="w-full h-full object-contain"
                                onError={(e) => {
                                    e.target.onerror = null;
                                    e.target.src = "https://via.placeholder.com/800x600?text=No+Signal";
                                }}
                            />

                            {/* Overlay Info */}
                            <div className="absolute top-4 left-4 flex items-center gap-2">
                                <span className="px-2 py-1 bg-black/60 rounded text-xs font-mono text-red-500 flex items-center gap-1">
                                    <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse"></div>
                                    LIVE
                                </span>
                                <span className="px-2 py-1 bg-black/60 rounded text-xs font-bold text-white">
                                    {selectedCamera.name}
                                </span>
                            </div>

                            {/* PTZ Controls Overlay (if enabled) */}
                            <div className="absolute bottom-8 right-8 flex flex-col items-center gap-2 bg-black/50 p-4 rounded-full backdrop-blur-sm border border-white/10">
                                <button onClick={() => handlePtz('up')} className="p-2 hover:bg-white/20 rounded-full"><ChevronUp size={24} /></button>
                                <div className="flex gap-4">
                                    <button onClick={() => handlePtz('left')} className="p-2 hover:bg-white/20 rounded-full"><ChevronLeft size={24} /></button>
                                    <div className="w-8 h-8 rounded-full bg-white/10"></div>
                                    <button onClick={() => handlePtz('right')} className="p-2 hover:bg-white/20 rounded-full"><ChevronRight size={24} /></button>
                                </div>
                                <button onClick={() => handlePtz('down')} className="p-2 hover:bg-white/20 rounded-full"><ChevronDown size={24} /></button>

                                <div className="flex items-center gap-2 mt-2 pt-2 border-t border-white/10 w-full justify-center">
                                    <button onClick={() => handlePtz('zoomin')} className="p-2 hover:bg-white/20 rounded-full"><ZoomIn size={20} /></button>
                                    <button onClick={() => handlePtz('zoomout')} className="p-2 hover:bg-white/20 rounded-full"><ZoomOut size={20} /></button>
                                </div>
                            </div>
                        </div>
                    )}

                    {viewMode === 'grid' && cameras.map(cam => (
                        <div
                            key={cam.id}
                            className={`relative bg-black rounded-lg overflow-hidden border transition-all cursor-pointer group ${selectedCamera?.id === cam.id ? 'border-blue-500 ring-1 ring-blue-500' : 'border-gray-800 hover:border-gray-600'}`}
                            onClick={() => { setSelectedCamera(cam); setViewMode('single'); }}
                        >
                            <div className="aspect-video bg-gray-900 relative">
                                <img
                                    src={cam.streamUrl}
                                    alt={cam.name}
                                    className="w-full h-full object-cover opacity-90 group-hover:opacity-100 transition-opacity"
                                    loading="lazy"
                                />
                                <div className="absolute inset-0 bg-gradient-to-t from-black/80 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity flex items-end justify-between p-3">
                                    <div className="flex gap-2">
                                        <button
                                            onClick={(e) => { e.stopPropagation(); toggleRecording(cam.id, cam.recording); }}
                                            className={`p-1.5 rounded-full ${cam.recording ? 'bg-red-500 text-white' : 'bg-gray-700/50 text-gray-300 hover:bg-red-500/50 hover:text-white'}`}
                                            title={cam.recording ? "Stop Recording" : "Start Recording"}
                                        >
                                            <div className={`w-2 h-2 rounded-full ${cam.recording ? 'bg-white' : 'bg-current'}`} />
                                        </button>
                                        <button className="p-1.5 rounded-full bg-gray-700/50 text-gray-300 hover:bg-blue-500/50 hover:text-white">
                                            <Maximize2 size={12} />
                                        </button>
                                    </div>
                                </div>
                            </div>
                            <div className="p-3 bg-gray-900 border-t border-gray-800 flex justify-between items-center">
                                <div className="flex flex-col">
                                    <span className="text-sm font-bold text-gray-200">{cam.name}</span>
                                    <span className="text-[10px] text-gray-500 uppercase">{cam.type}</span>
                                </div>
                                <div className="flex items-center gap-2">
                                    {cam.recording && <Film size={14} className="text-red-500 animate-pulse" />}
                                    {cam.motionDetection && <Activity size={14} className="text-blue-500" />}
                                    <div className={`w-2 h-2 rounded-full ${cam.enabled ? 'bg-green-500' : 'bg-gray-600'}`}></div>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>

                {/* Sidebar (Only in Single View) */}
                {viewMode === 'single' && (
                    <div className="w-64 bg-black/40 border-l border-gray-800 flex flex-col backdrop-blur-md">
                        <div className="p-4 border-b border-gray-800">
                            <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-2">Cameras</h3>
                            <div className="space-y-1">
                                {cameras.map(cam => (
                                    <button
                                        key={cam.id}
                                        onClick={() => setSelectedCamera(cam)}
                                        className={`w-full flex items-center justify-between p-2 rounded text-left text-sm transition-colors ${selectedCamera?.id === cam.id ? 'bg-blue-600/20 text-blue-400 border border-blue-600/30' : 'hover:bg-gray-800 text-gray-300'}`}
                                    >
                                        <div className="flex items-center gap-2 truncate">
                                            <Camera size={14} />
                                            <span className="truncate">{cam.name}</span>
                                        </div>
                                        {cam.recording && <div className="w-1.5 h-1.5 bg-red-500 rounded-full"></div>}
                                    </button>
                                ))}
                            </div>
                        </div>

                        {selectedCamera && (
                            <div className="p-4">
                                <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-3">Quick Actions</h3>
                                <div className="grid grid-cols-2 gap-2">
                                    <button
                                        onClick={() => toggleRecording(selectedCamera.id, selectedCamera.recording)}
                                        className={`p-3 rounded-lg flex flex-col items-center justify-center gap-1 border transition-all ${selectedCamera.recording ? 'bg-red-900/20 border-red-500/50 text-red-400' : 'bg-gray-800 border-gray-700 hover:bg-gray-700'}`}
                                    >
                                        <Film size={20} />
                                        <span className="text-[10px]">{selectedCamera.recording ? 'Stop Rec' : 'Record'}</span>
                                    </button>
                                    <button className="p-3 rounded-lg flex flex-col items-center justify-center gap-1 bg-gray-800 border border-gray-700 hover:bg-gray-700 transition-all">
                                        <Activity size={20} className="text-blue-400" />
                                        <span className="text-[10px]">Motion</span>
                                    </button>
                                    <button className="p-3 rounded-lg flex flex-col items-center justify-center gap-1 bg-gray-800 border border-gray-700 hover:bg-gray-700 transition-all">
                                        <Camera size={20} className="text-green-400" />
                                        <span className="text-[10px]">Snapshot</span>
                                    </button>
                                    <button className="p-3 rounded-lg flex flex-col items-center justify-center gap-1 bg-gray-800 border border-gray-700 hover:bg-gray-700 transition-all">
                                        <Settings size={20} className="text-gray-400" />
                                        <span className="text-[10px]">Config</span>
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
};

export default CameraDashboard;
