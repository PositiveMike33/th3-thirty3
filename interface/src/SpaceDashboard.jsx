import React, { useState, useEffect } from 'react';
import { API_URL } from './config';

const SpaceDashboard = () => {
    const [astronomyData, setAstronomyData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [customLocation, setCustomLocation] = useState('');
    const [showPanel, setShowPanel] = useState(true);

    // Fetch astronomy data
    const fetchAstronomyData = async (location = null) => {
        setLoading(true);
        setError(null);
        try {
            const url = location 
                ? `${API_URL}/api/astronomy/location?location=${encodeURIComponent(location)}`
                : `${API_URL}/api/astronomy`;
            
            const response = await fetch(url);
            const result = await response.json();
            
            if (result.success) {
                setAstronomyData(result.data);
            } else {
                setError(result.error || 'Failed to fetch astronomy data');
            }
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchAstronomyData();
        // Refresh every 5 minutes
        const interval = setInterval(() => fetchAstronomyData(), 300000);
        return () => clearInterval(interval);
    }, []);

    const handleLocationSearch = (e) => {
        e.preventDefault();
        if (customLocation.trim()) {
            fetchAstronomyData(customLocation.trim());
        }
    };

    // Moon phase icon based on illumination
    const getMoonPhaseIcon = (illumination) => {
        if (illumination < 5) return '🌑';
        if (illumination < 25) return '🌒';
        if (illumination < 45) return '🌓';
        if (illumination < 55) return '🌔';
        if (illumination < 75) return '🌕';
        if (illumination < 95) return '🌖';
        return '🌗';
    };

    return (
        <div 
            className="flex-1 flex flex-col bg-black relative overflow-hidden"
            style={{ height: 'calc(100vh - 64px)', width: '100%' }}
        >
            {/* Header Bar (Overlay) */}
            <div className="absolute top-0 left-0 right-0 z-20 p-4 bg-gradient-to-b from-black/90 to-transparent flex justify-between items-start pointer-events-none">
                <div>
                    <h2 className="text-2xl font-bold text-cyan-400 tracking-widest uppercase glow-text drop-shadow-md">
                        Surveillance Orbitale
                    </h2>
                    <div className="text-xs text-cyan-300 font-mono opacity-80">
                        FLUX TEMPS RÉEL :: WORLDWIDE TELESCOPE
                    </div>
                </div>
                <div className="flex gap-4 text-xs font-mono text-cyan-100/70">
                    <div className="flex items-center gap-2">
                        <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse shadow-[0_0_10px_#22c55e]"></span>
                        <span>SIGNAL: OPTIMAL</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <span className="w-2 h-2 bg-red-500 rounded-full animate-ping"></span>
                        <span>ANOMALIES: 0</span>
                    </div>
                </div>
            </div>

            {/* Astronomy Panel Toggle */}
            <button
                onClick={() => setShowPanel(!showPanel)}
                className="absolute top-20 right-4 z-30 px-3 py-1.5 bg-purple-600/80 hover:bg-purple-500 text-white text-xs font-mono rounded-lg transition-all duration-300 backdrop-blur-sm border border-purple-400/30 shadow-lg shadow-purple-500/20"
            >
                {showPanel ? '◀ MASQUER' : '▶ ASTRO DATA'}
            </button>

            {/* Astronomy Data Panel */}
            {showPanel && (
                <div 
                    className="absolute top-28 right-4 z-30 w-80 bg-black/80 backdrop-blur-xl rounded-2xl border border-cyan-500/30 shadow-2xl shadow-cyan-500/10 overflow-hidden"
                    style={{ maxHeight: 'calc(100vh - 200px)' }}
                >
                    {/* Panel Header */}
                    <div className="bg-gradient-to-r from-purple-900/50 to-cyan-900/50 p-4 border-b border-cyan-500/20">
                        <div className="flex items-center gap-2">
                            <span className="text-2xl">🔭</span>
                            <div>
                                <h3 className="text-cyan-300 font-bold text-sm tracking-wider">ASTRONOMIE</h3>
                                <p className="text-xs text-gray-400 font-mono">Données Solaires & Lunaires</p>
                            </div>
                        </div>
                    </div>

                    {/* Location Search */}
                    <form onSubmit={handleLocationSearch} className="p-3 border-b border-cyan-500/10">
                        <div className="flex gap-2">
                            <input
                                type="text"
                                value={customLocation}
                                onChange={(e) => setCustomLocation(e.target.value)}
                                placeholder="Ville, Pays..."
                                className="flex-1 bg-gray-900/50 border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none transition-colors"
                            />
                            <button
                                type="submit"
                                className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold rounded-lg transition-colors"
                            >
                                🔍
                            </button>
                        </div>
                    </form>

                    {/* Content */}
                    <div className="p-4 overflow-y-auto" style={{ maxHeight: '400px' }}>
                        {loading ? (
                            <div className="flex flex-col items-center justify-center py-8">
                                <div className="w-10 h-10 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
                                <p className="text-cyan-400 text-xs mt-3 font-mono">CALCUL ORBITES...</p>
                            </div>
                        ) : error ? (
                            <div className="text-red-400 text-sm p-4 bg-red-500/10 rounded-lg border border-red-500/30">
                                <p className="font-bold mb-1">⚠️ Erreur</p>
                                <p className="text-xs opacity-80">{error}</p>
                                <button 
                                    onClick={() => fetchAstronomyData()}
                                    className="mt-3 px-3 py-1 bg-red-600 hover:bg-red-500 text-white text-xs rounded transition-colors"
                                >
                                    Réessayer
                                </button>
                            </div>
                        ) : astronomyData ? (
                            <div className="space-y-4">
                                {/* Location Info */}
                                <div className="text-center pb-3 border-b border-gray-700/50">
                                    <p className="text-cyan-400 font-bold">{astronomyData.location?.city || 'Position Actuelle'}</p>
                                    <p className="text-xs text-gray-500">{astronomyData.location?.country || ''}</p>
                                    <p className="text-xs text-gray-600 font-mono mt-1">
                                        {astronomyData.date} | {astronomyData.current_time}
                                    </p>
                                </div>

                                {/* Sun Section */}
                                <div className="bg-gradient-to-br from-orange-900/30 to-yellow-900/30 rounded-xl p-4 border border-orange-500/20">
                                    <div className="flex items-center gap-2 mb-3">
                                        <span className="text-3xl">☀️</span>
                                        <h4 className="text-orange-300 font-bold text-sm">SOLEIL</h4>
                                    </div>
                                    <div className="grid grid-cols-2 gap-3 text-xs">
                                        <div className="bg-black/30 rounded-lg p-2">
                                            <p className="text-gray-500">Lever</p>
                                            <p className="text-orange-300 font-mono font-bold">{astronomyData.sunrise || 'N/A'}</p>
                                        </div>
                                        <div className="bg-black/30 rounded-lg p-2">
                                            <p className="text-gray-500">Coucher</p>
                                            <p className="text-orange-300 font-mono font-bold">{astronomyData.sunset || 'N/A'}</p>
                                        </div>
                                        <div className="bg-black/30 rounded-lg p-2">
                                            <p className="text-gray-500">Zénith</p>
                                            <p className="text-yellow-300 font-mono font-bold">{astronomyData.solar_noon || 'N/A'}</p>
                                        </div>
                                        <div className="bg-black/30 rounded-lg p-2">
                                            <p className="text-gray-500">Durée Jour</p>
                                            <p className="text-yellow-300 font-mono font-bold">{astronomyData.day_length || 'N/A'}</p>
                                        </div>
                                        <div className="bg-black/30 rounded-lg p-2 col-span-2">
                                            <p className="text-gray-500">Altitude / Azimuth</p>
                                            <p className="text-orange-200 font-mono">
                                                {astronomyData.sun_altitude || 'N/A'}° / {astronomyData.sun_azimuth || 'N/A'}°
                                            </p>
                                        </div>
                                    </div>
                                </div>

                                {/* Moon Section */}
                                <div className="bg-gradient-to-br from-blue-900/30 to-purple-900/30 rounded-xl p-4 border border-blue-500/20">
                                    <div className="flex items-center gap-2 mb-3">
                                        <span className="text-3xl">
                                            {getMoonPhaseIcon(parseFloat(astronomyData.moon_illumination) || 0)}
                                        </span>
                                        <div>
                                            <h4 className="text-blue-300 font-bold text-sm">LUNE</h4>
                                            <p className="text-xs text-purple-400">{astronomyData.moon_phase || 'N/A'}</p>
                                        </div>
                                    </div>
                                    <div className="grid grid-cols-2 gap-3 text-xs">
                                        <div className="bg-black/30 rounded-lg p-2">
                                            <p className="text-gray-500">Lever</p>
                                            <p className="text-blue-300 font-mono font-bold">{astronomyData.moonrise || 'N/A'}</p>
                                        </div>
                                        <div className="bg-black/30 rounded-lg p-2">
                                            <p className="text-gray-500">Coucher</p>
                                            <p className="text-blue-300 font-mono font-bold">{astronomyData.moonset || 'N/A'}</p>
                                        </div>
                                        <div className="bg-black/30 rounded-lg p-2 col-span-2">
                                            <p className="text-gray-500">Illumination</p>
                                            <div className="flex items-center gap-2 mt-1">
                                                <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
                                                    <div 
                                                        className="h-full bg-gradient-to-r from-blue-500 to-purple-500 transition-all duration-500"
                                                        style={{ width: `${astronomyData.moon_illumination || 0}%` }}
                                                    ></div>
                                                </div>
                                                <span className="text-purple-300 font-mono font-bold">
                                                    {astronomyData.moon_illumination || 0}%
                                                </span>
                                            </div>
                                        </div>
                                        <div className="bg-black/30 rounded-lg p-2 col-span-2">
                                            <p className="text-gray-500">Altitude / Azimuth</p>
                                            <p className="text-blue-200 font-mono">
                                                {astronomyData.moon_altitude || 'N/A'}° / {astronomyData.moon_azimuth || 'N/A'}°
                                            </p>
                                        </div>
                                    </div>
                                </div>

                                {/* Refresh Button */}
                                <button
                                    onClick={() => fetchAstronomyData(customLocation || null)}
                                    className="w-full py-2 bg-gradient-to-r from-cyan-600 to-purple-600 hover:from-cyan-500 hover:to-purple-500 text-white text-xs font-bold rounded-lg transition-all duration-300 flex items-center justify-center gap-2"
                                >
                                    <span>🔄</span>
                                    <span>ACTUALISER</span>
                                </button>
                            </div>
                        ) : null}
                    </div>
                </div>
            )}

            {/* WWT Iframe Container (Full Screen) */}
            <div 
                className="w-full flex-1 relative z-10"
                style={{ minHeight: '100%' }}
            >
                <iframe
                    src="https://web.wwtassets.org/embed/1/wwt/"
                    title="WorldWide Telescope"
                    className="border-none"
                    style={{ width: '100%', height: '100%', position: 'absolute', top: 0, left: 0 }}
                    allowFullScreen
                    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                ></iframe>
            </div>

            {/* Subtle Corner Accents */}
            <div className="absolute top-0 right-0 w-32 h-32 bg-[radial-gradient(circle_at_top_right,rgba(34,211,238,0.1),transparent)] pointer-events-none z-10"></div>
            <div className="absolute bottom-0 left-0 w-32 h-32 bg-[radial-gradient(circle_at_bottom_left,rgba(34,211,238,0.1),transparent)] pointer-events-none z-10"></div>
        </div>
    );
};

export default SpaceDashboard;
