import React from 'react';

const SpaceDashboard = () => {
    return (
        <div className="flex-1 flex flex-col h-full bg-black relative overflow-hidden">
            {/* Header Bar (Non-overlapping) */}
            <div className="z-20 p-3 bg-black/90 border-b border-cyan-900/50 flex justify-between items-end shrink-0">
                <div>
                    <h2 className="text-xl font-bold text-cyan-400 tracking-widest uppercase glow-text">
                        Surveillance Orbitale
                    </h2>
                    <div className="text-[10px] text-cyan-700 font-mono">
                        FLUX TEMPS RÉEL :: WORLDWIDE TELESCOPE
                    </div>
                </div>
                <div className="flex gap-4 text-[10px] font-mono text-gray-500">
                    <div className="flex items-center gap-2">
                        <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></span>
                        <span>SIGNAL: OPTIMAL</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <span className="w-1.5 h-1.5 bg-red-500 rounded-full animate-ping"></span>
                        <span>ANOMALIES: 0</span>
                    </div>
                </div>
            </div>

            {/* WWT Iframe Container */}
            <div className="flex-1 w-full relative z-10 overflow-hidden">
                <iframe
                    src="https://worldwidetelescope.org/webclient/"
                    title="WorldWide Telescope"
                    className="w-full h-full border-none"
                    allowFullScreen
                ></iframe>
            </div>

            {/* Corner Accents */}
            <div className="absolute top-4 right-4 w-16 h-16 border-t-2 border-r-2 border-cyan-500/30 rounded-tr-xl pointer-events-none z-20"></div>
            <div className="absolute bottom-4 left-4 w-16 h-16 border-b-2 border-l-2 border-cyan-500/30 rounded-bl-xl pointer-events-none z-20"></div>

            {/* Scanlines */}
            <div className="absolute inset-0 bg-[url('/scanlines.png')] opacity-10 pointer-events-none z-30 mix-blend-overlay"></div>
        </div>
    );
};

export default SpaceDashboard;
