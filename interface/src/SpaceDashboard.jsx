import React from 'react';

const SpaceDashboard = () => {
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
