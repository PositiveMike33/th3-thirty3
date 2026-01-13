import React from 'react';
import WWTMapComponent from './components/WWTMapComponent';

const SpaceDashboard = () => {
    return (
        <div
            className="flex-1 flex flex-col bg-black relative overflow-hidden"
            style={{ height: 'calc(100vh - 64px)', width: '100%' }}
        >
            {/* WWT Component (Full Screen) */}
            <div className="w-full h-full relative z-10">
                <WWTMapComponent />
            </div>

            {/* Subtle Corner Accents - kept for aesthetic continuity if desired, or can be removed if WWTMapComponent has its own borders */}
            <div className="absolute top-0 right-0 w-32 h-32 bg-[radial-gradient(circle_at_top_right,rgba(34,211,238,0.1),transparent)] pointer-events-none z-0"></div>
            <div className="absolute bottom-0 left-0 w-32 h-32 bg-[radial-gradient(circle_at_bottom_left,rgba(34,211,238,0.1),transparent)] pointer-events-none z-0"></div>
        </div>
    );
};

export default SpaceDashboard;
