import React from 'react';
import { Maximize, ExternalLink } from 'lucide-react';

const WWTMapComponent = () => {
    return (
        <div className="w-full h-full bg-black relative overflow-hidden">
            <iframe
                src="https://worldwidetelescope.org/webclient/?wtml=http://www.worldwidetelescope.org/wwtweb/catalog.aspx?W=Sky"
                title="WorldWide Telescope"
                className="absolute left-0 right-0 border-none"
                style={{
                    top: '-110px',        // Hide the top header/tabs
                    height: 'calc(100% + 250px)', // Increase height to push bottom UI off-screen
                    width: '100%'
                }}
                allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; fullscreen"
                allowFullScreen
            />
        </div>
    );
};

const GlobeIcon = ({ className }) => (
    <svg
        xmlns="http://www.w3.org/2000/svg"
        width="24"
        height="24"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        className={className}
    >
        <circle cx="12" cy="12" r="10" />
        <line x1="2" x2="22" y1="12" y2="12" />
        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </svg>
);

export default WWTMapComponent;
