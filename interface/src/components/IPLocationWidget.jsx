/**
 * IP Location Widget Component
 * Displays user's IP info using iplocation.net API
 */

import { useEffect, useRef, useState } from 'react';

const IPLocationWidget = ({ 
    display = 'LIPFB',  // L:Location, I:ISP, P:Proxy, F:Platform, B:Browser
    width = 350,
    className = '',
    showRefresh = true
}) => {
    const containerRef = useRef(null);
    const [isLoaded, setIsLoaded] = useState(false);
    const [error, setError] = useState(null);

    // API Key for iplocation.net
    const API_KEY = 'wosTmWLXYjYuE//UCr/N4nUAp0NrfIFluBFBdzHeG6M=';

    useEffect(() => {
        loadWidget();
    }, [display, width]);

    const loadWidget = () => {
        setIsLoaded(false);
        setError(null);

        try {
            // Clear previous widget
            if (containerRef.current) {
                containerRef.current.innerHTML = '<div id="iplocation"></div>';
            }

            // Remove existing script if any
            const existingScript = document.getElementById('ipWidget');
            if (existingScript) {
                existingScript.remove();
            }

            // Create and load the script
            const script = document.createElement('script');
            script.id = 'ipWidget';
            script.src = 'https://www.iplocation.net/widget.js';
            script.type = 'text/javascript';
            script.setAttribute('data-display', display);
            script.setAttribute('data-width', width.toString());
            script.setAttribute('data-key', API_KEY);
            
            script.onload = () => {
                setIsLoaded(true);
            };

            script.onerror = () => {
                setError('Failed to load IP widget');
            };

            document.body.appendChild(script);

        } catch (err) {
            setError(err.message);
        }
    };

    return (
        <div className={`ip-location-widget ${className}`}>
            <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-semibold text-gray-400">
                    🌐 IP Information
                </h3>
                {showRefresh && (
                    <button 
                        onClick={loadWidget}
                        className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                        title="Refresh IP info"
                    >
                        ↻ Refresh
                    </button>
                )}
            </div>
            
            {error && (
                <div className="text-red-400 text-xs p-2 bg-red-900/20 rounded">
                    {error}
                </div>
            )}
            
            <div 
                ref={containerRef} 
                className="bg-gray-800/50 rounded-lg p-2 border border-gray-700"
                style={{ minHeight: '80px' }}
            >
                <div id="iplocation"></div>
                {!isLoaded && !error && (
                    <div className="text-gray-500 text-xs animate-pulse">
                        Loading IP information...
                    </div>
                )}
            </div>
        </div>
    );
};

export default IPLocationWidget;
