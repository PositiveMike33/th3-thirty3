import React, { useState, useEffect } from 'react';
import { API_URL } from '../config';

const GoogleAuthPanel = () => {
    const [googleStatus, setGoogleStatus] = useState({});
    const [loading, setLoading] = useState(true);
    
    const ACCOUNTS = [
        'mikegauthierguillet@gmail.com',
        'th3thirty3@gmail.com', 
        'mgauthierguillet@gmail.com'
    ];

    useEffect(() => {
        fetchGoogleStatus();
        const interval = setInterval(fetchGoogleStatus, 30000);
        return () => clearInterval(interval);
    }, []);

    const fetchGoogleStatus = async () => {
        try {
            const response = await fetch(API_URL + '/api/google/status');
            if (response.ok) {
                const data = await response.json();
                const statusMap = {};
                if (data.accounts) {
                    data.accounts.forEach(account => {
                        statusMap[account.email] = account.connected;
                    });
                }
                setGoogleStatus(statusMap);
            }
        } catch (error) {
            console.error('[GoogleAuthPanel] Error:', error);
        } finally {
            setLoading(false);
        }
    };

    const connectGoogle = async (email) => {
        try {
            const response = await fetch(API_URL + '/api/google/auth/' + encodeURIComponent(email));
            if (response.ok) {
                const data = await response.json();
                if (data.authUrl) {
                    window.open(data.authUrl, '_blank');
                }
            }
        } catch (error) {
            console.error('[GoogleAuthPanel] Error:', error);
        }
    };

    if (loading) {
        return <div className="text-xs text-gray-500">Loading...</div>;
    }

    return (
        <div className="space-y-1">
            <span className="text-xs text-gray-500 uppercase tracking-widest">Comptes Google</span>
            <div className="flex flex-col gap-1 mt-1">
                {ACCOUNTS.map((email) => {
                    const isConnected = googleStatus[email] === true;
                    const shortName = email.split('@')[0];
                    return (
                        <button
                            key={email}
                            onClick={() => !isConnected && connectGoogle(email)}
                            title={email}
                            className={isConnected 
                                ? 'text-xs px-2 py-1 rounded border bg-green-900/20 border-green-900 text-green-400' 
                                : 'text-xs px-2 py-1 rounded border bg-red-900/20 border-red-900 text-red-500 hover:bg-red-900/40'}
                        >
                            {shortName} {isConnected ? 'OK' : 'X'}
                        </button>
                    );
                })}
            </div>
        </div>
    );
};

export default GoogleAuthPanel;
