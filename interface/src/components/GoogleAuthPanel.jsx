import React, { useState, useEffect } from 'react';
import { API_URL } from '../config';
import { api } from '../services/apiService';

const GoogleAuthPanel = () => {
    const [googleStatus, setGoogleStatus] = useState({});
    const ACCOUNTS = ['th3thirty3@gmail.com', 'mikegauthierguillet@gmail.com', 'mgauthierguillet@gmail.com'];

    useEffect(() => {
        // Check Google Status using API Service
        api.get('/google/status')
            .then(setGoogleStatus)
            .catch(err => console.error("Status check failed:", err));
    }, []);

    const connectGoogle = (email) => {
        window.open(`${API_URL}/auth/google?email=${email}`, '_blank', 'width=500,height=600');
    };

    return (
        <div className="flex gap-2 mt-2">
            {ACCOUNTS.map(email => (
                <button
                    key={email}
                    onClick={() => googleStatus && !googleStatus[email] && connectGoogle(email)}
                    className={`text-[8px] px-2 py-1 rounded border ${(googleStatus && googleStatus[email])
                        ? 'bg-green-900/50 border-green-500 text-green-300 cursor-default'
                        : 'bg-red-900/20 border-red-900 text-red-500 hover:bg-red-900/40'
                        }`}
                    title={email}
                >
                    {email.split('@')[0]} {(googleStatus && googleStatus[email]) ? '✓' : '✗'}
                </button>
            ))}
        </div>
    );
};

export default GoogleAuthPanel;
