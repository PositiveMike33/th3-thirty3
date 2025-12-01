import React, { useState, useEffect } from 'react';

const GoogleAuthPanel = () => {
    const [googleStatus, setGoogleStatus] = useState({});
    const ACCOUNTS = ['th3thirty3@gmail.com', 'mikegauthierguillet@gmail.com', 'mgauthierguillet@gmail.com'];

    useEffect(() => {
        // Check Google Status
        fetch('http://localhost:3000/google/status')
            .then(res => res.json())
            .then(setGoogleStatus)
            .catch(console.error);
    }, []);

    const connectGoogle = (email) => {
        window.open(`http://localhost:3000/auth/google?email=${email}`, '_blank', 'width=500,height=600');
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
