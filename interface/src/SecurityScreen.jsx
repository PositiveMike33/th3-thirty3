import React, { useState } from 'react';

const SecurityScreen = ({ onUnlock }) => {
    const [pin, setPin] = useState('');
    const [error, setError] = useState(false);

    const handleUnlock = (e) => {
        e.preventDefault();
        // Simple "33" based password or just unlock for now since user didn't specify a code
        if (pin === '3333' || pin === '33') {
            onUnlock();
        } else {
            setError(true);
            setTimeout(() => setError(false), 1000);
            setPin('');
        }
    };

    return (
        <div className="fixed inset-0 z-50 overflow-hidden flex flex-col items-center justify-end pb-20">
            {/* Full Screen Background Image */}
            <div className="absolute inset-0 z-0">
                <img
                    src="/logo_security_clean.png"
                    alt="Security Background"
                    className="w-full h-full object-cover"
                />
                {/* Dark overlay for readability if needed, adjustable opacity */}
                <div className="absolute inset-0 bg-black/30"></div>
            </div>

            <div className="relative z-10 flex flex-col items-center w-full h-full justify-end pb-32">
                {/* The controls are positioned at the bottom to match the image layout */}

                <form onSubmit={handleUnlock} className="flex flex-row items-center gap-4 bg-black/40 p-2 rounded-xl backdrop-blur-md border border-purple-500/30 shadow-[0_0_30px_rgba(147,51,234,0.3)]">
                    <input
                        type="password"
                        value={pin}
                        onChange={(e) => setPin(e.target.value)}
                        placeholder="Enter PIN or Password"
                        className={`bg-transparent border-b-2 ${error ? 'border-red-500 animate-shake' : 'border-purple-400/50 focus:border-purple-200'} px-4 py-2 text-white font-serif text-lg placeholder:text-purple-300/70 placeholder:font-serif outline-none w-64 transition-all`}
                        autoFocus
                    />
                    <button
                        type="submit"
                        className="px-6 py-2 border border-purple-400 text-purple-100 font-serif uppercase tracking-widest text-sm hover:bg-purple-500/20 hover:shadow-[0_0_15px_rgba(168,85,247,0.5)] transition-all rounded-sm"
                    >
                        UNLOCK
                    </button>
                </form>
            </div>
        </div>
    );
};

export default SecurityScreen;
