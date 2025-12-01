import React from 'react';

const PatternModal = ({ isOpen, onClose, patternName, content }) => {
    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-black/90 backdrop-blur-md flex items-center justify-center z-50 p-4">
            <div className="bg-[#0a0a0a] border border-green-500/50 rounded-lg w-full max-w-4xl h-[85vh] flex flex-col shadow-[0_0_50px_rgba(0,255,65,0.2)] animate-fade-in-up">

                {/* Header */}
                <div className="flex justify-between items-center p-6 border-b border-green-900/50 bg-[#111] rounded-t-lg">
                    <div className="flex flex-col">
                        <span className="text-xs text-green-600 font-mono tracking-widest mb-1">FABRIC_PROTOCOL // VIEWER</span>
                        <h3 className="text-green-400 font-mono font-bold text-2xl tracking-tight">
                            {patternName ? patternName.toUpperCase() : "UNKNOWN_PATTERN"}
                        </h3>
                    </div>
                    <button
                        onClick={onClose}
                        className="text-green-700 hover:text-green-400 hover:bg-green-900/20 rounded-full p-2 transition-all"
                    >
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                {/* Content */}
                <div className="flex-1 overflow-y-auto p-8 custom-scrollbar bg-[#050505]">
                    <div className="prose prose-invert max-w-none">
                        <pre className="font-mono text-sm md:text-base text-green-300/90 whitespace-pre-wrap leading-relaxed font-medium">
                            {content || "Chargement des données du pattern..."}
                        </pre>
                    </div>
                </div>

                {/* Footer */}
                <div className="p-4 border-t border-green-900/50 bg-[#111] rounded-b-lg flex justify-between items-center">
                    <span className="text-[10px] text-green-800 font-mono">SYSTEM_ID: THIRTY3 // PATTERN_DB</span>
                    <button
                        onClick={onClose}
                        className="px-6 py-2 bg-green-900/20 text-green-400 border border-green-500/50 rounded hover:bg-green-500/20 hover:text-green-300 transition-all font-mono text-xs tracking-wider uppercase"
                    >
                        Fermer le Terminal
                    </button>
                </div>
            </div>
        </div>
    );
};

export default PatternModal;
