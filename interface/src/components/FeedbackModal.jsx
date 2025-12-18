import React from 'react';

const FeedbackModal = ({ isOpen, onClose, onSubmit, value, onChange }) => {
    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50">
            <div className="bg-gray-900 border border-green-500 p-6 rounded-lg w-96 shadow-[0_0_20px_rgba(0,255,65,0.2)]">
                <h3 className="text-green-500 font-mono text-lg mb-4">Correction du Mentor</h3>
                <p className="text-gray-400 text-xs mb-2">Dis-moi ce que j'aurais dû répondre :</p>
                <textarea
                    value={value}
                    onChange={onChange}
                    className="w-full h-32 bg-black border border-green-900 rounded p-2 text-green-400 font-mono text-sm focus:outline-none focus:border-green-500 mb-4"
                    placeholder="La bonne réponse est..."
                />
                <div className="flex justify-end gap-2">
                    <button
                        onClick={onClose}
                        className="px-3 py-1 text-xs text-gray-400 hover:text-white"
                    >
                        Annuler
                    </button>
                    <button
                        onClick={onSubmit}
                        className="px-3 py-1 text-xs bg-green-900/50 text-green-400 border border-green-500 hover:bg-green-500/20 rounded"
                    >
                        Enseigner
                    </button>
                </div>
            </div>
        </div>
    );
};

export default FeedbackModal;
