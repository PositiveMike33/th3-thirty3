import React, { useState, useEffect } from 'react';
import { API_URL } from '../config';

const ModelSelector = ({ onSelectModel, currentModel, currentProvider }) => {
    const [models, setModels] = useState({ cloud: [] });
    const [isOpen, setIsOpen] = useState(false);

    useEffect(() => {
        fetch(`${API_URL}/models`)
            .then(res => res.json())
            .then(data => {
                setModels(data);
            })
            .catch(err => {
                console.error("Failed to load models", err);
            });
    }, []);

    const handleSelect = (modelId, provider) => {
        onSelectModel(modelId, provider);
        setIsOpen(false);
    };

    return (
        <div className="relative">
            <button
                onClick={() => setIsOpen(!isOpen)}
                className="flex items-center gap-2 bg-[#111] border border-gray-700 hover:border-gray-500 text-xs px-3 py-1.5 rounded-md transition-all text-gray-300"
            >


                {/* CLOUD MODELS */}
                <div className="p-2">
                    <div className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-1 px-2">Cloud (Public)</div>
                    {models.cloud.length === 0 && (
                        <div className="text-[10px] text-gray-600 px-2 italic">Aucun modèle (Vérifiez API Keys)</div>
                    )}
                    {models.cloud.filter(m => m.provider !== 'anythingllm').map(model => (
                        <button
                            key={model.id}
                            onClick={() => handleSelect(model.id, model.provider)}
                            className={`w-full text-left px-3 py-2 rounded text-xs font-mono mb-1 transition-colors ${currentModel === model.id ? 'bg-blue-900/30 text-blue-400' : 'text-gray-300 hover:bg-[#28292a]'}`}
                        >
                            <div className="flex justify-between items-center">
                                <span>{model.name}</span>
                                <span className="text-[8px] bg-gray-800 px-1 rounded text-gray-500">{model.provider}</span>
                            </div>
                        </button>
                    ))}
                </div>

                {/* AGENTS (AnythingLLM) */}
                {models.cloud.some(m => m.provider === 'anythingllm') && (
                    <div className="p-2 border-t border-gray-700">
                        <div className="text-[10px] font-bold text-purple-500 uppercase tracking-wider mb-1 px-2">Agents (AnythingLLM)</div>
                        {models.cloud.filter(m => m.provider === 'anythingllm').map(model => (
                            <button
                                key={model.id}
                                onClick={() => handleSelect(model.id, model.provider)}
                                className={`w-full text-left px-3 py-2 rounded text-xs font-mono mb-1 transition-colors ${currentModel === model.id ? 'bg-purple-900/30 text-purple-400' : 'text-gray-300 hover:bg-[#28292a]'}`}
                            >
                                <div className="flex justify-between items-center">
                                    <span>{model.name}</span>
                                    <span className="text-[8px] bg-gray-800 px-1 rounded text-gray-500">AGENT</span>
                                </div>
                            </button>
                        ))}
                    </div>
                )}
        </div>
                </div >
            )}
        </div >
    );
};

export default ModelSelector;
