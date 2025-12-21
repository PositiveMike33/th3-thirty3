import React, { useState, useEffect } from 'react';
import { API_URL } from '../config';

const ModelSelector = ({ onSelectModel, currentModel, currentProvider }) => {
    const [models, setModels] = useState({ local: [], cloud: [] });
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
                className="flex items-center gap-2 bg-[#111] border border-gray-700 hover:border-gray-500 text-xs px-2 py-1 rounded-md transition-all text-gray-300 max-w-[180px]"
            >
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${currentProvider === 'local' ? 'bg-green-500' : 'bg-blue-500'}`}></span>
                <span className="font-mono uppercase truncate text-[10px]">{currentModel || 'MODEL'}</span>
                <span className="text-[8px] opacity-50 flex-shrink-0">▼</span>
            </button>

            {isOpen && (
                <>
                    {/* Backdrop */}
                    <div className="fixed inset-0 z-[99]" onClick={() => setIsOpen(false)} />
                    
                    {/* Dropdown - 250px with scroll to access ALL models */}
                    <div 
                        className="absolute top-full left-0 mt-1 w-60 bg-[#1a1a1a] border border-gray-700 rounded-lg shadow-2xl z-[100] overflow-hidden"
                        style={{ maxHeight: '250px' }}
                    >
                        <div 
                            className="overflow-y-auto scrollbar-thin scrollbar-thumb-gray-600 scrollbar-track-gray-900" 
                            style={{ maxHeight: '250px' }}
                        >
                            {/* LOCAL - All models */}
                            <div className="px-2 py-1 bg-[#111] border-b border-gray-800 sticky top-0 z-10">
                                <span className="text-[9px] text-green-500 font-bold">🖥️ LOCAL ({models.local.length})</span>
                            </div>
                            {models.local.map(model => (
                                <button
                                    key={model}
                                    onClick={() => handleSelect(model, 'local')}
                                    className={`w-full text-left px-2 py-0.5 text-[10px] font-mono truncate ${currentModel === model ? 'bg-green-900/40 text-green-400' : 'text-gray-400 hover:bg-gray-800'}`}
                                >
                                    {model}
                                </button>
                            ))}

                            {/* CLOUD - All models */}
                            <div className="px-2 py-1 bg-[#111] border-y border-gray-800 sticky top-0 z-10">
                                <span className="text-[9px] text-blue-500 font-bold">☁️ CLOUD ({models.cloud.filter(m => m.provider !== 'anythingllm').length})</span>
                            </div>
                            {models.cloud.filter(m => m.provider !== 'anythingllm').map(model => (
                                <button
                                    key={model.id}
                                    onClick={() => handleSelect(model.id, model.provider)}
                                    className={`w-full text-left px-2 py-0.5 text-[10px] font-mono truncate flex justify-between ${currentModel === model.id ? 'bg-blue-900/40 text-blue-400' : 'text-gray-400 hover:bg-gray-800'}`}
                                >
                                    <span className="truncate">{model.name}</span>
                                    <span className="text-[7px] text-gray-600 ml-1">{model.provider}</span>
                                </button>
                            ))}

                            {/* AGENTS - All agents */}
                            {models.cloud.some(m => m.provider === 'anythingllm') && (
                                <>
                                    <div className="px-2 py-1 bg-[#111] border-y border-gray-800 sticky top-0 z-10">
                                        <span className="text-[9px] text-purple-500 font-bold">🤖 AGENTS ({models.cloud.filter(m => m.provider === 'anythingllm').length})</span>
                                    </div>
                                    {models.cloud.filter(m => m.provider === 'anythingllm').map(model => (
                                        <button
                                            key={model.id}
                                            onClick={() => handleSelect(model.id, model.provider)}
                                            className={`w-full text-left px-2 py-0.5 text-[10px] font-mono truncate ${currentModel === model.id ? 'bg-purple-900/40 text-purple-400' : 'text-gray-400 hover:bg-gray-800'}`}
                                        >
                                            {model.name}
                                        </button>
                                    ))}
                                </>
                            )}
                        </div>
                    </div>
                </>
            )}
        </div>
    );
};

export default ModelSelector;
