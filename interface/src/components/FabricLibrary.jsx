import React, { useState, useEffect } from 'react';
import { X, Search, BookOpen, ChevronRight } from 'lucide-react';

const FabricLibrary = ({ isOpen, onClose, onSelectPattern }) => {
    const [patterns, setPatterns] = useState([]);
    const [searchTerm, setSearchTerm] = useState('');
    const [loading, setLoading] = useState(true);
    const [selectedCategory, setSelectedCategory] = useState('all');

    useEffect(() => {
        if (isOpen) {
            setLoading(true);
            fetch('http://localhost:3000/patterns')
                .then(res => res.json())
                .then(data => {
                    setPatterns(data.sort());
                    setLoading(false);
                })
                .catch(err => {
                    console.error("Failed to load patterns", err);
                    setLoading(false);
                });
        }
    }, [isOpen]);

    const filteredPatterns = patterns.filter(p =>
        p.toLowerCase().includes(searchTerm.toLowerCase())
    );

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
            <div className="bg-gray-900 border border-cyan-500/50 rounded-xl w-full max-w-4xl h-[80vh] flex flex-col shadow-[0_0_50px_rgba(8,145,178,0.3)] animate-in zoom-in-95 duration-200">

                {/* Header */}
                <div className="p-6 border-b border-cyan-900/50 flex justify-between items-center bg-black/40 rounded-t-xl">
                    <div className="flex items-center gap-3">
                        <BookOpen className="text-cyan-400" size={24} />
                        <div>
                            <h2 className="text-xl font-bold text-cyan-100 tracking-wider">BIBLIOTHÈQUE FABRIC</h2>
                            <p className="text-xs text-cyan-500 uppercase tracking-widest">Prompts & Patterns Stratégiques</p>
                        </div>
                    </div>
                    <button onClick={onClose} className="text-gray-500 hover:text-red-400 transition-colors">
                        <X size={24} />
                    </button>
                </div>

                {/* Search Bar */}
                <div className="p-4 bg-gray-900/50 border-b border-cyan-900/30">
                    <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={18} />
                        <input
                            type="text"
                            placeholder="Rechercher un pattern (ex: analyze_claims, extract_wisdom)..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full bg-black/50 border border-gray-700 rounded-lg py-3 pl-10 pr-4 text-cyan-100 placeholder-gray-600 focus:outline-none focus:border-cyan-500 transition-all"
                            autoFocus
                        />
                    </div>
                </div>

                {/* Content Grid */}
                <div className="flex-1 overflow-y-auto p-6 bg-[url('/grid.png')]">
                    {loading ? (
                        <div className="flex justify-center items-center h-full text-cyan-500 animate-pulse">
                            Chargement de la base de données...
                        </div>
                    ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                            {filteredPatterns.map(pattern => (
                                <button
                                    key={pattern}
                                    onClick={() => {
                                        onSelectPattern(pattern);
                                        onClose();
                                    }}
                                    className="group text-left bg-gray-800/50 hover:bg-cyan-900/20 border border-gray-700 hover:border-cyan-500/50 p-4 rounded-lg transition-all hover:scale-[1.02] hover:shadow-lg flex flex-col gap-2"
                                >
                                    <div className="flex justify-between items-start w-full">
                                        <span className="font-mono font-bold text-cyan-300 group-hover:text-cyan-100 truncate w-full">
                                            {pattern}
                                        </span>
                                        <ChevronRight size={16} className="text-gray-600 group-hover:text-cyan-400 opacity-0 group-hover:opacity-100 transition-all" />
                                    </div>
                                    <div className="text-xs text-gray-500 group-hover:text-gray-400 line-clamp-2">
                                        Pattern système pour {pattern.replace(/_/g, ' ')}.
                                    </div>
                                </button>
                            ))}
                            {filteredPatterns.length === 0 && (
                                <div className="col-span-full text-center text-gray-500 py-10">
                                    Aucun pattern trouvé pour "{searchTerm}".
                                </div>
                            )}
                        </div>
                    )}
                </div>

                {/* Footer */}
                <div className="p-4 border-t border-cyan-900/30 bg-black/40 rounded-b-xl text-xs text-gray-500 flex justify-between">
                    <span>{filteredPatterns.length} Patterns disponibles</span>
                    <span>Powered by Fabric</span>
                </div>
            </div>
        </div>
    );
};

export default FabricLibrary;
