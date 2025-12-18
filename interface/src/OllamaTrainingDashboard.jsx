import React, { useState, useEffect, useCallback } from 'react';
import { 
    Activity, Brain, TrendingUp, RefreshCw, 
    Zap, Clock, Target, Award, AlertTriangle, Cloud, Monitor, MessageCircle, Send
} from 'lucide-react';
import { 
    RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar,
    LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
    BarChart, Bar, Legend
} from 'recharts';
import { API_URL, OLLAMA_URL } from './config';

// Category labels
const CATEGORY_LABELS = {
    coding: 'Codage',
    intelligence: 'Intelligence',
    logic: 'Logique',
    creativity: 'Creativite',
    chat: 'Chat',
    humanizer: 'Humanisation',
    analysis: 'Analyse',
    writing: 'Redaction'
};

// Category colors
const CATEGORY_COLORS = {
    coding: '#22d3ee',
    intelligence: '#8b5cf6',
    logic: '#3b82f6',
    creativity: '#f59e0b',
    chat: '#10b981',
    humanizer: '#ec4899',
    analysis: '#f97316',
    writing: '#a855f7'
};

// Helper: Detect if model is cloud or local based on name prefix
const getProviderInfo = (modelName) => {
    if (modelName.startsWith('[')) {
        // Cloud provider format: [GROQ] model-name
        const provider = modelName.match(/\[([^\]]+)\]/)?.[1] || 'CLOUD';
        return { type: 'cloud', provider, Icon: Cloud, color: 'text-blue-400' };
    }
    return { type: 'local', provider: 'OLLAMA', Icon: Monitor, color: 'text-green-400' };
};

// Helper: Calculate overall score from expertise if null
const calculateOverallScore = (model) => {
    if (!model) return 50;
    if (model.cognitive?.overallScore && model.cognitive.overallScore !== null) {
        return model.cognitive.overallScore;
    }
    // Fallback: Calculate from expertise average
    const expertise = model.expertise || {};
    const expertiseScores = Object.values(expertise)
        .map(e => {
            if (e === null || e === undefined) return null;
            if (typeof e === 'object') return e?.score ?? null;
            if (typeof e === 'number') return e;
            return null;
        })
        .filter(s => s !== null && s !== undefined && !isNaN(s));
    if (expertiseScores.length > 0) {
        return expertiseScores.reduce((a, b) => a + b, 0) / expertiseScores.length;
    }
    return 50; // Default
};

// Helper: Check if model is an embedding model (should not appear in training)
const isEmbeddingModel = (modelName) => {
    const embeddingKeywords = ['embed', 'embedding', 'nomic-embed'];
    return embeddingKeywords.some(keyword => modelName.toLowerCase().includes(keyword));
};

const OllamaTrainingDashboard = () => {
    const [metrics, setMetrics] = useState({});
    const [loading, setLoading] = useState(true);
    const [selectedModel, setSelectedModel] = useState(null);
    const [benchmarking, setBenchmarking] = useState(false);
    const [lastUpdate, setLastUpdate] = useState(null);
    const [compareMode, setCompareMode] = useState(false);
    const [selectedModels, setSelectedModels] = useState([]);
    const [availableModels, setAvailableModels] = useState({ local: [], cloud: [] });
    const [benchmarkModel, setBenchmarkModel] = useState('');
    
    // LLM Commentary state
    const [commentary, setCommentary] = useState(null);
    const [recentCommentaries, setRecentCommentaries] = useState([]);
    const [generatingCommentary, setGeneratingCommentary] = useState(false);

    // Fetch metrics
    const fetchMetrics = useCallback(async () => {
        try {
            const res = await fetch(`${API_URL}/models/metrics`);
            const data = await res.json();
            setMetrics(data);
            setLastUpdate(new Date());
            
            // Auto-select first model if none selected
            if (!selectedModel && Object.keys(data).length > 0) {
                setSelectedModel(Object.keys(data)[0]);
            }
        } catch (error) {
            console.error('Failed to fetch metrics:', error);
        } finally {
            setLoading(false);
        }
    }, [selectedModel]);

    // Initial load and 5-second refresh
    useEffect(() => {
        fetchMetrics();
        const interval = setInterval(fetchMetrics, 5000);
        return () => clearInterval(interval);
    }, [fetchMetrics]);
    
    // Fetch ALL Ollama models ONCE on mount (for benchmark selector)
    useEffect(() => {
        fetch(`${OLLAMA_URL}/api/tags`)
            .then(res => res.json())
            .then(data => {
                const ollamaModels = (data.models || []).map(m => m.name);
                setAvailableModels({ local: ollamaModels, cloud: [] });
            })
            .catch(err => console.error('Failed to load Ollama models:', err));
    }, []); // Empty dependency = run once on mount
    
    // Fetch existing commentaries ONCE on mount
    useEffect(() => {
        fetch(`${API_URL}/training/commentary`)
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    setCommentary(data.last);
                    setRecentCommentaries(data.recent || []);
                }
            })
            .catch(err => console.error('Failed to load commentaries:', err));
    }, []); // Empty dependency = run once on mount

    // Trigger LLM Commentary
    const triggerCommentary = async () => {
        if (generatingCommentary) return;
        setGeneratingCommentary(true);
        try {
            const res = await fetch(`${API_URL}/training/commentary/trigger`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ modelName: selectedModel })
            });
            const data = await res.json();
            if (data.success && data.commentary) {
                setCommentary(data.commentary);
                setRecentCommentaries(prev => [...prev.slice(-9), data.commentary]);
            }
        } catch (error) {
            console.error('Commentary generation failed:', error);
        } finally {
            setGeneratingCommentary(false);
        }
    };

    // Run benchmark on selected model
    const runBenchmark = async (modelName) => {
        if (!modelName) return;
        setBenchmarking(true);
        try {
            await fetch(`${API_URL}/models/${encodeURIComponent(modelName)}/benchmark`, {
                method: 'POST'
            });
            await fetchMetrics();
        } catch (error) {
            console.error('Benchmark failed:', error);
        } finally {
            setBenchmarking(false);
        }
    };

    // Toggle model in comparison selection
    const toggleCompareModel = (name) => {
        setSelectedModels(prev => 
            prev.includes(name) 
                ? prev.filter(m => m !== name)
                : [...prev, name]
        );
    };

    const modelNames = Object.keys(metrics).filter(name => !isEmbeddingModel(name));
    const currentModel = selectedModel ? metrics[selectedModel] : null;

    // Prepare radar chart data - with null safety
    const radarData = (currentModel && currentModel.expertise) ? 
        Object.entries(currentModel.expertise)
            .filter(([, value]) => value !== null && value !== undefined)
            .map(([key, value]) => ({
                category: CATEGORY_LABELS[key] || key,
                score: Math.round(typeof value === 'object' ? (value?.score ?? 0) : (value ?? 0)),
                fullMark: 100
            })) : [];

    // Prepare history chart data
    const historyData = currentModel?.historyLast7Days?.slice(-24) || [];
    const chartHistory = historyData.map((h) => ({
        time: new Date(h.date).toLocaleTimeString('fr-CA', { hour: '2-digit', minute: '2-digit' }),
        score: h.cognitiveScore
    }));

    if (loading) {
        return (
            <div className="flex-1 flex items-center justify-center bg-black text-cyan-400">
                <div className="animate-pulse flex items-center gap-3">
                    <Brain className="animate-spin" />
                    Chargement des me�triques de training...
                </div>
            </div>
        );
    }

    return (
        <div className="flex-1 p-6 bg-black text-cyan-300 overflow-y-auto overflow-x-hidden bg-[url('/grid.png')]">
            {/* Header */}
            <div className="flex justify-between items-center mb-6">
                <div>
                    <h1 className="text-2xl font-bold tracking-widest flex items-center gap-3">
                        <Brain className="text-purple-500" />
                        TRAINING DASHBOARD
                    </h1>
                    <p className="text-xs text-gray-500 mt-1">
                        Suivi temps réel de tous les modèles Ollama (Flash Attention activé)
                    </p>
                </div>
                <div className="flex items-center gap-4">
                    <div className="text-xs text-gray-500">
                        Dernie�re MAJ: {lastUpdate?.toLocaleTimeString('fr-CA')}
                    </div>
                    <button 
                        onClick={() => setCompareMode(!compareMode)}
                        className={`px-3 py-1.5 text-xs rounded border transition-colors ${
                            compareMode 
                                ? 'bg-purple-900/50 border-purple-500 text-purple-300'
                                : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-purple-500'
                        }`}
                    >
                        {compareMode ? ' Comparaison' : ' Comparer'}
                    </button>
                    <button 
                        onClick={fetchMetrics}
                        className="p-2 bg-gray-800 border border-gray-700 rounded hover:border-cyan-500 transition-colors"
                    >
                        <RefreshCw size={16} className="text-cyan-400" />
                    </button>
                </div>
            </div>

            {/* Benchmark Any Model Section */}
            <div className="mb-6 p-4 bg-gray-900/50 border border-yellow-800 rounded-xl">
                <h3 className="text-sm font-bold text-yellow-400 mb-3 flex items-center gap-2">
                    <Zap size={16} />
                    Lancer un Benchmark sur n'importe quel mode�le
                </h3>
                <div className="flex gap-3 flex-wrap">
                    <select 
                        value={benchmarkModel}
                        onChange={(e) => setBenchmarkModel(e.target.value)}
                        className="flex-1 min-w-[200px] bg-black border border-gray-700 rounded px-3 py-2 text-sm text-gray-300"
                    >
                        <option value="">Sélectionner un modèle Ollama...</option>
                        <optgroup label="🧠 Cerveau (Long Terme)">
                            {availableModels.local?.filter(m => m.includes('brain') || m.includes('7b') || m.includes('8b')).map(m => (
                                <option key={m} value={m}>{m}</option>
                            ))}
                        </optgroup>
                        <optgroup label="⚡ Flash Attention (Rapide)">
                            {availableModels.local?.filter(m => m.includes('flash') || m.includes('3b') || m.includes('1b')).map(m => (
                                <option key={m} value={m}>{m}</option>
                            ))}
                        </optgroup>
                        <optgroup label="📦 Tous les modèles">
                            {availableModels.local?.filter(m => !m.includes('embed')).map(m => (
                                <option key={m} value={m}>{m}</option>
                            ))}
                        </optgroup>
                    </select>
                    <button
                        onClick={() => runBenchmark(benchmarkModel)}
                        disabled={benchmarking || !benchmarkModel}
                        className="px-4 py-2 bg-yellow-900/50 border border-yellow-600 rounded text-sm text-yellow-300 hover:bg-yellow-800/50 disabled:opacity-50 flex items-center gap-2"
                    >
                        {benchmarking ? ' Test en cours...' : ' Lancer Benchmark'}
                    </button>
                </div>
            </div>

            {modelNames.length === 0 ? (
                <div className="text-center text-gray-500 py-20">
                    <Brain size={48} className="mx-auto mb-4 opacity-50" />
                    <p>Aucune donne�e de training disponible.</p>
                    <p className="text-xs mt-2">Les me�triques s'accumuleront au fil de l'utilisation.</p>
                </div>
            ) : (
                <>
                    {/* Comparison Mode: Multi-select with chart */}
                    {compareMode && (
                        <div className="mb-6 p-4 bg-gray-900/50 border border-purple-800 rounded-xl">
                            <h3 className="text-sm font-bold text-purple-400 mb-3">
                                 Comparaison des Mode�les ({selectedModels.length} se�lectionne�s)
                            </h3>
                            <div className="flex flex-wrap gap-2 mb-4">
                                {modelNames.map(name => {
                                    const isChecked = selectedModels.includes(name);
                                    const providerInfo = getProviderInfo(name);
                                    const ProviderIcon = providerInfo.Icon;
                                    return (
                                        <label 
                                            key={name}
                                            className={`flex items-center gap-2 px-3 py-2 rounded-lg border cursor-pointer transition-all ${
                                                isChecked 
                                                    ? 'bg-purple-900/50 border-purple-500' 
                                                    : 'bg-gray-800 border-gray-700 hover:border-purple-700'
                                            }`}
                                        >
                                            <input 
                                                type="checkbox" 
                                                checked={isChecked}
                                                onChange={() => toggleCompareModel(name)}
                                                className="accent-purple-500"
                                            />
                                            <ProviderIcon size={14} className={providerInfo.color} />
                                            <span className="text-xs font-mono text-gray-300">
                                                {name.replace(/^\[[^\]]+\]\s*/, '').split(':')[0]}
                                            </span>
                                        </label>
                                    );
                                })}
                            </div>
                            {selectedModels.length > 0 && (
                                <ResponsiveContainer width="100%" height={300}>
                                    <BarChart 
                                        data={selectedModels.map(name => ({
                                            name: name.replace(/^\[[^\]]+\]\s*/, '').split(':')[0],
                                            score: Math.round(metrics[name]?.cognitive?.overallScore || 0),
                                            queries: metrics[name]?.performance?.totalQueries || 0,
                                            speed: Math.round(metrics[name]?.performance?.tokensPerSecond || 0)
                                        }))}
                                        margin={{ top: 20, right: 30, left: 20, bottom: 60 }}
                                    >
                                        <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                                        <XAxis 
                                            dataKey="name" 
                                            stroke="#666" 
                                            fontSize={10} 
                                            angle={-45} 
                                            textAnchor="end"
                                            height={60}
                                        />
                                        <YAxis stroke="#666" fontSize={10} />
                                        <Tooltip 
                                            contentStyle={{ background: '#1a1a2e', border: '1px solid #333' }}
                                        />
                                        <Legend />
                                        <Bar dataKey="score" name="Score Cognitif" fill="#a855f7" />
                                        <Bar dataKey="queries" name="Reque�tes" fill="#22d3ee" />
                                        <Bar dataKey="speed" name="Tokens/s" fill="#10b981" />
                                    </BarChart>
                                </ResponsiveContainer>
                            )}
                        </div>
                    )}

                    {/* Model Selector */}
                    <div className="flex gap-2 mb-6 overflow-x-hidden pb-2">
                        {modelNames.map(name => {
                            const model = metrics[name];
                            const isSelected = selectedModel === name;
                            const providerInfo = getProviderInfo(name);
                            const ProviderIcon = providerInfo.Icon;
                            return (
                                <button
                                    key={name}
                                    onClick={() => setSelectedModel(name)}
                                    className={`flex-shrink-0 p-3 rounded-lg border transition-all ${
                                        isSelected 
                                            ? 'bg-cyan-900/50 border-cyan-500 shadow-[0_0_15px_rgba(34,211,238,0.3)]'
                                            : 'bg-gray-900/50 border-gray-700 hover:border-cyan-700'
                                    }`}
                                >
                                    <div className="flex items-center gap-2">
                                        <ProviderIcon size={16} className={providerInfo.color} />
                                        <span className={`font-mono text-sm ${isSelected ? 'text-white' : 'text-gray-400'}`}>
                                            {name.replace(/^\[[^\]]+\]\s*/, '').split(':')[0]}
                                        </span>
                                    </div>
                                    <div className="mt-1 flex items-center gap-2">
                                        <span className={`text-2xl font-bold ${
                                            calculateOverallScore(model) >= 70 ? 'text-green-400' :
                                            calculateOverallScore(model) >= 50 ? 'text-yellow-400' : 'text-red-400'
                                        }`}>
                                            {Math.round(calculateOverallScore(model))}
                                        </span>
                                        <span className="text-xs text-gray-500">pts</span>
                                        {model.cognitive?.overallScore === null && (
                                            <span className="text-xs text-gray-600" title="Score calcule� e� partir des expertises">*</span>
                                        )}
                                    </div>
                                </button>
                            );
                        })}
                    </div>

                    {currentModel && (
                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                            {/* Main Stats */}
                            <div className="lg:col-span-2 space-y-6">
                                {/* Cognitive Score Card */}
                                <div className="bg-gray-900/50 border border-purple-800 rounded-xl p-6">
                                    <div className="flex justify-between items-start mb-4">
                                        <div>
                                            <h3 className="text-lg font-bold text-white flex items-center gap-2">
                                                <Brain className="text-purple-500" />
                                                Score Cognitif
                                            </h3>
                                            <p className="text-xs text-gray-500">Performance globale ponde�re�e</p>
                                        </div>
                                        <button
                                            onClick={() => runBenchmark(selectedModel)}
                                            disabled={benchmarking}
                                            className="px-3 py-1.5 bg-purple-900/50 border border-purple-600 rounded text-xs text-purple-300 hover:bg-purple-800/50 disabled:opacity-50"
                                        >
                                            {benchmarking ? 'Test en cours...' : ' Lancer Benchmark'}
                                        </button>
                                    </div>
                                    
                                    <div className="flex items-center gap-6">
                                        <div className="text-6xl font-bold text-purple-400">
                                            {Math.round(calculateOverallScore(currentModel))}
                                        </div>
                                        <div className="flex-1">
                                            <div className="h-4 bg-gray-800 rounded-full overflow-hidden">
                                                <div 
                                                className="h-full bg-gradient-to-r from-purple-600 to-cyan-500 transition-all duration-500"
                                                style={{ width: `${calculateOverallScore(currentModel)}%` }}
                                            />
                                            </div>
                                            <div className="flex justify-between text-xs text-gray-500 mt-1">
                                                <span>0</span>
                                                <span>100</span>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="grid grid-cols-3 gap-4 mt-4">
                                        <div className="bg-black/40 p-3 rounded-lg">
                                            <div className="text-xs text-gray-500 mb-1">Taux Apprentissage</div>
                                            <div className={`text-lg font-bold ${
                                                (currentModel.cognitive?.learningRate || 0) > 0 ? 'text-green-400' : 
                                                (currentModel.cognitive?.learningRate || 0) < 0 ? 'text-red-400' : 'text-gray-400'
                                            }`}>
                                                {(currentModel.cognitive?.learningRate || 0) > 0 ? '+' : ''}
                                                {((currentModel.cognitive?.learningRate || 0) * 100).toFixed(1)}%
                                            </div>
                                        </div>
                                        <div className="bg-black/40 p-3 rounded-lg">
                                            <div className="text-xs text-gray-500 mb-1">Consistance</div>
                                            <div className="text-lg font-bold text-cyan-400">
                                                {Math.round(currentModel.cognitive?.consistency || 0)}%
                                            </div>
                                        </div>
                                        <div className="bg-black/40 p-3 rounded-lg">
                                            <div className="text-xs text-gray-500 mb-1">Reque�tes</div>
                                            <div className="text-lg font-bold text-white">
                                                {currentModel.performance.totalQueries}
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                {/* Info Note */}
                                {currentModel.cognitive?.overallScore === null && (
                                    <div className="bg-yellow-900/20 border border-yellow-800/50 rounded-lg p-3 flex items-start gap-2">
                                        <AlertTriangle size={16} className="text-yellow-500 flex-shrink-0 mt-0.5" />
                                        <p className="text-xs text-yellow-300">
                                            <strong>Note:</strong> Le score cognitif global est calcule a partir de la moyenne des expertises disponibles (*). 
                                            Plus de requetes permettront un calcul plus precis.
                                        </p>
                                    </div>
                                )}

                                {/* History Chart */}
                                <div className="bg-gray-900/50 border border-cyan-800 rounded-xl p-6">
                                    <h3 className="text-lg font-bold text-white flex items-center gap-2 mb-4">
                                        <TrendingUp className="text-cyan-500" />
                                        Progression (24h)
                                    </h3>
                                    
                                    {chartHistory.length > 0 ? (
                                        <ResponsiveContainer width="100%" height={200}>
                                            <LineChart data={chartHistory}>
                                                <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                                                <XAxis dataKey="time" stroke="#666" fontSize={10} />
                                                <YAxis domain={[0, 100]} stroke="#666" fontSize={10} />
                                                <Tooltip 
                                                    contentStyle={{ background: '#1a1a2e', border: '1px solid #333' }}
                                                    labelStyle={{ color: '#888' }}
                                                />
                                                <Line 
                                                    type="monotone" 
                                                    dataKey="score" 
                                                    stroke="#22d3ee" 
                                                    strokeWidth={2}
                                                    dot={false}
                                                />
                                            </LineChart>
                                        </ResponsiveContainer>
                                    ) : (
                                        <div className="text-center text-gray-500 py-10">
                                            Pas assez de donne�es historiques
                                        </div>
                                    )}
                                </div>

                                {/* Learning Progress Panel */}
                                <div className="bg-gray-900/50 border border-purple-800 rounded-xl p-6">
                                    <h3 className="text-lg font-bold text-white flex items-center gap-2 mb-4">
                                        <Award className="text-purple-500" />
                                        Apprentissage Continu
                                    </h3>
                                    <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                                        <div className="bg-black/40 p-3 rounded-lg text-center">
                                            <div className="text-xs text-gray-500 mb-1">Sessions</div>
                                            <div className="text-xl font-bold text-purple-400">
                                                {currentModel.learning?.sessionsCompleted || currentModel.performance.totalQueries}
                                            </div>
                                        </div>
                                        <div className="bg-black/40 p-3 rounded-lg text-center">
                                            <div className="text-xs text-gray-500 mb-1">Tendance</div>
                                            <div className={`text-xl font-bold ${
                                                (currentModel.learning?.improvementTrend || 0) > 0 ? 'text-green-400' : 
                                                (currentModel.learning?.improvementTrend || 0) < 0 ? 'text-red-400' : 'text-yellow-400'
                                            }`}>
                                                {(currentModel.learning?.improvementTrend || 0) > 0 ? '+' : 
                                                 (currentModel.learning?.improvementTrend || 0) < 0 ? '-' : '='}
                                                {Math.abs((currentModel.learning?.improvementTrend || 0) * 100).toFixed(0)}%
                                            </div>
                                        </div>
                                        <div className="bg-black/40 p-3 rounded-lg text-center">
                                            <div className="text-xs text-gray-500 mb-1">Moy. Session</div>
                                            <div className="text-xl font-bold text-cyan-400">
                                                {Math.round(currentModel.learning?.averageSessionScore || calculateOverallScore(currentModel))}
                                            </div>
                                        </div>
                                        <div className="bg-black/40 p-3 rounded-lg text-center">
                                            <div className="text-xs text-gray-500 mb-1">Score Max</div>
                                            <div className="text-xl font-bold text-green-400">
                                                {Math.round(currentModel.learning?.peakScore || calculateOverallScore(currentModel))}
                                            </div>
                                        </div>
                                        <div className="bg-black/40 p-3 rounded-lg text-center">
                                            <div className="text-xs text-gray-500 mb-1">Croissance</div>
                                            <div className={`text-xl font-bold ${
                                                (currentModel.learning?.growthPercentage || 0) >= 0 ? 'text-green-400' : 'text-red-400'
                                            }`}>
                                                {(currentModel.learning?.growthPercentage || 0) >= 0 ? '+' : ''}
                                                {Math.round(currentModel.learning?.growthPercentage || 0)}%
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                {/* Performance Stats */}
                                <div className="bg-gray-900/50 border border-green-800 rounded-xl p-6">
                                    <h3 className="text-lg font-bold text-white flex items-center gap-2 mb-4">
                                        <Activity className="text-green-500" />
                                        Performance
                                    </h3>
                                    
                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                        <div className="bg-black/40 p-4 rounded-lg">
                                            <Clock size={20} className="text-blue-400 mb-2" />
                                            <div className="text-xs text-gray-500">Temps Re�ponse Moy.</div>
                                            <div className="text-xl font-bold text-white">
                                                {(currentModel.performance.avgResponseTime / 1000).toFixed(2)}s
                                            </div>
                                        </div>
                                        <div className="bg-black/40 p-4 rounded-lg">
                                            <Zap size={20} className="text-yellow-400 mb-2" />
                                            <div className="text-xs text-gray-500">Tokens/sec</div>
                                            <div className="text-xl font-bold text-white">
                                                {Math.round(currentModel.performance.tokensPerSecond || 0)}
                                            </div>
                                        </div>
                                        <div className="bg-black/40 p-4 rounded-lg">
                                            <Target size={20} className="text-green-400 mb-2" />
                                            <div className="text-xs text-gray-500">Taux Succe�s</div>
                                            <div className="text-xl font-bold text-white">
                                                {currentModel.performance.totalQueries > 0 
                                                    ? Math.round((currentModel.performance.successfulQueries / currentModel.performance.totalQueries) * 100)
                                                    : 0}%
                                            </div>
                                        </div>
                                        <div className="bg-black/40 p-4 rounded-lg">
                                            <Activity size={20} className="text-purple-400 mb-2" />
                                            <div className="text-xs text-gray-500">Total Tokens</div>
                                            <div className="text-xl font-bold text-white">
                                                {(currentModel.performance.totalTokensGenerated / 1000).toFixed(1)}K
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Sidebar */}
                            <div className="space-y-6">
                                {/* Radar Chart */}
                                <div className="bg-gray-900/50 border border-cyan-800 rounded-xl p-6">
                                    <h3 className="text-lg font-bold text-white flex items-center gap-2 mb-4">
                                        <Target className="text-cyan-500" />
                                        Expertise par Domaine
                                    </h3>
                                    
                                    <ResponsiveContainer width="100%" height={250}>
                                        <RadarChart data={radarData}>
                                            <PolarGrid stroke="#333" />
                                            <PolarAngleAxis dataKey="category" tick={{ fill: '#888', fontSize: 10 }} />
                                            <PolarRadiusAxis domain={[0, 100]} tick={{ fill: '#666', fontSize: 8 }} />
                                            <Radar 
                                                name="Score" 
                                                dataKey="score" 
                                                stroke="#22d3ee" 
                                                fill="#22d3ee" 
                                                fillOpacity={0.3} 
                                            />
                                        </RadarChart>
                                    </ResponsiveContainer>
                                </div>

                                {/* Strengths */}
                                <div className="bg-gray-900/50 border border-green-800 rounded-xl p-6">
                                    <h3 className="text-sm font-bold text-white flex items-center gap-2 mb-3">
                                        <Award className="text-green-500" size={16} />
                                        FORCES
                                    </h3>
                                    
                                    {currentModel.strengths?.length > 0 ? (
                                        <div className="space-y-2">
                                            {currentModel.strengths.map((s, i) => (
                                                <div key={i} className="flex justify-between items-center bg-green-900/20 p-2 rounded">
                                                    <span className="text-sm">{s.label}</span>
                                                    <span className="text-sm font-bold text-green-400">{s.score}</span>
                                                </div>
                                            ))}
                                        </div>
                                    ) : (
                                        <p className="text-xs text-gray-500">Plus de donne�es ne�cessaires</p>
                                    )}
                                </div>

                                {/* Weaknesses */}
                                <div className="bg-gray-900/50 border border-red-800 rounded-xl p-6">
                                    <h3 className="text-sm font-bold text-white flex items-center gap-2 mb-3">
                                        <AlertTriangle className="text-red-500" size={16} />
                                        FAIBLESSES
                                    </h3>
                                    
                                    {currentModel.weaknesses?.length > 0 ? (
                                        <div className="space-y-2">
                                            {currentModel.weaknesses.map((w, i) => (
                                                <div key={i} className="flex justify-between items-center bg-red-900/20 p-2 rounded">
                                                    <span className="text-sm">{w.label}</span>
                                                    <span className="text-sm font-bold text-red-400">{w.score}</span>
                                                </div>
                                            ))}
                                        </div>
                                    ) : (
                                        <p className="text-xs text-gray-500">Aucune faiblesse identifie�e</p>
                                    )}
                                </div>

                                {/* Last Benchmark */}
                                <div className="bg-gray-900/50 border border-gray-700 rounded-xl p-4">
                                    <div className="text-xs text-gray-500 mb-1">Dernier Benchmark</div>
                                    <div className="text-sm text-gray-300">
                                        {currentModel.lastBenchmark 
                                            ? new Date(currentModel.lastBenchmark).toLocaleString('fr-CA')
                                            : 'Jamais exe�cute�'}
                                    </div>
                                </div>

                                {/* LLM Commentary Panel */}
                                <div className="bg-gray-900/50 border border-amber-800 rounded-xl p-4">
                                    <div className="flex justify-between items-center mb-3">
                                        <h3 className="text-sm font-bold text-white flex items-center gap-2">
                                            <MessageCircle className="text-amber-500" size={16} />
                                            COMMENTAIRE IA
                                        </h3>
                                        <button
                                            onClick={triggerCommentary}
                                            disabled={generatingCommentary}
                                            className="p-1.5 bg-amber-900/50 border border-amber-600 rounded text-amber-300 hover:bg-amber-800/50 disabled:opacity-50"
                                            title="Ge�ne�rer un commentaire"
                                        >
                                            {generatingCommentary ? (
                                                <RefreshCw size={14} className="animate-spin" />
                                            ) : (
                                                <Send size={14} />
                                            )}
                                        </button>
                                    </div>
                                    
                                    {commentary ? (
                                        <div className="space-y-2">
                                            <div className="text-xs text-gray-400 mb-2">
                                                 Mistral - {new Date(commentary.timestamp).toLocaleString('fr-CA')}
                                            </div>
                                            <p className="text-sm text-amber-200 italic leading-relaxed">
                                                "{commentary.commentary}"
                                            </p>
                                            <div className="flex gap-2 text-xs mt-2">
                                                <span className="px-2 py-0.5 bg-purple-900/50 rounded text-purple-300">
                                                    Score: {commentary.cognitiveScore}/100
                                                </span>
                                                <span className={`px-2 py-0.5 rounded ${
                                                    commentary.learningRate > 0 
                                                        ? 'bg-green-900/50 text-green-300' 
                                                        : 'bg-red-900/50 text-red-300'
                                                }`}>
                                                    {commentary.learningRate > 0 ? '+' : ''}{commentary.learningRate}
                                                </span>
                                            </div>
                                        </div>
                                    ) : (
                                        <p className="text-xs text-gray-500 italic">
                                            Cliquez sur  pour ge�ne�rer une analyse par Mistral
                                        </p>
                                    )}
                                    
                                    {recentCommentaries.length > 1 && (
                                        <div className="mt-3 pt-3 border-t border-gray-800">
                                            <div className="text-xs text-gray-500 mb-2">
                                                Historique ({recentCommentaries.length} commentaires)
                                            </div>
                                            <div className="max-h-32 overflow-y-auto space-y-1">
                                                {recentCommentaries.slice(0, -1).reverse().map((c, i) => (
                                                    <div key={i} className="text-xs text-gray-400 truncate">
                                                        {new Date(c.timestamp).toLocaleTimeString('fr-CA')} - Score: {c.cognitiveScore}
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}
                </>
            )}
        </div>
    );
};

export default OllamaTrainingDashboard;





