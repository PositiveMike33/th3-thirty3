import React, { useState, useEffect } from 'react';
import { API_URL } from '../config';

/**
 * ModelProgressChart - Dashboard graphique de progression des modèles IA
 * Affiche les performances, évolutions et régressions des modèles
 */

const ModelProgressChart = () => {
    const [_models, setModels] = useState([]);
    const [_metrics, setMetrics] = useState({});
    const [loading, setLoading] = useState(true);
    const [selectedModel, setSelectedModel] = useState(null);
    const [timeRange, setTimeRange] = useState('7d');

    // Données simulées pour la démonstration (à connecter à l'API réelle)
    const MOCK_HISTORY = {
        'qwen2.5:7b': [
            { date: '12-09', score: 72, responseTime: 4200, queries: 45 },
            { date: '12-10', score: 74, responseTime: 4100, queries: 52 },
            { date: '12-11', score: 75, responseTime: 3900, queries: 48 },
            { date: '12-12', score: 78, responseTime: 3800, queries: 61 },
            { date: '12-13', score: 76, responseTime: 3850, queries: 55 },
            { date: '12-14', score: 80, responseTime: 3600, queries: 72 },
            { date: '12-15', score: 82, responseTime: 3500, queries: 68 }
        ],
        'llama3.2:3b': [
            { date: '12-09', score: 68, responseTime: 2800, queries: 38 },
            { date: '12-10', score: 70, responseTime: 2700, queries: 42 },
            { date: '12-11', score: 71, responseTime: 2650, queries: 45 },
            { date: '12-12', score: 69, responseTime: 2900, queries: 40 },
            { date: '12-13', score: 72, responseTime: 2600, queries: 51 },
            { date: '12-14', score: 74, responseTime: 2500, queries: 58 },
            { date: '12-15', score: 75, responseTime: 2400, queries: 62 }
        ],
        'dolphin-uncensored:latest': [
            { date: '12-09', score: 82, responseTime: 2200, queries: 120 },
            { date: '12-10', score: 83, responseTime: 2100, queries: 135 },
            { date: '12-11', score: 85, responseTime: 2000, queries: 142 },
            { date: '12-12', score: 84, responseTime: 2050, queries: 138 },
            { date: '12-13', score: 86, responseTime: 1950, queries: 150 },
            { date: '12-14', score: 88, responseTime: 1900, queries: 165 },
            { date: '12-15', score: 89, responseTime: 1850, queries: 172 }
        ],
        'qwen-flash:latest': [
            { date: '12-09', score: 78, responseTime: 8500, queries: 25 },
            { date: '12-10', score: 79, responseTime: 8200, queries: 28 },
            { date: '12-11', score: 80, responseTime: 8000, queries: 32 },
            { date: '12-12', score: 78, responseTime: 8800, queries: 22 },
            { date: '12-13', score: 81, responseTime: 7800, queries: 35 },
            { date: '12-14', score: 83, responseTime: 7500, queries: 40 },
            { date: '12-15', score: 84, responseTime: 7200, queries: 45 }
        ],
        'brain-7b:latest': [
            { date: '12-09', score: 65, responseTime: 28000, queries: 8 },
            { date: '12-10', score: 68, responseTime: 26000, queries: 10 },
            { date: '12-11', score: 70, responseTime: 25000, queries: 12 },
            { date: '12-12', score: 72, responseTime: 24000, queries: 15 },
            { date: '12-13', score: 71, responseTime: 26000, queries: 11 },
            { date: '12-14', score: 74, responseTime: 23000, queries: 18 },
            { date: '12-15', score: 76, responseTime: 22000, queries: 20 }
        ]
    };

    useEffect(() => {
        const fetchData = async () => {
            try {
                // Fetch models from Ollama
                const res = await fetch(`${API_URL}/models`);
                const data = await res.json();
                const localModels = data.local || [];
                
                // Fetch metrics
                const metricsRes = await fetch(`${API_URL}/api/model-metrics/status`).catch(() => null);
                const metricsData = metricsRes?.ok ? await metricsRes.json() : {};

                setModels(localModels);
                setMetrics(metricsData);
                setLoading(false);
            } catch (error) {
                console.error('Error fetching model data:', error);
                setLoading(false);
            }
        };

        fetchData();
        const interval = setInterval(fetchData, 60000);
        return () => clearInterval(interval);
    }, []);

    // Calculer les tendances
    const calculateTrend = (history) => {
        if (!history || history.length < 2) return { value: 0, direction: 'neutral' };
        const recent = history.slice(-3);
        const older = history.slice(-6, -3);
        
        const recentAvg = recent.reduce((s, h) => s + h.score, 0) / recent.length;
        const olderAvg = older.length ? older.reduce((s, h) => s + h.score, 0) / older.length : recentAvg;
        
        const diff = recentAvg - olderAvg;
        return {
            value: Math.abs(diff).toFixed(1),
            direction: diff > 0.5 ? 'up' : diff < -0.5 ? 'down' : 'neutral'
        };
    };

    // Mini graphique en ligne (sparkline)
    const Sparkline = ({ data, color, height = 40, width = 120 }) => {
        if (!data || data.length === 0) return null;
        
        const values = data.map(d => d.score);
        const min = Math.min(...values) - 5;
        const max = Math.max(...values) + 5;
        const range = max - min || 1;
        
        const points = values.map((v, i) => {
            const x = (i / (values.length - 1)) * width;
            const y = height - ((v - min) / range) * height;
            return `${x},${y}`;
        }).join(' ');

        return (
            <svg width={width} height={height} className="overflow-visible">
                {/* Grid lines */}
                <line x1="0" y1={height} x2={width} y2={height} stroke="rgba(148,163,184,0.2)" strokeWidth="1" />
                <line x1="0" y1={height/2} x2={width} y2={height/2} stroke="rgba(148,163,184,0.1)" strokeWidth="1" strokeDasharray="4" />
                
                {/* Area fill */}
                <polygon
                    points={`0,${height} ${points} ${width},${height}`}
                    fill={`url(#gradient-${color.replace('#', '')})`}
                    opacity="0.3"
                />
                
                {/* Line */}
                <polyline
                    points={points}
                    fill="none"
                    stroke={color}
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                />
                
                {/* Current point */}
                <circle
                    cx={width}
                    cy={height - ((values[values.length - 1] - min) / range) * height}
                    r="4"
                    fill={color}
                    stroke="white"
                    strokeWidth="2"
                />
                
                {/* Gradient definition */}
                <defs>
                    <linearGradient id={`gradient-${color.replace('#', '')}`} x1="0%" y1="0%" x2="0%" y2="100%">
                        <stop offset="0%" stopColor={color} stopOpacity="0.4" />
                        <stop offset="100%" stopColor={color} stopOpacity="0" />
                    </linearGradient>
                </defs>
            </svg>
        );
    };

    // Grande Chart pour le modèle sélectionné
    const DetailChart = ({ modelName }) => {
        const history = MOCK_HISTORY[modelName];
        if (!history) return <div className="text-gray-500 text-center py-8">Pas de données historiques</div>;

        const height = 150;
        const width = 400;
        const padding = 40;
        
        const scores = history.map(h => h.score);
        const minScore = Math.min(...scores) - 10;
        const maxScore = Math.max(...scores) + 10;
        const scoreRange = maxScore - minScore;

        const responseTimes = history.map(h => h.responseTime);
        const minTime = Math.min(...responseTimes) * 0.8;
        const maxTime = Math.max(...responseTimes) * 1.2;
        const timeRange = maxTime - minTime;

        return (
            <div className="mt-4">
                <svg width="100%" height={height + padding * 2} viewBox={`0 0 ${width + padding * 2} ${height + padding * 2}`}>
                    {/* Background grid */}
                    {[0, 25, 50, 75, 100].map((p, i) => (
                        <g key={i}>
                            <line 
                                x1={padding} 
                                y1={padding + (height * p / 100)} 
                                x2={width + padding} 
                                y2={padding + (height * p / 100)} 
                                stroke="rgba(148,163,184,0.1)" 
                                strokeWidth="1" 
                            />
                            <text 
                                x={padding - 5} 
                                y={padding + (height * p / 100) + 4} 
                                fill="#64748b" 
                                fontSize="10" 
                                textAnchor="end"
                            >
                                {Math.round(maxScore - (scoreRange * p / 100))}
                            </text>
                        </g>
                    ))}

                    {/* X-axis labels */}
                    {history.map((h, i) => (
                        <text 
                            key={i}
                            x={padding + (i / (history.length - 1)) * width}
                            y={height + padding + 15}
                            fill="#64748b"
                            fontSize="9"
                            textAnchor="middle"
                        >
                            {h.date}
                        </text>
                    ))}

                    {/* Score line */}
                    <polyline
                        points={history.map((h, i) => {
                            const x = padding + (i / (history.length - 1)) * width;
                            const y = padding + ((maxScore - h.score) / scoreRange) * height;
                            return `${x},${y}`;
                        }).join(' ')}
                        fill="none"
                        stroke="#3b82f6"
                        strokeWidth="3"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                    />

                    {/* Response time line (secondary) */}
                    <polyline
                        points={history.map((h, i) => {
                            const x = padding + (i / (history.length - 1)) * width;
                            const y = padding + ((h.responseTime - minTime) / timeRange) * height;
                            return `${x},${y}`;
                        }).join(' ')}
                        fill="none"
                        stroke="#f59e0b"
                        strokeWidth="2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeDasharray="5,3"
                    />

                    {/* Data points for score */}
                    {history.map((h, i) => {
                        const x = padding + (i / (history.length - 1)) * width;
                        const y = padding + ((maxScore - h.score) / scoreRange) * height;
                        return (
                            <g key={i}>
                                <circle cx={x} cy={y} r="5" fill="#3b82f6" stroke="white" strokeWidth="2" />
                                <title>{h.date}: Score {h.score}, Queries: {h.queries}</title>
                            </g>
                        );
                    })}
                </svg>

                {/* Legend */}
                <div className="flex justify-center gap-6 mt-2 text-xs">
                    <div className="flex items-center gap-2">
                        <div className="w-4 h-0.5 bg-blue-500"></div>
                        <span className="text-gray-400">Score Performance</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <div className="w-4 h-0.5 bg-amber-500" style={{ borderStyle: 'dashed' }}></div>
                        <span className="text-gray-400">Temps de Réponse</span>
                    </div>
                </div>
            </div>
        );
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center h-full">
                <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
            </div>
        );
    }

    // Préparer les données des modèles avec historique
    const modelsWithData = Object.keys(MOCK_HISTORY).map(name => {
        const history = MOCK_HISTORY[name];
        const current = history[history.length - 1];
        const trend = calculateTrend(history);
        
        return {
            name,
            score: current.score,
            responseTime: current.responseTime,
            queries: history.reduce((s, h) => s + h.queries, 0),
            trend,
            history
        };
    });

    return (
        <div className="h-full flex flex-col">
            {/* Header */}
            <div className="flex items-center justify-between mb-4 flex-shrink-0">
                <div className="flex items-center gap-2">
                    <span className="text-lg">📈</span>
                    <h3 className="font-bold text-white text-sm">PROGRESSION DES MODÈLES</h3>
                </div>
                <select
                    value={timeRange}
                    onChange={(e) => setTimeRange(e.target.value)}
                    className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300"
                >
                    <option value="7d">7 jours</option>
                    <option value="30d">30 jours</option>
                    <option value="90d">90 jours</option>
                </select>
            </div>

            {/* Model Cards */}
            <div className="flex-1 overflow-y-auto space-y-2 pr-1">
                {modelsWithData.map((model, idx) => (
                    <div 
                        key={idx}
                        onClick={() => setSelectedModel(selectedModel === model.name ? null : model.name)}
                        className={`p-3 rounded-lg border transition-all cursor-pointer ${
                            selectedModel === model.name 
                                ? 'bg-gray-800/80 border-cyan-500/50' 
                                : 'bg-gray-900/50 border-gray-700/50 hover:border-gray-600'
                        }`}
                    >
                        <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-2">
                                <span className={`w-2 h-2 rounded-full ${
                                    model.trend.direction === 'up' ? 'bg-green-500' :
                                    model.trend.direction === 'down' ? 'bg-red-500' :
                                    'bg-gray-500'
                                }`}></span>
                                <span className="text-xs font-mono text-gray-300 truncate max-w-[100px]">
                                    {model.name.split(':')[0]}
                                </span>
                            </div>
                            <div className="flex items-center gap-2">
                                <span className={`text-xs font-bold ${
                                    model.trend.direction === 'up' ? 'text-green-400' :
                                    model.trend.direction === 'down' ? 'text-red-400' :
                                    'text-gray-400'
                                }`}>
                                    {model.trend.direction === 'up' ? '↑' : model.trend.direction === 'down' ? '↓' : '→'}
                                    {model.trend.value}%
                                </span>
                                <span className="text-lg font-bold text-cyan-400">{model.score}</span>
                            </div>
                        </div>

                        {/* Sparkline */}
                        <div className="flex items-center justify-between">
                            <Sparkline 
                                data={model.history} 
                                color={model.trend.direction === 'up' ? '#10b981' : model.trend.direction === 'down' ? '#ef4444' : '#6b7280'}
                                height={30}
                                width={100}
                            />
                            <div className="text-right">
                                <div className="text-xs text-gray-500">{(model.responseTime / 1000).toFixed(1)}s</div>
                                <div className="text-xs text-gray-600">{model.queries} queries</div>
                            </div>
                        </div>

                        {/* Expanded Detail */}
                        {selectedModel === model.name && (
                            <div className="mt-4 pt-4 border-t border-gray-700">
                                <DetailChart modelName={model.name} />
                                
                                {/* Stats row */}
                                <div className="grid grid-cols-3 gap-2 mt-4">
                                    <div className="text-center p-2 bg-gray-900/50 rounded">
                                        <div className="text-lg font-bold text-blue-400">{model.score}/100</div>
                                        <div className="text-xs text-gray-500">Score</div>
                                    </div>
                                    <div className="text-center p-2 bg-gray-900/50 rounded">
                                        <div className="text-lg font-bold text-amber-400">{(model.responseTime / 1000).toFixed(1)}s</div>
                                        <div className="text-xs text-gray-500">Latence</div>
                                    </div>
                                    <div className="text-center p-2 bg-gray-900/50 rounded">
                                        <div className="text-lg font-bold text-green-400">{model.queries}</div>
                                        <div className="text-xs text-gray-500">Queries</div>
                                    </div>
                                </div>

                                {/* Trend analysis */}
                                <div className={`mt-3 p-2 rounded text-xs ${
                                    model.trend.direction === 'up' ? 'bg-green-500/10 text-green-400' :
                                    model.trend.direction === 'down' ? 'bg-red-500/10 text-red-400' :
                                    'bg-gray-500/10 text-gray-400'
                                }`}>
                                    {model.trend.direction === 'up' && `📈 Progression de +${model.trend.value}% sur la période`}
                                    {model.trend.direction === 'down' && `📉 Régression de -${model.trend.value}% - attention requise`}
                                    {model.trend.direction === 'neutral' && `➡️ Performance stable sur la période`}
                                </div>
                            </div>
                        )}
                    </div>
                ))}
            </div>

            {/* Summary Footer */}
            <div className="mt-4 pt-3 border-t border-gray-800 flex-shrink-0">
                <div className="grid grid-cols-3 gap-2 text-center">
                    <div>
                        <div className="text-green-400 font-bold">
                            {modelsWithData.filter(m => m.trend.direction === 'up').length}
                        </div>
                        <div className="text-xs text-gray-500">En progression</div>
                    </div>
                    <div>
                        <div className="text-gray-400 font-bold">
                            {modelsWithData.filter(m => m.trend.direction === 'neutral').length}
                        </div>
                        <div className="text-xs text-gray-500">Stables</div>
                    </div>
                    <div>
                        <div className="text-red-400 font-bold">
                            {modelsWithData.filter(m => m.trend.direction === 'down').length}
                        </div>
                        <div className="text-xs text-gray-500">En régression</div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ModelProgressChart;
