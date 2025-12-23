import React, { useState, useEffect, useCallback } from 'react';
import { OLLAMA_URL } from '../config';

/**
 * ModelIntelligenceDashboard - Dashboard intelligent des modèles IA
 * Connexion réelle aux métriques Ollama avec profils détaillés
 */

// Profils des modèles avec forces/faiblesses/cas d'usage
const MODEL_PROFILES = {
    'qwen2.5': {
        icon: '🧠', category: 'Raisonnement', color: '#8b5cf6',
        strengths: ['Excellent raisonnement logique', 'Multilingue (FR/EN)', 'Contexte étendu (32k)'],
        weaknesses: ['Plus lent', 'Mémoire élevée'],
        bestFor: ['Analyse complexe', 'Code', 'Traduction'],
        speed: 'medium', creativity: 3, accuracy: 5, context: 5
    },
    'llama3.2': {
        icon: '🦙', category: 'Polyvalent', color: '#3b82f6',
        strengths: ['Très polyvalent', 'Bon équilibre', 'Créativité élevée'],
        weaknesses: ['Moins précis calculs', 'Peut halluciner'],
        bestFor: ['Chat général', 'Créativité', 'Résumés'],
        speed: 'fast', creativity: 5, accuracy: 4, context: 4
    },
    'dolphin': {
        icon: '⚡', category: 'Rapide', color: '#10b981',
        strengths: ['Extrêmement rapide', 'Faible ressources', 'Concis'],
        weaknesses: ['Contexte limité', 'Tâches simples'],
        bestFor: ['Réponses rapides', 'Classification', 'Extraction'],
        speed: 'very-fast', creativity: 3, accuracy: 4, context: 3
    },
    'mistral': {
        icon: '🌪️', category: 'Équilibré', color: '#f59e0b',
        strengths: ['Excellent rapport qualité/taille', 'Bon en français'],
        weaknesses: ['Moins créatif', 'Contexte moyen'],
        bestFor: ['Rédaction formelle', 'Instructions', 'Précision'],
        speed: 'fast', creativity: 3, accuracy: 5, context: 3
    },
    'deepseek': {
        icon: '🔬', category: 'Code & Analyse', color: '#ef4444',
        strengths: ['Excellent code', 'Maths', 'Debugging'],
        weaknesses: ['Moins bon chat', 'Trop technique'],
        bestFor: ['Programmation', 'Debug', 'Analyse technique'],
        speed: 'slow', creativity: 2, accuracy: 5, context: 4
    },
    'phi': {
        icon: '🔮', category: 'Compact', color: '#ec4899',
        strengths: ['Très compact', 'Rapide CPU', 'Low latency'],
        weaknesses: ['Capacités limitées', 'Contexte court'],
        bestFor: ['Tâches légères', 'Prototypage', 'Tests'],
        speed: 'very-fast', creativity: 2, accuracy: 3, context: 2
    }
};

const ModelIntelligenceDashboard = () => {
    const [models, setModels] = useState([]);
    const [runningModels, setRunningModels] = useState([]);
    const [userProfile, setUserProfile] = useState(() => {
        try {
            const saved = localStorage.getItem('th3_user_ai_profile');
            if (saved) return JSON.parse(saved);
        } catch { /* ignore */ }
        return {
            preferredModels: {},
            usagePatterns: { morningTasks: [], afternoonTasks: [], eveningTasks: [] },
            preferences: { speedVsQuality: 'balanced', verbosity: 'medium', expertise: 'intermediate' },
            learningProgress: { totalInteractions: 0, topicsDiscussed: {}, tasksCompleted: 0 },
            lastUpdated: new Date().toISOString()
        };
    });
    const [predictions, setPredictions] = useState([]);
    const [loading, setLoading] = useState(true);
    const [selectedModel, setSelectedModel] = useState(null);
    const [activeTab, setActiveTab] = useState('models');

    const saveUserProfile = useCallback((profile) => {
        try {
            profile.lastUpdated = new Date().toISOString();
            localStorage.setItem('th3_user_ai_profile', JSON.stringify(profile));
            setUserProfile(profile);
        } catch (e) { console.error('Error saving profile:', e); }
    }, []);

    // Fetch Ollama data
    const fetchOllamaData = useCallback(async () => {
        try {
            const [tagsRes, psRes] = await Promise.all([
                fetch(`${OLLAMA_URL}/api/tags`),
                fetch(`${OLLAMA_URL}/api/ps`)
            ]);
            const tagsData = await tagsRes.json();
            const psData = await psRes.json();

            const enrichedModels = (tagsData.models || []).map(model => {
                const baseName = model.name.split(':')[0].toLowerCase();
                const profile = Object.entries(MODEL_PROFILES).find(([key]) => baseName.includes(key));
                return {
                    ...model,
                    profile: profile ? profile[1] : null,
                    profileKey: profile ? profile[0] : 'unknown',
                    isRunning: (psData.models || []).some(m => m.name === model.name),
                    sizeGB: (model.size / (1024 * 1024 * 1024)).toFixed(1)
                };
            });

            setModels(enrichedModels);
            setRunningModels(psData.models || []);
            setLoading(false);
        } catch (error) {
            console.error('Error fetching Ollama data:', error);
            setLoading(false);
        }
    }, []);

    // Generate predictions based on time and preferences
    const generatePredictions = useCallback((profile) => {
        const hour = new Date().getHours();
        const isWeekend = [0, 6].includes(new Date().getDay());
        const preds = [];

        if (hour >= 6 && hour < 12) {
            preds.push({ icon: '☀️', type: 'time', message: 'Matin - Modèles rapides pour productivité', model: 'dolphin', confidence: 0.8 });
        } else if (hour >= 12 && hour < 18) {
            preds.push({ icon: '🏢', type: 'time', message: 'Travail - Modèles équilibrés', model: 'qwen2.5', confidence: 0.75 });
        } else {
            preds.push({ icon: '🌙', type: 'time', message: 'Soirée - Modèles créatifs', model: 'llama3.2', confidence: 0.7 });
        }

        if (profile.preferences.speedVsQuality === 'speed') {
            preds.push({ icon: '⚡', type: 'pref', message: 'Vitesse préférée → granite', model: 'dolphin', confidence: 0.9 });
        } else if (profile.preferences.speedVsQuality === 'quality') {
            preds.push({ icon: '🎯', type: 'pref', message: 'Qualité préférée → qwen2.5', model: 'qwen2.5', confidence: 0.9 });
        }

        if (isWeekend) {
            preds.push({ icon: '🎮', type: 'context', message: 'Weekend - Mode créatif', model: 'llama3.2', confidence: 0.6 });
        }

        setPredictions(preds);
    }, []);

    useEffect(() => {
        fetchOllamaData();
        generatePredictions(userProfile);
        const interval = setInterval(fetchOllamaData, 30000);
        return () => clearInterval(interval);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [fetchOllamaData, userProfile.preferences.speedVsQuality]);

    const StatBar = ({ label, value, max = 5, color }) => (
        <div className="flex items-center gap-2 mb-1">
            <span className="text-xs text-gray-500 w-16">{label}</span>
            <div className="flex-1 h-1.5 bg-gray-700 rounded-full overflow-hidden">
                <div className="h-full rounded-full" style={{ width: `${(value / max) * 100}%`, backgroundColor: color }} />
            </div>
            <span className="text-xs font-mono" style={{ color }}>{value}/{max}</span>
        </div>
    );

    if (loading) {
        return (
            <div className="flex items-center justify-center h-full">
                <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
            </div>
        );
    }

    return (
        <div className="h-full flex flex-col">
            {/* Header */}
            <div className="flex items-center justify-between mb-3 flex-shrink-0">
                <div className="flex gap-1">
                    {[
                        { id: 'models', icon: '🤖' },
                        { id: 'predict', icon: '🔮' },
                        { id: 'learn', icon: '📊' }
                    ].map(tab => (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={`px-2 py-1 rounded text-xs font-medium transition-all ${
                                activeTab === tab.id ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'text-gray-500 hover:text-gray-300'
                            }`}
                        >
                            {tab.icon}
                        </button>
                    ))}
                </div>
                <div className="flex items-center gap-1">
                    <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                    <span className="text-xs text-gray-500">{models.length}</span>
                </div>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto pr-1">
                {/* Models Tab */}
                {activeTab === 'models' && (
                    <div className="space-y-2">
                        {models.map((model, idx) => {
                            const profile = model.profile;
                            const isSelected = selectedModel === model.name;
                            return (
                                <div 
                                    key={idx}
                                    onClick={() => setSelectedModel(isSelected ? null : model.name)}
                                    className={`p-3 rounded-lg border cursor-pointer transition-all ${
                                        isSelected ? 'bg-gray-800/80 border-cyan-500/50' : 'bg-gray-900/50 border-gray-700/50 hover:border-gray-600'
                                    } ${model.isRunning ? 'ring-1 ring-green-500/30' : ''}`}
                                >
                                    <div className="flex items-center justify-between mb-1">
                                        <div className="flex items-center gap-2">
                                            <span className="text-lg">{profile?.icon || '🤖'}</span>
                                            <div>
                                                <div className="text-sm font-bold text-white truncate max-w-[100px]">{model.name.split(':')[0]}</div>
                                                <div className="text-xs text-gray-500">{model.sizeGB}GB • {profile?.category || 'Général'}</div>
                                            </div>
                                        </div>
                                        {model.isRunning && <span className="px-2 py-0.5 bg-green-500/20 text-green-400 text-xs rounded-full">Actif</span>}
                                    </div>

                                    {profile && (
                                        <div className="flex gap-3 text-xs mt-1">
                                            <span className="text-gray-400">⚡{profile.speed}</span>
                                            <span className="text-gray-400">🎯{profile.accuracy}/5</span>
                                        </div>
                                    )}

                                    {isSelected && profile && (
                                        <div className="mt-3 pt-3 border-t border-gray-700 space-y-3">
                                            <div>
                                                <StatBar label="Vitesse" value={profile.speed === 'very-fast' ? 5 : profile.speed === 'fast' ? 4 : 3} color={profile.color} />
                                                <StatBar label="Précision" value={profile.accuracy} color={profile.color} />
                                                <StatBar label="Créativité" value={profile.creativity} color={profile.color} />
                                            </div>
                                            <div>
                                                <div className="text-xs text-green-400 mb-1">✓ Forces</div>
                                                {profile.strengths.map((s, i) => <div key={i} className="text-xs text-gray-400">• {s}</div>)}
                                            </div>
                                            <div>
                                                <div className="text-xs text-red-400 mb-1">✗ Limites</div>
                                                {profile.weaknesses.map((w, i) => <div key={i} className="text-xs text-gray-400">• {w}</div>)}
                                            </div>
                                            <div className="flex flex-wrap gap-1">
                                                {profile.bestFor.map((use, i) => (
                                                    <span key={i} className="px-2 py-0.5 bg-cyan-500/10 text-cyan-400 text-xs rounded-full">{use}</span>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            );
                        })}
                        {models.length === 0 && <div className="text-center text-gray-500 text-sm py-8">Aucun modèle Ollama</div>}
                    </div>
                )}

                {/* Predictions Tab */}
                {activeTab === 'predict' && (
                    <div className="space-y-2">
                        <div className="text-xs text-gray-500 mb-2">🔮 Anticipations intelligentes</div>
                        {predictions.map((pred, idx) => (
                            <div key={idx} className="p-3 bg-gray-900/50 border border-gray-700/50 rounded-lg">
                                <div className="flex items-center gap-2 mb-1">
                                    <span>{pred.icon}</span>
                                    <span className={`text-xs px-2 py-0.5 rounded-full ${
                                        pred.type === 'time' ? 'bg-blue-500/20 text-blue-400' :
                                        pred.type === 'pref' ? 'bg-purple-500/20 text-purple-400' :
                                        'bg-amber-500/20 text-amber-400'
                                    }`}>{pred.type}</span>
                                </div>
                                <p className="text-sm text-gray-300">{pred.message}</p>
                                <div className="flex justify-between text-xs mt-1">
                                    <span className="text-cyan-400">→ {pred.model}</span>
                                    <span className="text-gray-500">{Math.round(pred.confidence * 100)}%</span>
                                </div>
                            </div>
                        ))}
                    </div>
                )}

                {/* Learning Tab */}
                {activeTab === 'learn' && userProfile && (
                    <div className="space-y-3">
                        <div className="text-xs text-gray-500">📊 Apprentissage de vos préférences</div>
                        
                        <div className="grid grid-cols-2 gap-2">
                            <div className="p-3 bg-gray-900/50 border border-gray-700/50 rounded-lg text-center">
                                <div className="text-xl font-bold text-cyan-400">{userProfile.learningProgress.totalInteractions}</div>
                                <div className="text-xs text-gray-500">Interactions</div>
                            </div>
                            <div className="p-3 bg-gray-900/50 border border-gray-700/50 rounded-lg text-center">
                                <div className="text-xl font-bold text-green-400">{userProfile.learningProgress.tasksCompleted}</div>
                                <div className="text-xs text-gray-500">Tâches</div>
                            </div>
                        </div>

                        <div className="p-3 bg-gray-900/50 border border-gray-700/50 rounded-lg">
                            <div className="text-xs font-bold text-white mb-2">⚙️ Préférences</div>
                            <div className="space-y-2">
                                <div className="flex justify-between items-center">
                                    <span className="text-xs text-gray-500">Mode</span>
                                    <select 
                                        value={userProfile.preferences.speedVsQuality}
                                        onChange={(e) => {
                                            const updated = { ...userProfile, preferences: { ...userProfile.preferences, speedVsQuality: e.target.value }};
                                            saveUserProfile(updated);
                                            generatePredictions(updated);
                                        }}
                                        className="bg-gray-800 border border-gray-700 rounded px-2 py-0.5 text-xs text-gray-300"
                                    >
                                        <option value="speed">⚡ Vitesse</option>
                                        <option value="balanced">⚖️ Équilibré</option>
                                        <option value="quality">🎯 Qualité</option>
                                    </select>
                                </div>
                                <div className="flex justify-between items-center">
                                    <span className="text-xs text-gray-500">Verbosité</span>
                                    <select 
                                        value={userProfile.preferences.verbosity}
                                        onChange={(e) => saveUserProfile({ ...userProfile, preferences: { ...userProfile.preferences, verbosity: e.target.value }})}
                                        className="bg-gray-800 border border-gray-700 rounded px-2 py-0.5 text-xs text-gray-300"
                                    >
                                        <option value="concise">📝 Concis</option>
                                        <option value="medium">📄 Medium</option>
                                        <option value="detailed">📚 Détaillé</option>
                                    </select>
                                </div>
                            </div>
                        </div>

                        <button 
                            onClick={() => {
                                if (confirm('Réinitialiser l\'apprentissage?')) {
                                    localStorage.removeItem('th3_user_ai_profile');
                                    window.location.reload();
                                }
                            }}
                            className="w-full px-3 py-2 bg-red-500/10 border border-red-500/30 text-red-400 text-xs rounded-lg hover:bg-red-500/20"
                        >
                            🗑️ Réinitialiser
                        </button>
                    </div>
                )}
            </div>

            {/* Footer */}
            <div className="mt-2 pt-2 border-t border-gray-800 text-center text-xs text-gray-500">
                {runningModels.length > 0 ? `🟢 ${runningModels.length} actif(s)` : '⚪ Aucun chargé'}
            </div>
        </div>
    );
};

export default ModelIntelligenceDashboard;
