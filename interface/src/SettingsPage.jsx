import React, { useState, useEffect } from 'react';
import { Settings, Cpu, Cloud, Zap, Brain, Shield, Mail, Calendar, Activity, CheckCircle, XCircle } from 'lucide-react';
import { API_URL } from './config';

const SettingsPage = () => {
    // State for Settings
    const [settings, setSettings] = useState({
        darkMode: true,
        themeMode: 'dark', // 'dark' | 'light' | 'paint'
        customWallpaper: '', // URL for 'paint' mode
        language: 'fr-QC', // 'fr-QC' | 'en-US' | 'fr-FR'
        autoCorrect: true,
        computeMode: 'cloud',
        reflectionMode: 'think'
    });

    // State for Connectors Status
    const [connectors, setConnectors] = useState({
        gmail: [],
        calendar: [],
        dart: { status: 'active' },
        wwt: { status: 'active' }
    });

    // State for API Keys
    const [apiKeys, setApiKeys] = useState({
        groq: '',
        gemini: '',
        openai: '',
        anthropic: '',
        perplexity: '',
        anythingllm_url: '',
        anythingllm_key: '',
        userApiKey: '' // New field for SaaS Key
    });

    const [isLoading, setIsLoading] = useState(true);

    // Load Settings & Status on Mount
    useEffect(() => {
        setIsLoading(true);
        // 1. Get Settings
        fetch(`${API_URL}/settings`)
            .then(res => res.json())
            .then(data => {
                console.log("Loaded settings:", data);
                setSettings(data);
                // Ensure apiKeys object exists before setting state
                if (data.apiKeys) {
                    setApiKeys(prev => ({
                        ...prev,
                        ...data.apiKeys
                    }));
                }
                setIsLoading(false); // Data loaded, enable UI
            })
            .catch(err => {
                console.error("Failed to load settings", err);
                setIsLoading(false); // Enable UI even on error to allow retry
            });

        // 2. Get Google Status
        fetch(`${API_URL}/google/status`)
            .then(res => res.json())
            .then(statusMap => {
                // Map the 3 specific accounts
                const accounts = [
                    'th3thirty3@gmail.com',
                    'mgauthierguillet@gmail.com',
                    'mikegauthierguillet@gmail.com'
                ];

                const gmailStatus = accounts.map((email, i) => ({
                    id: i,
                    email,
                    status: statusMap[email] ? 'active' : 'inactive'
                }));

                setConnectors(prev => ({
                    ...prev,
                    gmail: gmailStatus,
                    calendar: gmailStatus // Calendar uses same auth
                }));
            })
            .catch(err => console.error("Failed to load google status", err));
    }, []);

    // Helper to update and save settings
    const updateSetting = (key, value) => {
        const newSettings = { ...settings, [key]: value };
        setSettings(newSettings);
        saveSettings(newSettings);
    };

    // Handle API Key Input Changes
    const handleApiKeyChange = (e) => {
        const { name, value } = e.target;
        setApiKeys(prev => ({ ...prev, [name]: value }));
    };

    // Save API Keys
    const saveApiKeys = () => {
        const newSettings = { ...settings, apiKeys };
        saveSettings(newSettings);
    };

    // Backend Save Call
    const saveSettings = (newSettings) => {
        if (isLoading) {
            console.warn("[FRONTEND] Save prevented: Settings still loading.");
            return;
        }
        console.log("[FRONTEND] Saving settings payload:", newSettings);
        fetch(`${API_URL}/settings`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(newSettings)
        })
            .then(res => res.json())
            .then(data => {
                console.log("[FRONTEND] Save response:", data);
                // window.alert("✅ Configuration sauvegardée avec succès !"); // Too invasive on auto-save
            })
            .catch(err => {
                console.error("[FRONTEND] Save error:", err);
                window.alert("❌ Erreur lors de la sauvegarde : " + err.message);
            });
    };

    if (isLoading) {
        return (
            <div className="flex-1 p-8 bg-black text-cyan-300 flex items-center justify-center font-mono">
                <div className="text-center animate-pulse">
                    <Activity size={48} className="mx-auto mb-4 text-cyan-500" />
                    <h2 className="text-xl tracking-[0.2em]">INITIALISATION DU SYSTÈME...</h2>
                </div>
            </div>
        );
    }

    return (
        <div className="flex-1 p-8 bg-black text-cyan-300 overflow-y-auto bg-[url('/grid.png')] notranslate" translate="no">
            <h2 className="text-2xl font-bold tracking-widest mb-8 border-b border-cyan-900 pb-4 flex items-center gap-3">
                <Settings className="text-cyan-500" /> SYSTÈME & PARAMÈTRES
            </h2>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">

                {/* COLUMN 1: MODES & INTELLIGENCE */}
                <div className="space-y-8">

                    {/* REFLECTION MODE */}
                    <div className="bg-gray-900/50 border border-cyan-800 p-6 rounded-lg backdrop-blur">
                        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                            <Brain size={20} /> MODE RÉFLEXION
                        </h3>
                        <div className="grid grid-cols-3 gap-2">
                            {['rapide', 'think', 'ultra'].map(mode => (
                                <button
                                    key={mode}
                                    onClick={() => updateSetting('reflectionMode', mode)}
                                    className={`p-3 rounded border text-center transition-all ${settings.reflectionMode === mode
                                        ? 'bg-green-900/30 border-green-500 text-green-400 shadow-[0_0_15px_rgba(34,197,94,0.3)] font-bold'
                                        : 'bg-black/40 border-gray-700 text-gray-500 hover:border-green-900 hover:text-green-300'
                                        }`}
                                >
                                    <div className="text-xs uppercase font-bold mb-1">{mode}</div>
                                    <div className="text-[10px] opacity-70">
                                        {mode === 'rapide' ? 'Réponse instantanée' : mode === 'think' ? 'Analyse standard' : 'Chain of Thought'}
                                    </div>
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* THEME & WALLPAPER */}
                    <div className="bg-gray-900/50 border border-pink-800 p-6 rounded-lg backdrop-blur">
                        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                            <Activity size={20} /> APPARENCE & LANGUE
                        </h3>

                        {/* THEME SELECTOR */}
                        <div className="grid grid-cols-3 gap-2 mb-4">
                            {['dark', 'light', 'paint'].map(mode => (
                                <button
                                    key={mode}
                                    onClick={() => updateSetting('themeMode', mode)}
                                    className={`p-2 rounded border text-center transition-all ${settings.themeMode === mode
                                        ? 'bg-green-900/30 border-green-500 text-green-400 shadow-[0_0_10px_rgba(34,197,94,0.3)] font-bold'
                                        : 'bg-black/40 border-gray-700 text-gray-500 hover:border-green-900 hover:text-green-300'
                                        }`}
                                >
                                    <div className="text-xs uppercase font-bold">{mode === 'paint' ? 'Sur Mesure' : mode}</div>
                                </button>
                            ))}
                        </div>

                        {/* WALLPAPER INPUT (Only if Paint mode) */}
                        {settings.themeMode === 'paint' && (
                            <div className="mb-4">
                                <label className="text-xs text-gray-500 block mb-1">URL du Fond d'écran</label>
                                <input
                                    type="text"
                                    value={settings.customWallpaper || ''}
                                    onChange={(e) => updateSetting('customWallpaper', e.target.value)}
                                    placeholder="https://example.com/image.jpg"
                                    className="w-full bg-black/40 border border-gray-700 rounded p-2 text-xs text-white focus:border-pink-500 focus:outline-none"
                                />
                            </div>
                        )}

                        {/* LANGUAGE SELECTOR */}
                        <div>
                            <label className="text-xs text-gray-500 block mb-1">Langue / Région</label>
                            <select
                                value={settings.language || 'fr-QC'}
                                onChange={(e) => updateSetting('language', e.target.value)}
                                className="w-full bg-black/40 border border-gray-700 rounded p-2 text-xs text-white focus:border-pink-500 focus:outline-none"
                            >
                                <option value="fr-QC">Français (Québec) ⚜️</option>
                                <option value="fr-FR">Français (France)</option>
                                <option value="en-US">English (US)</option>
                            </select>
                        </div>
                    </div>

                    {/* COMPUTE MODE */}
                    <div className="bg-gray-900/50 border border-purple-800 p-6 rounded-lg backdrop-blur">
                        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                            <Cpu size={20} /> PUISSANCE DE CALCUL
                        </h3>
                        <button
                            onClick={() => updateSetting('computeMode', 'cloud')}
                            className={`flex-1 p-4 rounded border flex items-center justify-center gap-2 transition-all ${settings.computeMode === 'cloud'
                                ? 'bg-blue-900/80 border-blue-400 text-white'
                                : 'bg-black/40 border-gray-700 text-gray-500'
                                }`}
                        >
                            <Cloud size={18} /> CLOUD (Puissant) - Mode Unique
                        </button>
                    </div>

                    {/* AUTO-CORRECTION */}
                    <div className="bg-gray-900/50 border border-green-800 p-6 rounded-lg backdrop-blur flex justify-between items-center">
                        <div>
                            <h3 className="text-lg font-bold text-white flex items-center gap-2">
                                <Shield size={20} /> AUTO-CORRECTION
                            </h3>
                            <p className="text-xs text-gray-400 mt-1">Apprentissage continu des erreurs.</p>
                        </div>
                        <button
                            onClick={() => updateSetting('autoCorrect', !settings.autoCorrect)}
                            className={`w-12 h-6 rounded-full p-1 transition-colors ${settings.autoCorrect ? 'bg-green-500' : 'bg-gray-700'}`}
                        >
                            <div className={`w-4 h-4 bg-white rounded-full shadow-md transform transition-transform ${settings.autoCorrect ? 'translate-x-6' : 'translate-x-0'}`} />
                        </button>
                    </div>

                    {/* API KEYS CONFIGURATION */}
                    <div className="bg-gray-900/50 border border-yellow-800 p-6 rounded-lg backdrop-blur">
                        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                            <Settings size={20} /> CONFIGURATION API
                        </h3>
                        <div className="space-y-3">
                            {[
                                { label: 'Groq API Key (Fast)', name: 'groq', placeholder: 'gsk_...' },
                                { label: 'Google Gemini Key', name: 'gemini', placeholder: 'AIza...' },
                                { label: 'OpenAI API Key', name: 'openai', placeholder: 'sk-...' },
                                { label: 'Anthropic Claude Key', name: 'anthropic', placeholder: 'sk-ant-...' },
                                { label: 'Perplexity API Key', name: 'perplexity', placeholder: 'pplx-...' },
                            ].map(field => (
                                <div key={field.name}>
                                    <div className="flex justify-between items-center mb-1">
                                        <label className="text-xs text-gray-500">{field.label}</label>
                                        {apiKeys[field.name] && (
                                            <span className="text-[10px] text-green-400 flex items-center gap-1">
                                                <CheckCircle size={10} /> CONNECTÉ
                                            </span>
                                        )}
                                    </div>
                                    <input
                                        type="password"
                                        name={field.name}
                                        value={apiKeys[field.name]}
                                        onChange={handleApiKeyChange}
                                        placeholder={field.placeholder}
                                        className={`w-full bg-black/40 border rounded p-2 text-xs text-white focus:outline-none ${apiKeys[field.name] ? 'border-green-900 focus:border-green-500' : 'border-gray-700 focus:border-yellow-500'}`}
                                    />
                                </div>
                            ))}

                            <div className="pt-2 border-t border-gray-800 mt-2">
                                <div className="flex justify-between items-center mb-1">
                                    <label className="text-xs text-gray-500">AnythingLLM URL</label>
                                    {apiKeys.anythingllm_url && apiKeys.anythingllm_key && (
                                        <span className="text-[10px] text-green-400 flex items-center gap-1">
                                            <CheckCircle size={10} /> CONNECTÉ
                                        </span>
                                    )}
                                </div>
                                <input
                                    type="text"
                                    name="anythingllm_url"
                                    value={apiKeys.anythingllm_url}
                                    onChange={handleApiKeyChange}
                                    placeholder="http://localhost:3001/api/v1"
                                    className="w-full bg-black/40 border border-gray-700 rounded p-2 text-xs text-white focus:border-purple-500 focus:outline-none mb-2"
                                />
                                <label className="text-xs text-gray-500 block mb-1">AnythingLLM Key</label>
                                <input
                                    type="password"
                                    name="anythingllm_key"
                                    value={apiKeys.anythingllm_key}
                                    onChange={handleApiKeyChange}
                                    placeholder="API Key..."
                                    className="w-full bg-black/40 border border-gray-700 rounded p-2 text-xs text-white focus:border-purple-500 focus:outline-none"
                                />
                            </div>

                            {/* USER API KEY (SAAS) */}
                            <div className="pt-4 border-t border-gray-800 mt-4">
                                <h3 className="text-sm font-bold text-cyan-400 mb-2 flex items-center gap-2">
                                    <Shield size={14} />
                                    CLÉ D'ACCÈS UTILISATEUR (SaaS)
                                </h3>
                                <div className="flex justify-between items-center mb-1">
                                    <label className="text-xs text-gray-500">Votre Clé API (Th3 Thirty3)</label>
                                    {apiKeys.userApiKey && (
                                        <span className="text-[10px] text-cyan-400 flex items-center gap-1">
                                            <CheckCircle size={10} /> ENREGISTRÉ
                                        </span>
                                    )}
                                </div>
                                <input
                                    type="password"
                                    name="userApiKey"
                                    value={apiKeys.userApiKey}
                                    onChange={handleApiKeyChange}
                                    placeholder="sk-..."
                                    className="w-full bg-black/40 border border-cyan-900 rounded p-2 text-xs text-white focus:border-cyan-500 focus:outline-none"
                                />
                                <p className="text-[10px] text-gray-500 mt-1">
                                    Cette clé détermine votre niveau d'accès (Initiate, Operator, Shadow).
                                </p>
                            </div>

                            <button
                                onClick={saveApiKeys}
                                className="w-full bg-yellow-900/50 border border-yellow-600 text-yellow-200 py-2 rounded text-xs font-bold hover:bg-yellow-800/50 transition-colors mt-2"
                            >
                                SAUVEGARDER LES CLÉS
                            </button>
                        </div>
                    </div>

                </div>

                {/* COLUMN 2: CONNECTORS STATUS */}
                <div className="bg-gray-900/50 border border-gray-700 p-6 rounded-lg backdrop-blur h-full">
                    <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-2">
                        <Activity size={20} /> ÉTAT DES CONNECTEURS
                    </h3>

                    <div className="space-y-6">
                        {/* GMAIL */}
                        <div>
                            <h4 className="text-xs uppercase text-gray-500 font-bold mb-2 flex items-center gap-2">
                                <Mail size={12} /> GMAIL FLUX
                            </h4>
                            <div className="space-y-2">
                                {connectors.gmail.map(acc => (
                                    <div key={acc.id} className="flex justify-between items-center bg-black/40 p-2 rounded border border-gray-800">
                                        <span className="text-sm text-gray-300">{acc.email}</span>
                                        <div className="flex items-center gap-2">
                                            <span className={`text-xs flex items-center gap-1 ${acc.status === 'active' ? 'text-green-400' : 'text-red-500'}`}>
                                                {acc.status === 'active' ? <CheckCircle size={10} /> : <XCircle size={10} />}
                                                {acc.status === 'active' ? 'ACTIVE' : 'INACTIVE'}
                                            </span>
                                            {acc.status !== 'active' && (
                                                <a
                                                    href={`${API_URL}/auth/google?email=${acc.email}`}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="text-[10px] bg-blue-900/50 text-blue-300 px-2 py-1 rounded border border-blue-800 hover:bg-blue-800 transition-colors"
                                                >
                                                    CONNECTER
                                                </a>
                                            )}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* CALENDAR */}
                        <div>
                            <h4 className="text-xs uppercase text-gray-500 font-bold mb-2 flex items-center gap-2">
                                <Calendar size={12} /> CALENDAR SYNC
                            </h4>
                            <div className="space-y-2">
                                {connectors.calendar.map(acc => (
                                    <div key={acc.id} className="flex justify-between items-center bg-black/40 p-2 rounded border border-gray-800">
                                        <span className="text-sm text-gray-300">{acc.email}</span>
                                        <span className={`text-xs flex items-center gap-1 ${acc.status === 'active' ? 'text-green-400' : 'text-red-500'}`}>
                                            {acc.status === 'active' ? <CheckCircle size={10} /> : <XCircle size={10} />}
                                            {acc.status === 'active' ? 'ACTIVE' : 'INACTIVE'}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* OTHERS */}
                        <div className="grid grid-cols-2 gap-4">
                            <div className="bg-black/40 p-3 rounded border border-gray-800">
                                <div className="text-xs text-gray-500 mb-1">DART AI</div>
                                <div className="flex justify-between items-center">
                                    <span className="text-sm text-white">th3thirty3</span>
                                    <CheckCircle size={12} className="text-green-500" />
                                </div>
                            </div>
                            <div className="bg-black/40 p-3 rounded border border-gray-800">
                                <div className="text-xs text-gray-500 mb-1">TELESCOPE</div>
                                <div className="flex justify-between items-center">
                                    <span className="text-sm text-white">WWT Client</span>
                                    <CheckCircle size={12} className="text-green-500" />
                                </div>
                            </div>
                        </div>

                    </div>
                </div>

            </div>
        </div >
    );
};

export default SettingsPage;
