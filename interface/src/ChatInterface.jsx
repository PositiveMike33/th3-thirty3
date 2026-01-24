import React, { useState, useEffect, useRef, useCallback } from 'react';
import { api } from './services/apiService';
import Avatar from './Avatar';
import GoogleAuthPanel from './components/GoogleAuthPanel';
import FeedbackModal from './components/FeedbackModal';
import PatternModal from './components/PatternModal';
import WebcamInput from './components/WebcamInput';
import ModelSelector from './components/ModelSelector';
import Dashboard from './Dashboard';
import SpaceDashboard from './SpaceDashboard';
import ProjectDashboard from './ProjectDashboard';
import SettingsPage from './SettingsPage';
// OllamaTrainingDashboard removed - Cloud Only Mode
import { APP_CONFIG, API_URL } from './config';
import FabricLibrary from './components/FabricLibrary';
import { MessageSquare, LayoutDashboard, Settings, LogOut, Telescope, Briefcase, BookOpen, X, Brain, Facebook, Youtube, Linkedin, Instagram, Twitter, ChevronLeft, ChevronRight, Maximize2, Minimize2 } from 'lucide-react';

const ChatInterface = () => {
    const [messages, setMessages] = useState([
        { id: 1, sender: 'agent', text: `Initialisation... ${APP_CONFIG.name} en ligne. C'est quoi le plan ?` }
    ]);
    const [input, setInput] = useState('');
    const [isListening, setIsListening] = useState(false);
    const [isMuted, setIsMuted] = useState(false);
    const messagesEndRef = useRef(null);
    const [selectedPattern, setSelectedPattern] = useState('');
    const [libraryOpen, setLibraryOpen] = useState(false);
    const [sidebarExpanded, setSidebarExpanded] = useState(false); // Mode élargi pour voir les patterns

    // View State (Chat vs Dashboard)
    const [currentView, setCurrentView] = useState('chat');

    // Model Selection State - Default to Gemini 3 Pro with localStorage persistence
    const [selectedProvider, setSelectedProvider] = useState(() => {
        return localStorage.getItem('th3_selected_provider') || 'gemini';
    });
    const [selectedModel, setSelectedModel] = useState(() => {
        return localStorage.getItem('th3_selected_model') || 'gemini-3-pro-preview';
    });

    // Feedback State
    const [feedbackModalOpen, setFeedbackModalOpen] = useState(false);
    const [feedbackMsgId, setFeedbackMsgId] = useState(null);
    const [correctionText, setCorrectionText] = useState('');

    // Session State
    const [sessions, setSessions] = useState([]);
    const [currentSessionId, setCurrentSessionId] = useState(null);

    const [isAgentSpeaking, setIsAgentSpeaking] = useState(false);

    // Vision State
    const [showWebcam, setShowWebcam] = useState(false);
    const [capturedImage, setCapturedImage] = useState(null);

    const isMutedRef = useRef(isMuted);

    useEffect(() => {
        isMutedRef.current = isMuted;
        if (isMuted) {
            window.speechSynthesis.cancel(); // Stop talking immediately if muted
        }
    }, [isMuted]);

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };

    useEffect(scrollToBottom, [messages]);

    // Helper: Text-to-Speech
    const speak = (text) => {
        if (!isMutedRef.current) {
            const utterance = new SpeechSynthesisUtterance(text);
            const loadVoices = () => {
                window.speechSynthesis.onvoiceschanged = null;
                const voices = window.speechSynthesis.getVoices();
                const frenchVoice = voices.find(voice => voice.lang.includes('fr-CA')) || voices.find(voice => voice.lang.includes('fr'));
                if (frenchVoice) utterance.voice = frenchVoice;
                utterance.pitch = 0.9;
                utterance.rate = 1.1;

                if (!isMutedRef.current) {
                    window.speechSynthesis.speak(utterance);
                }
            };

            if (window.speechSynthesis.getVoices().length === 0) {
                window.speechSynthesis.onvoiceschanged = loadVoices;
            } else {
                loadVoices();
            }
        }
    };

    const loadSessions = useCallback(() => {
        api.get('/sessions')
            .then(data => {
                if (Array.isArray(data)) {
                    setSessions(data);
                } else if (data && Array.isArray(data.sessions)) {
                    setSessions(data.sessions);
                } else {
                    setSessions([]);
                }
            })
            .catch(err => {
                console.error("Failed to load sessions", err);
                setSessions([]);
            });
    }, []);

    useEffect(() => {
        api.get('/settings')
            .then(data => {
                if (data.apiKeys && data.apiKeys.userApiKey) {
                    localStorage.setItem('th3_api_key', data.apiKeys.userApiKey);
                }
                if (data.computeMode) {
                    setSelectedProvider(data.computeMode === 'cloud' ? 'anythingllm' : data.computeMode);
                    if (data.computeMode === 'cloud') {
                        setSelectedModel('gpt-4o');
                    }
                }
            })
            .catch(err => console.error("Failed to load settings", err));
        loadSessions();
    }, [loadSessions]);

    const createNewSession = () => {
        setMessages([{ id: 1, sender: 'agent', text: `Initialisation... ${APP_CONFIG.name} en ligne. C'est quoi le plan ?` }]);
        setCurrentSessionId(null);
    };

    const loadSession = (id) => {
        api.get(`/sessions/${id}`)
            .then(data => {
                const formattedMessages = data.messages.map((msg, index) => ({
                    id: msg.id || `legacy-${index}-${Date.now()}`,
                    sender: msg.role === 'user' ? 'user' : 'agent',
                    text: msg.content
                }));
                setMessages(formattedMessages);
                setCurrentSessionId(data.id);
            })
            .catch(err => console.error("Failed to load session", err));
    };

    const deleteSession = (id, e) => {
        e.stopPropagation();
        if (window.confirm("Supprimer cette session ?")) {
            api.delete(`/sessions/${id}`)
                .then(() => loadSessions());
        }
    };

    const handleDeleteMessage = async (msgId, e) => {
        e.stopPropagation();
        if (!currentSessionId) return;

        if (window.confirm("Supprimer ce message ?")) {
            try {
                await api.delete(`/sessions/${currentSessionId}/messages/${msgId}`);
                setMessages(prev => prev.filter(m => m.id !== msgId));
            } catch (error) {
                console.error("Error deleting message:", error);
            }
        }
    };

    const handleSend = async () => {
        if (!input.trim()) return;

        const userMessage = {
            id: messages.length + 1,
            sender: 'user',
            text: input,
            image: capturedImage
        };
        setMessages(prev => [...prev, userMessage]);
        setInput('');
        const imageToSend = capturedImage;
        setCapturedImage(null);

        try {
            setIsAgentSpeaking(true);
            const startTime = Date.now();

            if (selectedProvider === 'hackergpt') {
                const infoMsg = {
                    id: messages.length + 1.5,
                    sender: 'agent',
                    text: '⏳ HackerGPT analyse en cours avec Gemini... (Fallback: AnythingLLM th3-thirty3)',
                    isTemp: true
                };
                setMessages(prev => [...prev, infoMsg]);
            }

            const data = await api.post('/chat', {
                message: input,
                image: imageToSend,
                pattern: selectedPattern,
                provider: selectedProvider,
                model: selectedModel,
                sessionId: currentSessionId
            });
            const responseTime = Date.now() - startTime;

            if (selectedModel) {
                const trackingName = selectedProvider === 'local'
                    ? selectedModel
                    : `[${selectedProvider.toUpperCase()}] ${selectedModel}`;
                api.post(`/models/${encodeURIComponent(trackingName)}/track-query`, {
                    responseTime,
                    tokensGenerated: Math.floor((data.reply?.length || 0) / 4),
                    success: true,
                    category: selectedPattern ? 'analysis' : null,
                    qualityScore: null
                }).catch(console.error);
            }

            if (data.sessionId) {
                setCurrentSessionId(data.sessionId);
                loadSessions();
            }

            const agentMessage = { id: data.agentMsgId, sender: 'agent', text: data.reply };

            setMessages(prev => {
                let newMsgs = prev.filter(m => !m.isTemp);
                const lastUserMsgIndex = newMsgs.findIndex(m => m.text === input && m.sender === 'user');
                if (lastUserMsgIndex !== -1) {
                    newMsgs[lastUserMsgIndex].id = data.userMsgId;
                }
                return [...newMsgs, agentMessage];
            });
            setIsAgentSpeaking(false);
            speak(data.reply);
        } catch (error) {
            console.error("Error:", error);
            const errorText = error.message || "Erreur de connexion au serveur.";
            const errorMessage = { id: messages.length + 2, sender: 'agent', text: `⚠️ Erreur: ${errorText}` };
            setMessages(prev => [...prev.filter(m => !m.isTemp), errorMessage]);
        }
    };

    const handleKeyDown = (e) => {
        if (e.key === 'Enter') handleSend();
    };

    const toggleListening = () => {
        if (isListening) {
            setIsListening(false);
        } else {
            setIsListening(true);
            const recognition = new (window.SpeechRecognition || window.webkitSpeechRecognition)();
            recognition.lang = 'fr-FR';
            recognition.start();
            recognition.onresult = (event) => {
                const transcript = event.results[0][0].transcript;
                setInput(transcript);
                setIsListening(false);
            };
        }
    };

    const handleFeedbackOpen = (msgId) => {
        setFeedbackMsgId(msgId);
        setFeedbackModalOpen(true);
    };

    const submitFeedback = async () => {
        if (!feedbackMsgId || !correctionText) return;
        const msgIndex = messages.findIndex(m => m.id === feedbackMsgId);
        const wrongResponse = messages[msgIndex].text;
        const originalQuery = messages[msgIndex - 1]?.text;

        if (originalQuery) {
            try {
                await api.post('/feedback', { originalQuery, wrongResponse, correction: correctionText });
                alert("Correction envoyée !");
                setFeedbackModalOpen(false);
                setCorrectionText('');
            } catch {
                alert("Erreur lors de l'envoi du feedback.");
            }
        }
    };

    const handleModelSelect = (model, provider) => {
        setSelectedModel(model);
        setSelectedProvider(provider);
        localStorage.setItem('th3_selected_model', model);
        localStorage.setItem('th3_selected_provider', provider);

        const isLocal = provider === 'local' || provider === 'lmstudio';
        const computeMode = isLocal ? 'local' : 'cloud';

        api.post('/settings', { computeMode }).catch(console.error);

        const systemMsg = {
            id: messages.length + 1,
            sender: 'agent',
            text: `[SYSTEM] 🔥 Module activé : ${model} (${provider.toUpperCase()})`
        };
        setMessages(prev => [...prev, systemMsg]);
    };

    return (
        <div className="flex h-full w-full bg-transparent text-cyan-300 font-mono overflow-hidden">
            {/* Zone principale - Chat en pleine page */}
            <div className="flex-1 flex flex-col relative bg-transparent">
                {/* Header avec Model Selector */}
                <div className="h-16 border-b border-cyan-900 bg-black/80 backdrop-blur flex items-center justify-between px-6 z-40">
                    <div className="flex items-center gap-4">
                        <div className="w-12 h-12">
                            <Avatar isSpeaking={isAgentSpeaking} size="w-full h-full" />
                        </div>
                        <ModelSelector currentProvider={selectedProvider} currentModel={selectedModel} onSelectModel={handleModelSelect} />

                        {/* Sessions dropdown */}
                        <div className="flex items-center gap-2 border-l border-cyan-900 pl-4">
                            <button onClick={createNewSession} className="text-xs text-cyan-400 hover:text-cyan-300 border border-cyan-900 px-3 py-2 rounded hover:bg-cyan-900/30 transition-all flex items-center gap-2">
                                <MessageSquare size={14} /> + Nouvelle Session
                            </button>
                        </div>
                    </div>
                    <div className="flex items-center gap-4">
                        <button onClick={() => setIsMuted(!isMuted)} className={`p-2 rounded-full border ${isMuted ? 'border-red-500 text-red-500' : 'border-cyan-500 text-cyan-500'} hover:bg-gray-800 transition-all`}>
                            {isMuted ? '🔇' : '🔊'}
                        </button>
                        <GoogleAuthPanel />
                    </div>
                </div>

                {currentView === 'dashboard' ? (
                    <div className="flex-1 overflow-hidden"><Dashboard /></div>
                ) : currentView === 'space' ? (
                    <div className="flex-1 overflow-hidden"><SpaceDashboard /></div>
                ) : currentView === 'project' ? (
                    <div className="flex-1 overflow-hidden" style={{ display: 'flex', flexDirection: 'column', height: '100%' }}><ProjectDashboard /></div>
                ) : currentView === 'settings' ? (
                    <div className="flex-1 overflow-hidden"><SettingsPage /></div>
                ) : currentView === 'training' ? (
                    <div className="flex-1 overflow-hidden flex items-center justify-center bg-gray-900">
                        <div className="text-center p-8">
                            <div className="text-6xl mb-4">☁️</div>
                            <h2 className="text-2xl font-bold text-cyan-400 mb-2">CLOUD ONLY MODE</h2>
                            <p className="text-gray-500">Local training désactivé - Utilisez les modèles Cloud.</p>
                        </div>
                    </div>
                ) : (
                    <>
                        {/* Zone de messages - pleine largeur */}
                        <div className="flex-1 overflow-y-auto p-6 space-y-6 scrollbar-thin scrollbar-thumb-cyan-900 scrollbar-track-black">
                            {/* Sessions actives - barre horizontale compacte */}
                            {sessions.length > 0 && (
                                <div className="flex gap-2 overflow-x-auto pb-2 mb-4 border-b border-cyan-900/50">
                                    {sessions.slice(0, 5).map(session => (
                                        <button key={session.id} onClick={() => loadSession(session.id)} className={`flex-shrink-0 px-3 py-1 rounded text-xs transition-all ${currentSessionId === session.id ? 'bg-cyan-900/50 border-cyan-500 text-cyan-300' : 'bg-gray-900/50 border-gray-700 text-gray-400 hover:text-cyan-400'} border`}>
                                            {session.title?.substring(0, 20) || 'Session'}...
                                        </button>
                                    ))}
                                </div>
                            )}

                            {messages.map((msg) => (
                                <div key={msg.id} className={`flex ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
                                    <div className={`max-w-[70%] p-4 rounded-lg border backdrop-blur-sm ${msg.sender === 'user' ? 'bg-cyan-900/20 border-cyan-500/50 text-cyan-100 rounded-br-none' : 'bg-black/60 border-gray-700 text-gray-300 rounded-bl-none shadow-[0_0_15px_rgba(0,255,255,0.1)]'}`}>
                                        <div className="flex items-center gap-2 mb-2 border-b border-white/10 pb-1 justify-between">
                                            <div className="flex items-center gap-2">
                                                <span className={`text-xs font-bold uppercase tracking-wider ${msg.sender === 'user' ? 'text-cyan-400' : 'text-purple-400'}`}>{msg.sender === 'user' ? 'OPERATOR' : APP_CONFIG.name}</span>
                                                <span className="text-[10px] text-gray-500">{new Date().toLocaleTimeString()}</span>
                                            </div>
                                            <button onClick={(e) => handleDeleteMessage(msg.id, e)} className="text-gray-600 hover:text-red-500 transition-colors" title="Supprimer le message"><LogOut size={12} className="rotate-180" /></button>
                                        </div>
                                        <div className="whitespace-pre-wrap leading-relaxed text-sm">
                                            {msg.image && (<div className="mb-2"><img src={msg.image} alt="Captured" className="max-w-xs rounded border border-cyan-500/30" /></div>)}
                                            {msg.text}
                                        </div>
                                        {msg.sender === 'agent' && (
                                            <div className="mt-2 flex justify-end">
                                                <button onClick={() => handleFeedbackOpen(msg.id)} className="text-gray-600 hover:text-red-400 text-xs flex items-center gap-1 transition-colors" title="Signaler une erreur">👎 Corriger</button>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            ))}
                            <div ref={messagesEndRef} />
                        </div>

                        {/* Zone de saisie - pleine largeur */}
                        <div className="p-6 bg-black/80 border-t border-cyan-900 backdrop-blur">
                            <div className="relative max-w-full mx-auto">
                                <input type="text" value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={handleKeyDown} placeholder="Entrez votre commande..." className="w-full bg-gray-900/50 border border-cyan-700 rounded-lg py-4 pl-4 pr-32 text-cyan-100 placeholder-cyan-800 focus:outline-none focus:border-cyan-400 focus:shadow-[0_0_20px_rgba(8,145,178,0.3)] transition-all" />
                                <button onClick={toggleListening} className={`absolute right-3 top-1/2 -translate-y-1/2 p-2 rounded-full transition-all ${isListening ? 'bg-red-500/20 text-red-500 animate-pulse' : 'text-cyan-600 hover:text-cyan-400'}`}>{isListening ? '🛑' : '🎤'}</button>
                                <button onClick={() => setShowWebcam(true)} className={`absolute right-12 top-1/2 -translate-y-1/2 p-2 rounded-full transition-all ${capturedImage ? 'text-green-500' : 'text-cyan-600 hover:text-cyan-400'}`} title="Activer la Vision">📷</button>
                                <button onClick={() => setIsMuted(!isMuted)} className={`absolute right-20 top-1/2 -translate-y-1/2 p-2 rounded-full transition-all ${isMuted ? 'text-red-500' : 'text-cyan-600 hover:text-cyan-400'}`} title={isMuted ? "Activer le son" : "Couper le son"}>{isMuted ? '🔇' : '🔊'}</button>
                                <button onClick={handleSend} className="absolute right-28 top-1/2 -translate-y-1/2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-black font-bold rounded transition-all">↵</button>
                            </div>
                            {capturedImage && (
                                <div className="mt-2 flex items-center gap-2"><span className="text-xs text-green-500 font-mono">Image capturée</span><button onClick={() => setCapturedImage(null)} className="text-red-500 text-xs hover:underline">Supprimer</button></div>
                            )}
                            <div className="text-center mt-2 text-[10px] text-gray-600 uppercase tracking-widest">Système Sécurisé • Chiffrage End-to-End • {APP_CONFIG.version}</div>
                        </div>
                    </>
                )}
            </div>

            {/* Bande de droite - Réseaux Sociaux + Fabric - Mode redimensionnable */}
            <div className={`${sidebarExpanded ? 'w-[700px]' : 'w-72'} bg-black/90 border-l border-cyan-900 flex flex-col backdrop-blur-sm transition-all duration-300 ease-in-out`}>
                {/* Bouton Toggle Expand/Collapse */}
                <div className="p-2 border-b border-cyan-900/50 flex justify-between items-center">
                    <span className="text-[10px] uppercase tracking-widest text-gray-600">{sidebarExpanded ? '📖 MODE LECTURE PATTERNS' : 'MODE COMPACT'}</span>
                    <button
                        onClick={() => setSidebarExpanded(!sidebarExpanded)}
                        className="p-2 rounded hover:bg-purple-900/30 text-gray-400 hover:text-purple-400 transition-all flex items-center gap-1 text-xs"
                        title={sidebarExpanded ? 'Réduire' : 'Élargir pour voir les patterns en entier'}
                    >
                        {sidebarExpanded ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
                        <span>{sidebarExpanded ? 'Réduire' : 'Élargir'}</span>
                    </button>
                </div>

                {/* Section Fabric Library - Mode intégré quand élargi */}
                <div className={`p-4 border-b border-cyan-900 ${sidebarExpanded ? 'flex-1 overflow-hidden flex flex-col' : ''}`}>
                    <div className="text-xs uppercase tracking-widest text-purple-400 mb-3 flex items-center gap-2">
                        <Brain size={14} /> Fabric Patterns
                    </div>

                    {/* Bouton pour ouvrir la modal ou le mode intégré */}
                    <button onClick={() => setLibraryOpen(true)} className={`w-full flex items-center gap-2 px-3 py-3 rounded text-sm border transition-all ${selectedPattern ? 'bg-purple-900/50 border-purple-500 text-purple-300' : 'bg-black border-purple-900/50 text-gray-400 hover:text-purple-400 hover:border-purple-700'}`}>
                        <BookOpen size={16} /> <span className={sidebarExpanded ? '' : 'truncate'}>{selectedPattern || "Ouvrir la bibliothèque"}</span>
                    </button>

                    {selectedPattern && (
                        <button onClick={() => setSelectedPattern('')} className="w-full mt-2 text-xs text-gray-500 hover:text-red-400 flex items-center justify-center gap-1">
                            <X size={12} /> Désactiver le pattern
                        </button>
                    )}

                    {/* Mode élargi: Instructions pour naviguer */}
                    {sidebarExpanded && (
                        <div className="mt-4 p-3 bg-purple-900/20 border border-purple-800/50 rounded-lg">
                            <p className="text-xs text-purple-300 text-center">
                                💡 Cliquez sur "Ouvrir la bibliothèque" pour parcourir tous les patterns. En mode élargi, vous verrez chaque pattern en détail complet!
                            </p>
                        </div>
                    )}

                    <FabricLibrary isOpen={libraryOpen} onClose={() => setLibraryOpen(false)} onSelectPattern={(pattern) => setSelectedPattern(pattern)} />
                </div>

                {/* Section Réseaux Sociaux - Compacte en mode élargi */}
                <div className={`p-4 ${sidebarExpanded ? '' : 'flex-1'}`}>
                    <div className="text-xs uppercase tracking-widest text-gray-500 mb-3">Réseaux Sociaux</div>
                    <div className={`${sidebarExpanded ? 'flex flex-wrap gap-2' : 'space-y-2'}`}>
                        <a href="https://www.facebook.com/mike.g.guillet" target="_blank" rel="noopener noreferrer" className={`flex items-center gap-2 ${sidebarExpanded ? 'p-2 text-sm' : 'p-3 w-full'} rounded transition-all hover:bg-blue-900/30 text-gray-400 hover:text-blue-400 group border border-transparent hover:border-blue-900/50`}>
                            <Facebook size={sidebarExpanded ? 16 : 18} className="group-hover:scale-110 transition-transform" /> {!sidebarExpanded && <span>Facebook</span>}
                        </a>
                        <a href="https://x.com/guillet_mike" target="_blank" rel="noopener noreferrer" className={`flex items-center gap-2 ${sidebarExpanded ? 'p-2 text-sm' : 'p-3 w-full'} rounded transition-all hover:bg-gray-800/50 text-gray-400 hover:text-white group border border-transparent hover:border-gray-700`}>
                            <Twitter size={sidebarExpanded ? 16 : 18} className="group-hover:scale-110 transition-transform" /> {!sidebarExpanded && <span>X (Twitter)</span>}
                        </a>
                        <a href="https://www.youtube.com/" target="_blank" rel="noopener noreferrer" className={`flex items-center gap-2 ${sidebarExpanded ? 'p-2 text-sm' : 'p-3 w-full'} rounded transition-all hover:bg-red-900/30 text-gray-400 hover:text-red-400 group border border-transparent hover:border-red-900/50`}>
                            <Youtube size={sidebarExpanded ? 16 : 18} className="group-hover:scale-110 transition-transform" /> {!sidebarExpanded && <span>YouTube</span>}
                        </a>
                        <a href="https://www.instagram.com/mikegauthierguillet/" target="_blank" rel="noopener noreferrer" className={`flex items-center gap-2 ${sidebarExpanded ? 'p-2 text-sm' : 'p-3 w-full'} rounded transition-all hover:bg-pink-800/30 text-gray-400 hover:text-pink-300 group border border-transparent hover:border-pink-800/50`}>
                            <Instagram size={sidebarExpanded ? 16 : 18} className="group-hover:scale-110 transition-transform" /> {!sidebarExpanded && <span>Instagram</span>}
                        </a>
                        <a href="https://www.linkedin.com/in/micha%C3%ABl-gauthier-guillet-2141b8198/" target="_blank" rel="noopener noreferrer" className={`flex items-center gap-2 ${sidebarExpanded ? 'p-2 text-sm' : 'p-3 w-full'} rounded transition-all hover:bg-blue-800/30 text-gray-400 hover:text-blue-300 group border border-transparent hover:border-blue-800/50`}>
                            <Linkedin size={sidebarExpanded ? 16 : 18} className="group-hover:scale-110 transition-transform" /> {!sidebarExpanded && <span>LinkedIn</span>}
                        </a>
                    </div>
                </div>

                {/* Footer */}
                <div className="p-4 border-t border-cyan-900 bg-black/50">
                    <div className="flex items-center justify-between text-xs text-gray-500">
                        <span>{APP_CONFIG.version}</span>
                        <div className="flex gap-2">
                            <button onClick={() => setCurrentView('settings')} className={`hover:text-cyan-400 ${currentView === 'settings' ? 'text-cyan-400' : ''}`}><Settings size={14} /></button>
                            <button className="hover:text-red-400"><LogOut size={14} /></button>
                        </div>
                    </div>
                </div>
            </div>

            <FeedbackModal isOpen={feedbackModalOpen} onClose={() => setFeedbackModalOpen(false)} onSubmit={submitFeedback} correctionText={correctionText} setCorrectionText={setCorrectionText} />
            {showWebcam && (<WebcamInput onCapture={(img) => { setCapturedImage(img); setShowWebcam(false); }} onClose={() => setShowWebcam(false)} />)}
        </div>
    );
};

export default ChatInterface;
