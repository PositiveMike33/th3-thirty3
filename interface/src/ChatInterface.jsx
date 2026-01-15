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
import OllamaTrainingDashboard from './OllamaTrainingDashboard';
import { APP_CONFIG, API_URL } from './config';
import FabricLibrary from './components/FabricLibrary';
import { MessageSquare, LayoutDashboard, Settings, LogOut, Telescope, Briefcase, BookOpen, X, Brain, Facebook, Youtube, Linkedin, Instagram, Twitter } from 'lucide-react';

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
            <div className="w-64 bg-black border-r border-cyan-900 flex flex-col">
                <div className="p-4 border-b border-cyan-900 flex justify-center items-center">
                    <div className="w-24 h-24 max-w-[96px] max-h-[96px]">
                        <Avatar isSpeaking={isAgentSpeaking} size="w-full h-full" />
                    </div>
                </div>

                <div className="p-2 space-y-1">
                    <div className="text-xs uppercase tracking-widest text-gray-500 px-3 py-2 mb-2">Réseaux Sociaux</div>
                    <a href="https://www.facebook.com/mike.g.guillet" target="_blank" rel="noopener noreferrer" className="w-full flex items-center gap-3 p-3 rounded transition-all hover:bg-blue-900/30 text-gray-400 hover:text-blue-400 group">
                        <Facebook size={18} className="group-hover:scale-110 transition-transform" /> <span>Facebook</span>
                    </a>
                    <a href="https://x.com/guillet_mike" target="_blank" rel="noopener noreferrer" className="w-full flex items-center gap-3 p-3 rounded transition-all hover:bg-gray-800/50 text-gray-400 hover:text-white group">
                        <Twitter size={18} className="group-hover:scale-110 transition-transform" /> <span>X (Twitter)</span>
                    </a>
                    <a href="https://www.youtube.com/" target="_blank" rel="noopener noreferrer" className="w-full flex items-center gap-3 p-3 rounded transition-all hover:bg-red-900/30 text-gray-400 hover:text-red-400 group">
                        <Youtube size={18} className="group-hover:scale-110 transition-transform" /> <span>YouTube</span>
                    </a>
                    <a href="https://www.instagram.com/mikegauthierguillet/" target="_blank" rel="noopener noreferrer" className="w-full flex items-center gap-3 p-3 rounded transition-all hover:bg-pink-800/30 text-gray-400 hover:text-pink-300 group">
                        <Instagram size={18} className="group-hover:scale-110 transition-transform" /> <span>Instagram</span>
                    </a>
                    <a href="https://www.linkedin.com/in/micha%C3%ABl-gauthier-guillet-2141b8198/" target="_blank" rel="noopener noreferrer" className="w-full flex items-center gap-3 p-3 rounded transition-all hover:bg-blue-800/30 text-gray-400 hover:text-blue-300 group">
                        <Linkedin size={18} className="group-hover:scale-110 transition-transform" /> <span>LinkedIn</span>
                    </a>
                </div>

                <div className="flex-1 overflow-y-auto p-4">
                    <div className="flex justify-between items-center mb-4">
                        <h2 className="text-xs uppercase tracking-widest text-gray-500">Missions</h2>
                        <button onClick={createNewSession} className="text-xs text-cyan-400 hover:text-cyan-300 border border-cyan-900 px-2 py-1 rounded hover:bg-cyan-900/30 transition-all">+ NEW</button>
                    </div>
                    <div className="space-y-2">
                        {sessions.map(session => (
                            <div key={session.id} onClick={() => loadSession(session.id)} className={`group p-3 rounded cursor-pointer border transition-all ${currentSessionId === session.id ? 'bg-cyan-900/30 border-cyan-500 text-white' : 'bg-gray-900 border-gray-800 text-gray-400 hover:border-cyan-700'}`}>
                                <div className="font-bold text-sm truncate">{session.title}</div>
                                <div className="text-xs text-gray-600 mt-1 flex justify-between items-center">
                                    <span>{new Date(session.lastModified).toLocaleDateString()}</span>
                                    <button onClick={(e) => deleteSession(session.id, e)} className="opacity-0 group-hover:opacity-100 text-red-500 hover:text-red-400">×</button>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="p-4 border-t border-cyan-900 bg-black/50">
                    <div className="mb-2">
                        <span className="text-xs text-gray-500 uppercase tracking-widest">Comptes Google</span>
                        <GoogleAuthPanel />
                    </div>
                    <div className="mt-4 flex items-center justify-between text-xs text-gray-500">
                        <span>v1.2.0</span>
                        <div className="flex gap-2">
                            <button onClick={() => setCurrentView('settings')} className={`hover:text-cyan-400 ${currentView === 'settings' ? 'text-cyan-400' : ''}`}><Settings size={14} /></button>
                            <button className="hover:text-red-400"><LogOut size={14} /></button>
                        </div>
                    </div>
                </div>
            </div>

            <div className="flex-1 flex flex-col relative bg-transparent">
                <div className="h-16 border-b border-cyan-900 bg-black/80 backdrop-blur flex items-center justify-between px-6 z-40">
                    <div className="flex items-center gap-4">
                        <ModelSelector currentProvider={selectedProvider} currentModel={selectedModel} onSelectModel={handleModelSelect} />
                        <div className="flex items-center gap-2 border-l border-cyan-900 pl-4">
                            <button onClick={() => setLibraryOpen(true)} className={`flex items-center gap-2 px-3 py-1 rounded text-sm border transition-all ${selectedPattern ? 'bg-cyan-900/50 border-cyan-500 text-cyan-300' : 'bg-black border-cyan-900 text-gray-400 hover:text-cyan-400 hover:border-cyan-700'}`}>
                                <BookOpen size={14} /> <span>{selectedPattern || "Bibliothèque Fabric"}</span>
                            </button>
                            {selectedPattern && (
                                <button onClick={() => setSelectedPattern('')} className="text-gray-500 hover:text-red-400" title="Désactiver le pattern"><X size={14} /></button>
                            )}
                        </div>
                        <FabricLibrary isOpen={libraryOpen} onClose={() => setLibraryOpen(false)} onSelectPattern={(pattern) => setSelectedPattern(pattern)} />
                    </div>
                    <div className="flex items-center gap-4">
                        <button onClick={() => setIsMuted(!isMuted)} className={`p-2 rounded-full border ${isMuted ? 'border-red-500 text-red-500' : 'border-cyan-500 text-cyan-500'} hover:bg-gray-800 transition-all`}>
                            {isMuted ? '🔇' : '🔊'}
                        </button>
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
                    <div className="flex-1 overflow-hidden"><OllamaTrainingDashboard /></div>
                ) : (
                    <>
                        <div className="flex-1 overflow-y-auto p-6 space-y-6 scrollbar-thin scrollbar-thumb-cyan-900 scrollbar-track-black">
                            {messages.map((msg) => (
                                <div key={msg.id} className={`flex ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
                                    <div className={`max-w-[80%] p-4 rounded-lg border backdrop-blur-sm ${msg.sender === 'user' ? 'bg-cyan-900/20 border-cyan-500/50 text-cyan-100 rounded-br-none' : 'bg-black/60 border-gray-700 text-gray-300 rounded-bl-none shadow-[0_0_15px_rgba(0,255,255,0.1)]'}`}>
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

                        <div className="p-6 bg-black/80 border-t border-cyan-900 backdrop-blur">
                            <div className="relative max-w-4xl mx-auto">
                                <input type="text" value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={handleKeyDown} placeholder="Entrez votre commande..." className="w-full bg-gray-900/50 border border-cyan-700 rounded-lg py-4 pl-4 pr-12 text-cyan-100 placeholder-cyan-800 focus:outline-none focus:border-cyan-400 focus:shadow-[0_0_20px_rgba(8,145,178,0.3)] transition-all" />
                                <button onClick={toggleListening} className={`absolute right-3 top-1/2 -translate-y-1/2 p-2 rounded-full transition-all ${isListening ? 'bg-red-500/20 text-red-500 animate-pulse' : 'text-cyan-600 hover:text-cyan-400'}`}>{isListening ? '🛑' : '🎤'}</button>
                                <button onClick={() => setShowWebcam(true)} className={`absolute right-12 top-1/2 -translate-y-1/2 p-2 rounded-full transition-all ${capturedImage ? 'text-green-500' : 'text-cyan-600 hover:text-cyan-400'}`} title="Activer la Vision">📷</button>
                                <button onClick={() => setIsMuted(!isMuted)} className={`absolute right-20 top-1/2 -translate-y-1/2 p-2 rounded-full transition-all ${isMuted ? 'text-red-500' : 'text-cyan-600 hover:text-cyan-400'}`} title={isMuted ? "Activer le son" : "Couper le son"}>{isMuted ? '🔇' : '🔊'}</button>
                            </div>
                            {capturedImage && (
                                <div className="mt-2 flex items-center gap-2"><span className="text-xs text-green-500 font-mono">Image capturée</span><button onClick={() => setCapturedImage(null)} className="text-red-500 text-xs hover:underline">Supprimer</button></div>
                            )}
                            <div className="text-center mt-2 text-[10px] text-gray-600 uppercase tracking-widest">Système Sécurisé • Chiffrage End-to-End • {APP_CONFIG.version}</div>
                        </div>
                    </>
                )}
            </div>

            <FeedbackModal isOpen={feedbackModalOpen} onClose={() => setFeedbackModalOpen(false)} onSubmit={submitFeedback} correctionText={correctionText} setCorrectionText={setCorrectionText} />
            {showWebcam && (<WebcamInput onCapture={(img) => { setCapturedImage(img); setShowWebcam(false); }} onClose={() => setShowWebcam(false)} />)}
        </div >
    );
};

export default ChatInterface;
