import React, { useState, useEffect, useRef } from 'react';
import Avatar from './Avatar';
import GoogleAuthPanel from './components/GoogleAuthPanel';
import FeedbackModal from './components/FeedbackModal';
import PatternModal from './components/PatternModal';
import WebcamInput from './components/WebcamInput';
import ModelSelector from './components/ModelSelector';
import Dashboard from './Dashboard'; // Import Dashboard
import SpaceDashboard from './SpaceDashboard'; // Import SpaceDashboard
import ProjectDashboard from './ProjectDashboard'; // Import ProjectDashboard
import SettingsPage from './SettingsPage'; // Import SettingsPage
import { APP_CONFIG } from './config';
import { MessageSquare, LayoutDashboard, Settings, LogOut, Telescope, Briefcase } from 'lucide-react';

const ChatInterface = () => {
    const [messages, setMessages] = useState([
        { id: 1, sender: 'agent', text: `Initialisation... ${APP_CONFIG.name} en ligne. C'est quoi le plan ?` }
    ]);
    const [input, setInput] = useState('');
    const [isListening, setIsListening] = useState(false);
    const [isMuted, setIsMuted] = useState(false);
    const messagesEndRef = useRef(null);
    const [patterns, setPatterns] = useState([]);
    const [selectedPattern, setSelectedPattern] = useState('');

    // View State (Chat vs Dashboard)
    const [currentView, setCurrentView] = useState('chat');

    // Model Selection State
    const [selectedProvider, setSelectedProvider] = useState('local');
    const [selectedModel, setSelectedModel] = useState('granite3.1-moe:1b');

    // Feedback State
    const [feedbackModalOpen, setFeedbackModalOpen] = useState(false);
    const [feedbackMsgId, setFeedbackMsgId] = useState(null);
    const [correctionText, setCorrectionText] = useState('');

    // Session State
    const [sessions, setSessions] = useState([]);
    const [currentSessionId, setCurrentSessionId] = useState(null);

    // Pattern View State
    const [patternModalOpen, setPatternModalOpen] = useState(false);
    const [viewingPatternContent, setViewingPatternContent] = useState('');
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

    const loadSessions = () => {
        fetch('http://localhost:3000/sessions')
            .then(res => res.json()
                .then(data => {
                    setSessions(data);
                }))
            .catch(err => console.error("Failed to load sessions", err));
    };

    useEffect(() => {
        // Load Patterns
        fetch('http://localhost:3000/patterns')
            .then(res => res.json())
            .then(data => setPatterns(data))
            .catch(err => console.error("Failed to load patterns", err));

        // Load Settings (Compute Mode)
        fetch('http://localhost:3000/settings')
            .then(res => res.json())
            .then(data => {
                if (data.computeMode) {
                    setSelectedProvider(data.computeMode);
                    // Set default model based on mode
                    if (data.computeMode === 'cloud') {
                        // Try to pick a cloud model if available, otherwise default to Gemini
                        setSelectedModel('gemini-1.5-flash');
                    }
                }
            })
            .catch(err => console.error("Failed to load settings", err));

        // Load Sessions
        loadSessions();
    }, []);

    const createNewSession = () => {
        setMessages([{ id: 1, sender: 'agent', text: `Initialisation... ${APP_CONFIG.name} en ligne. C'est quoi le plan ?` }]);
        setCurrentSessionId(null);
    };

    const loadSession = (id) => {
        fetch(`http://localhost:3000/sessions/${id}`)
            .then(res => res.json())
            .then(data => {
                // Map backend format (role/content) to frontend format (sender/text)
                // and ensure IDs exist
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
            fetch(`http://localhost:3000/sessions/${id}`, { method: 'DELETE' })
                .then(() => loadSessions());
        }
    };

    const handleDeleteMessage = async (msgId, e) => {
        e.stopPropagation();
        if (!currentSessionId) return; // Can't delete from unsaved session easily without ID

        if (window.confirm("Supprimer ce message ?")) {
            try {
                const response = await fetch(`http://localhost:3000/sessions/${currentSessionId}/messages/${msgId}`, {
                    method: 'DELETE'
                });
                if (response.ok) {
                    setMessages(prev => prev.filter(m => m.id !== msgId));
                } else {
                    console.error("Failed to delete message");
                }
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
            image: capturedImage // Store image in local message for display
        };
        setMessages(prev => [...prev, userMessage]);
        setInput('');
        const imageToSend = capturedImage;
        setCapturedImage(null); // Clear immediately

        try {
            setIsAgentSpeaking(true);
            const response = await fetch('http://localhost:3000/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: input,
                    image: imageToSend, // Send image
                    pattern: selectedPattern,
                    provider: selectedProvider,
                    model: selectedModel,
                    sessionId: currentSessionId
                }),
            });
            const data = await response.json();

            if (data.sessionId) {
                setCurrentSessionId(data.sessionId);
                loadSessions(); // Refresh list
            }

            // Update user message with real ID if needed (though we just appended it)
            // Ideally we should replace the optimistic message with the confirmed one
            // For simplicity, we'll just update the last user message ID if we could track it,
            // but here we just append the agent message.
            // A better way is to reload the session or update the state more carefully.
            // Let's just append the agent message with its ID.

            const agentMessage = { id: data.agentMsgId, sender: 'agent', text: data.reply };

            // Also update the user message ID we just sent? 
            // We added it with `messages.length + 1`. 
            // Let's assume for now we reload or just accept the temp ID until reload.
            // actually, let's update the last user message with the real ID
            setMessages(prev => {
                const newMsgs = [...prev];
                const lastUserMsgIndex = newMsgs.findIndex(m => m.text === input && m.sender === 'user'); // Simple heuristic
                if (lastUserMsgIndex !== -1) {
                    newMsgs[lastUserMsgIndex].id = data.userMsgId;
                }
                return [...newMsgs, agentMessage];
            });
            setIsAgentSpeaking(false);
            speak(data.reply);
        } catch (error) {
            console.error("Error:", error);
            const errorMessage = { id: messages.length + 2, sender: 'agent', text: "Erreur de connexion au serveur." };
            setMessages(prev => [...prev, errorMessage]);
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

        // Find original query (user message before the agent message)
        const msgIndex = messages.findIndex(m => m.id === feedbackMsgId);
        const wrongResponse = messages[msgIndex].text;
        const originalQuery = messages[msgIndex - 1]?.text;

        if (originalQuery) {
            try {
                await fetch('http://localhost:3000/feedback', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ originalQuery, wrongResponse, correction: correctionText })
                });
                alert("Correction envoyée !");
                setFeedbackModalOpen(false);
                setCorrectionText('');
            } catch {
                alert("Erreur lors de l'envoi du feedback.");
            }
        }
    };

    const openPatternModal = (patternName) => {
        fetch(`http://localhost:3000/patterns/${patternName}`)
            .then(res => res.json())
            .then(data => {
                setViewingPatternContent(data.content);
                setPatternModalOpen(true);
            })
            .catch(() => alert("Impossible de charger le pattern"));
    };

    return (
        <div className="flex h-screen w-full bg-gray-900 text-cyan-300 font-mono overflow-hidden">
            {/* SIDEBAR */}
            <div className="w-64 bg-black border-r border-cyan-900 flex flex-col">
                <div className="p-6 pt-12 border-b border-cyan-900 flex justify-center items-center"> {/* Added pt-12 to push avatar down */}
                    <div className="">
                        <Avatar isSpeaking={isAgentSpeaking} size="w-32 h-32" />
                    </div>
                </div>

                {/* Navigation */}
                <div className="p-2 space-y-1">
                    <button
                        onClick={() => setCurrentView('chat')}
                        className={`w-full flex items-center gap-3 p-3 rounded transition-all ${currentView === 'chat' ? 'bg-cyan-900/50 text-white' : 'hover:bg-cyan-900/20 text-gray-400'}`}
                    >
                        <MessageSquare size={18} />
                        <span>Opérations</span>
                    </button>
                    <button
                        onClick={() => setCurrentView('dashboard')}
                        className={`w-full flex items-center gap-3 p-3 rounded transition-all ${currentView === 'dashboard' ? 'bg-cyan-900/50 text-white' : 'hover:bg-cyan-900/20 text-gray-400'}`}
                    >
                        <LayoutDashboard size={18} />
                        <span>Finance QG</span>
                    </button>

                    <button
                        onClick={() => setCurrentView('space')}
                        className={`w-full flex items-center gap-3 p-3 rounded transition-all ${currentView === 'space' ? 'bg-cyan-900/50 text-white' : 'hover:bg-cyan-900/20 text-gray-400'}`}
                    >
                        <Telescope size={18} />
                        <span>Space Monitor</span>
                    </button>

                    <button
                        onClick={() => setCurrentView('project')}
                        className={`w-full flex items-center gap-3 p-3 rounded transition-all ${currentView === 'project' ? 'bg-cyan-900/50 text-white' : 'hover:bg-cyan-900/20 text-gray-400'}`}
                    >
                        <Briefcase size={18} />
                        <span>Gestion Projet</span>
                    </button>
                </div>

                {/* Sessions List */}
                <div className="flex-1 overflow-y-auto p-4">
                    <div className="flex justify-between items-center mb-4">
                        <h2 className="text-xs uppercase tracking-widest text-gray-500">Missions</h2>
                        <button onClick={createNewSession} className="text-xs text-cyan-400 hover:text-cyan-300 border border-cyan-900 px-2 py-1 rounded hover:bg-cyan-900/30 transition-all">
                            + NEW
                        </button>
                    </div>
                    <div className="space-y-2">
                        {sessions.map(session => (
                            <div
                                key={session.id}
                                onClick={() => loadSession(session.id)}
                                className={`group p-3 rounded cursor-pointer border transition-all ${currentSessionId === session.id ? 'bg-cyan-900/30 border-cyan-500 text-white' : 'bg-gray-900 border-gray-800 text-gray-400 hover:border-cyan-700'}`}
                            >
                                <div className="font-bold text-sm truncate">{session.title}</div>
                                <div className="text-xs text-gray-600 mt-1 flex justify-between items-center">
                                    <span>{new Date(session.lastModified).toLocaleDateString()}</span>
                                    <button
                                        onClick={(e) => deleteSession(session.id, e)}
                                        className="opacity-0 group-hover:opacity-100 text-red-500 hover:text-red-400"
                                    >
                                        ×
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Footer Controls */}
                <div className="p-4 border-t border-cyan-900 bg-black/50">
                    {/* GoogleAuthPanel removed as per user request */}
                    <div className="mt-4 flex items-center justify-between text-xs text-gray-500">
                        <span>v1.2.0</span>
                        <div className="flex gap-2">
                            <button
                                onClick={() => setCurrentView('settings')}
                                className={`hover:text-cyan-400 ${currentView === 'settings' ? 'text-cyan-400' : ''}`}
                            >
                                <Settings size={14} />
                            </button>
                            <button className="hover:text-red-400"><LogOut size={14} /></button>
                        </div>
                    </div>
                </div>
            </div>

            {/* MAIN CONTENT AREA */}
            <div className="flex-1 flex flex-col relative bg-[url('/grid.png')]">
                {/* Header Toolbar */}
                <div className="h-16 border-b border-cyan-900 bg-black/80 backdrop-blur flex items-center justify-between px-6 z-40">
                    <div className="flex items-center gap-4">
                        <ModelSelector
                            currentProvider={selectedProvider}
                            currentModel={selectedModel}
                            onSelectModel={(model, provider) => {
                                setSelectedModel(model);
                                setSelectedProvider(provider);
                            }}
                        />
                        {/* Moved Pattern Selector Here */}
                        <div className="flex items-center gap-2 border-l border-cyan-900 pl-4">
                            <select
                                value={selectedPattern}
                                onChange={(e) => setSelectedPattern(e.target.value)}
                                className="bg-black border border-cyan-700 text-cyan-400 rounded px-3 py-1 text-sm focus:outline-none focus:border-cyan-400"
                            >
                                <option value="">Mode: Standard</option>
                                {patterns.map(p => (
                                    <option key={p} value={p}>{p}</option>
                                ))}
                            </select>
                            {selectedPattern && (
                                <button
                                    onClick={() => openPatternModal(selectedPattern)}
                                    className="text-cyan-600 hover:text-cyan-400"
                                    title="Voir le pattern"
                                >
                                    👁️
                                </button>
                            )}
                        </div>
                    </div>
                    <div className="flex items-center gap-4">
                        <button
                            onClick={() => setIsMuted(!isMuted)}
                            className={`p-2 rounded-full border ${isMuted ? 'border-red-500 text-red-500' : 'border-cyan-500 text-cyan-500'} hover:bg-gray-800 transition-all`}
                        >
                            {isMuted ? '🔇' : '🔊'}
                        </button>
                    </div>
                </div>

                {/* CONDITIONAL RENDER: CHAT or DASHBOARD or SPACE */}
                {currentView === 'dashboard' ? (
                    <Dashboard />
                ) : currentView === 'space' ? (
                    <SpaceDashboard />
                ) : currentView === 'project' ? (
                    <ProjectDashboard />
                ) : currentView === 'settings' ? (
                    <SettingsPage />
                ) : (
                    <>
                        {/* Chat History */}
                        <div className="flex-1 overflow-y-auto p-6 space-y-6 scrollbar-thin scrollbar-thumb-cyan-900 scrollbar-track-black">
                            {messages.map((msg) => (
                                <div key={msg.id} className={`flex ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
                                    <div className={`max-w-[80%] p-4 rounded-lg border backdrop-blur-sm ${msg.sender === 'user'
                                        ? 'bg-cyan-900/20 border-cyan-500/50 text-cyan-100 rounded-br-none'
                                        : 'bg-black/60 border-gray-700 text-gray-300 rounded-bl-none shadow-[0_0_15px_rgba(0,255,255,0.1)]'
                                        }`}>
                                        <div className="flex items-center gap-2 mb-2 border-b border-white/10 pb-1 justify-between">
                                            <div className="flex items-center gap-2">
                                                <span className={`text-xs font-bold uppercase tracking-wider ${msg.sender === 'user' ? 'text-cyan-400' : 'text-purple-400'}`}>
                                                    {msg.sender === 'user' ? 'OPERATOR' : APP_CONFIG.name}
                                                </span>
                                                <span className="text-[10px] text-gray-500">{new Date().toLocaleTimeString()}</span>
                                            </div>
                                            <button
                                                onClick={(e) => handleDeleteMessage(msg.id, e)}
                                                className="text-gray-600 hover:text-red-500 transition-colors"
                                                title="Supprimer le message"
                                            >
                                                <LogOut size={12} className="rotate-180" /> {/* Using LogOut as trash icon for now */}
                                            </button>
                                        </div>
                                        <div className="whitespace-pre-wrap leading-relaxed text-sm">
                                            {msg.image && (
                                                <div className="mb-2">
                                                    <img src={msg.image} alt="Captured" className="max-w-xs rounded border border-cyan-500/30" />
                                                </div>
                                            )}
                                            {msg.text}
                                        </div>
                                        {msg.sender === 'agent' && (
                                            <div className="mt-2 flex justify-end">
                                                <button
                                                    onClick={() => handleFeedbackOpen(msg.id)}
                                                    className="text-gray-600 hover:text-red-400 text-xs flex items-center gap-1 transition-colors"
                                                    title="Signaler une erreur"
                                                >
                                                    👎 Corriger
                                                </button>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            ))}
                            <div ref={messagesEndRef} />
                        </div>

                        {/* Input Area */}
                        <div className="p-6 bg-black/80 border-t border-cyan-900 backdrop-blur">
                            <div className="relative max-w-4xl mx-auto">
                                <input
                                    type="text"
                                    value={input}
                                    onChange={(e) => setInput(e.target.value)}
                                    onKeyDown={handleKeyDown}
                                    placeholder="Entrez votre commande..."
                                    className="w-full bg-gray-900/50 border border-cyan-700 rounded-lg py-4 pl-4 pr-12 text-cyan-100 placeholder-cyan-800 focus:outline-none focus:border-cyan-400 focus:shadow-[0_0_20px_rgba(8,145,178,0.3)] transition-all"
                                />
                                <button
                                    onClick={toggleListening}
                                    className={`absolute right-3 top-1/2 -translate-y-1/2 p-2 rounded-full transition-all ${isListening ? 'bg-red-500/20 text-red-500 animate-pulse' : 'text-cyan-600 hover:text-cyan-400'}`}
                                >
                                    {isListening ? '🛑' : '🎤'}
                                </button>
                                <button
                                    onClick={() => setShowWebcam(true)}
                                    className={`absolute right-12 top-1/2 -translate-y-1/2 p-2 rounded-full transition-all ${capturedImage ? 'text-green-500' : 'text-cyan-600 hover:text-cyan-400'}`}
                                    title="Activer la Vision"
                                >
                                    📷
                                </button>
                            </div>
                            {capturedImage && (
                                <div className="mt-2 flex items-center gap-2">
                                    <span className="text-xs text-green-500 font-mono">Image capturée</span>
                                    <button onClick={() => setCapturedImage(null)} className="text-red-500 text-xs hover:underline">Supprimer</button>
                                </div>
                            )}
                            <div className="text-center mt-2 text-[10px] text-gray-600 uppercase tracking-widest">
                                Système Sécurisé • Chiffrage End-to-End • {APP_CONFIG.version}
                            </div>
                        </div>
                    </>
                )}
            </div>

            {/* Modals */}
            <FeedbackModal
                isOpen={feedbackModalOpen}
                onClose={() => setFeedbackModalOpen(false)}
                onSubmit={submitFeedback}
                correctionText={correctionText}
                setCorrectionText={setCorrectionText}
            />

            <PatternModal
                isOpen={patternModalOpen}
                onClose={() => setPatternModalOpen(false)}
                content={viewingPatternContent}
            />

            {
                showWebcam && (
                    <WebcamInput
                        onCapture={(img) => {
                            setCapturedImage(img);
                            setShowWebcam(false);
                        }}
                        onClose={() => setShowWebcam(false)}
                    />
                )
            }
        </div >
    );
};

export default ChatInterface;
