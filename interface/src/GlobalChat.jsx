import AgentMonitor from './components/AgentMonitor'; // Ensure import

const GlobalChat = () => {
    const [isOpen, setIsOpen] = useState(false);
    const [messages, setMessages] = useState([]);
    const [input, setInput] = useState('');
    const [isListening, setIsListening] = useState(false);
    const messagesEndRef = useRef(null);
    const [sessionId, setSessionId] = useState(null);

    // Terminal Monitor State
    const [terminalLogs, setTerminalLogs] = useState([]);
    const [isAnalysing, setIsAnalysing] = useState(false);

    // Initial Session ID
    useEffect(() => {
        // Generate a random session ID if not set
        if (!sessionId) {
            setSessionId(`chat-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`);
        }
    }, []);

    // Socket listeners
    useEffect(() => {
        if (!sessionId) return;

        const handleTerminalStream = (data) => {
            // Filter by chat ID to avoid cross-talk
            if (data.chatId && data.chatId === sessionId) {
                setTerminalLogs(prev => [...prev, { type: data.type, content: data.content }]);
            } else if (!data.chatId) {
                // Fallback for legacy events
                setTerminalLogs(prev => [...prev, { type: 'STDOUT', content: typeof data === 'string' ? data : JSON.stringify(data) }]);
            }
        };

        const handleAgentStatus = (data) => {
            // Optional: update status indicator
            if (data.status === 'Analysing...') setIsAnalysing(true);
            else setIsAnalysing(false);
        };

        // Assuming global socket instance is available via window or import
        // For this codebase, we might need to import socket service or use window.socket if exposed
        // Checking previous files, socket is likely managed in App.jsx or similar.
        // If not available, we assume standard socket.io client is used.
        // Let's use window.socket if available, as is common in these setups.
        if (window.socket) {
            window.socket.on('agent:terminal:stream', handleTerminalStream);
            window.socket.on('agent:status', handleAgentStatus);
        }

        return () => {
            if (window.socket) {
                window.socket.off('agent:terminal:stream', handleTerminalStream);
                window.socket.off('agent:status', handleAgentStatus);
            }
        };
    }, [sessionId]);

    const handleSend = async () => {
        if (!input.trim()) return;

        // Clear terminal on new command
        setTerminalLogs([]);

        const userMsg = { id: Date.now(), sender: 'user', text: input };
        setMessages(prev => [...prev, userMsg]);
        const msgToSend = input;
        setInput('');

        try {
            const response = await fetch(`${API_URL}/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: msgToSend,
                    sessionId: sessionId,
                    provider: 'hackergpt', // Force HackerGPT for terminal features
                    model: 'gemini-3-pro-preview'
                }),
            });
            const data = await response.json();

            // if (data.sessionId && !sessionId) setSessionId(data.sessionId); // Keep our generated ID

            const agentMsg = { id: Date.now() + 1, sender: 'agent', text: data.reply };
            setMessages(prev => [...prev, agentMsg]);
        } catch (error) {
            console.error("Global Chat Error:", error);
            setMessages(prev => [...prev, { id: Date.now(), sender: 'agent', text: "Erreur de connexion." }]);
        }
    };

    // ... rest of component ...

    if (!isOpen) {
        return (
            <button
                onClick={() => setIsOpen(true)}
                className="fixed bottom-6 right-6 z-50 bg-cyan-900/80 hover:bg-cyan-600 text-white p-4 rounded-full shadow-[0_0_20px_rgba(0,255,255,0.3)] border border-cyan-500 transition-all hover:scale-110"
                title="Ouvrir Comms Link"
            >
                <MessageSquare size={24} />
            </button>
        );
    }

    return (
        <div className="fixed bottom-6 right-6 z-50 w-[500px] h-[700px] bg-black/95 border border-cyan-500/50 rounded-lg shadow-2xl flex flex-col backdrop-blur-md overflow-hidden animate-in slide-in-from-bottom-10 duration-300">
            {/* Header */}
            <div className="bg-cyan-900/20 p-3 border-b border-cyan-900/50 flex justify-between items-center">
                <div className="flex items-center gap-2 text-cyan-400">
                    <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                    <span className="font-mono font-bold tracking-widest text-sm">SECURE COMMS v3.0</span>
                </div>
                <div className="flex gap-2">
                    <button onClick={() => setIsOpen(false)} className="text-cyan-600 hover:text-cyan-300">
                        <Minimize2 size={16} />
                    </button>
                </div>
            </div>

            {/* Terminal Monitor (Always visible if logs exist) */}
            {terminalLogs.length > 0 && (
                <div className="p-2 bg-black border-b border-cyan-900/30">
                    <AgentMonitor output={terminalLogs} analyzing={isAnalysing} />
                </div>
            )}

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin scrollbar-thumb-cyan-900">
                {messages.length === 0 && (
                    <div className="text-center text-gray-600 text-xs italic mt-10">
                        Canal sécurisé établi.<br />En attente d'ordres.<br />Provider: HackerGPT + HexStrike
                    </div>
                )}
                {messages.map((msg) => (
                    <div key={msg.id} className={`flex ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
                        <div className={`max-w-[85%] p-2 rounded text-sm ${msg.sender === 'user'
                            ? 'bg-cyan-900/30 text-cyan-100 border border-cyan-900'
                            : 'bg-gray-900/50 text-gray-300 border border-gray-800'
                            }`}>
                            {msg.text}
                        </div>
                    </div>
                ))}
                <div ref={messagesEndRef} />
            </div>

            {/* Input */}
            <div className="p-3 bg-black border-t border-cyan-900/50 flex gap-2">
                <button
                    onClick={toggleListening}
                    className={`p-2 rounded hover:bg-gray-800 ${isListening ? 'text-red-500 animate-pulse' : 'text-gray-500'}`}
                >
                    <Mic size={18} />
                </button>
                <input
                    type="text"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Message..."
                    className="flex-1 bg-gray-900/50 border border-gray-700 rounded px-3 text-sm text-cyan-100 focus:outline-none focus:border-cyan-500 font-mono"
                    autoFocus
                />
                <button
                    onClick={handleSend}
                    className="p-2 text-cyan-500 hover:text-cyan-300 hover:bg-cyan-900/20 rounded"
                >
                    <Send size={18} />
                </button>
            </div>
        </div>
    );
};

export default GlobalChat;
