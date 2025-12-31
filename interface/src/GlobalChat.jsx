import React, { useState, useEffect, useRef } from 'react';
import { MessageSquare, X, Send, Mic, Minimize2, Maximize2 } from 'lucide-react';
import { APP_CONFIG, API_URL } from './config';

const GlobalChat = () => {
    const [isOpen, setIsOpen] = useState(false);
    const [messages, setMessages] = useState([]);
    const [input, setInput] = useState('');
    const [isListening, setIsListening] = useState(false);
    const messagesEndRef = useRef(null);
    const [sessionId, setSessionId] = useState(null);

    // Auto-scroll
    useEffect(() => {
        if (isOpen) {
            messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
        }
    }, [messages, isOpen]);

    const handleSend = async () => {
        if (!input.trim()) return;

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
                    provider: 'local', // Default to local for speed in global chat
                    model: 'granite-flash:latest'
                }),
            });
            const data = await response.json();

            if (data.sessionId) setSessionId(data.sessionId);

            const agentMsg = { id: Date.now() + 1, sender: 'agent', text: data.reply };
            setMessages(prev => [...prev, agentMsg]);
        } catch (error) {
            console.error("Global Chat Error:", error);
            setMessages(prev => [...prev, { id: Date.now(), sender: 'agent', text: "Erreur de connexion." }]);
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
        <div className="fixed bottom-6 right-6 z-50 w-96 h-[600px] bg-black/95 border border-cyan-500/50 rounded-lg shadow-2xl flex flex-col backdrop-blur-md overflow-hidden animate-in slide-in-from-bottom-10 duration-300">
            {/* Header */}
            <div className="bg-cyan-900/20 p-3 border-b border-cyan-900/50 flex justify-between items-center">
                <div className="flex items-center gap-2 text-cyan-400">
                    <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                    <span className="font-mono font-bold tracking-widest text-sm">COMMS LINK</span>
                </div>
                <div className="flex gap-2">
                    <button onClick={() => setIsOpen(false)} className="text-cyan-600 hover:text-cyan-300">
                        <Minimize2 size={16} />
                    </button>
                </div>
            </div>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin scrollbar-thumb-cyan-900">
                {messages.length === 0 && (
                    <div className="text-center text-gray-600 text-xs italic mt-10">
                        Canal sécurisé établi.<br />En attente d'ordres.
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
                    className="flex-1 bg-gray-900/50 border border-gray-700 rounded px-3 text-sm text-cyan-100 focus:outline-none focus:border-cyan-500"
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
