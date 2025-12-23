import React, { useState, useEffect, useRef } from 'react';
import { API_URL } from '../config';
import './AgentTeamChat.css';

/**
 * Agent Team Chat
 * 
 * A collaborative chat where the 3 AI agents can discuss together
 * and develop "fraternal chemistry" by working as a team with the user
 */
const AgentTeamChat = () => {
    const [messages, setMessages] = useState([]);
    const [inputMessage, setInputMessage] = useState('');
    const [isTyping, setIsTyping] = useState(null);
    const [activeAgents] = useState([
        { id: 'sadiq', name: 'Sadiq', icon: '🎭', color: '#9b59b6', specialty: 'Social Engineering', online: true },
        { id: 'dolphin', name: 'Dolphin', icon: '🐬', color: '#3498db', specialty: 'Pentesting', online: true },
        { id: 'nidum', name: 'Nidum', icon: '⚡', color: '#f39c12', specialty: 'Exploit Dev', online: true }
    ]);
    const [selectedAgents, setSelectedAgents] = useState(['sadiq', 'dolphin', 'nidum']);
    const [chatMode, setChatMode] = useState('team'); // 'team' or 'individual'
    const [loopStatus, setLoopStatus] = useState({ isRunning: false });
    const chatEndRef = useRef(null);
    const inputRef = useRef(null);

    // Model name mapping
    const modelMap = {
        'sadiq': 'sadiq-bd/llama3.2-3b-uncensored',
        'dolphin': 'uandinotai/dolphin-uncensored',
        'nidum': 'nidumai/nidum-llama-3.2-3b-uncensored'
    };

    // Scroll to bottom
    const scrollToBottom = () => {
        chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    };

    useEffect(() => {
        scrollToBottom();
    }, [messages]);

    // Add welcome message on mount
    useEffect(() => {
        setMessages([
            {
                id: 'welcome',
                type: 'system',
                content: '🎉 Bienvenue dans le Team Chat! Les 3 agents AI sont prêts à collaborer avec toi.',
                timestamp: new Date()
            },
            {
                id: 'intro-sadiq',
                agent: 'sadiq',
                content: "Salut Boss! 🎭 Je suis Sadiq, ton expert en Social Engineering et OSINT. Je suis là pour t'aider avec les aspects humains de la cybersécurité.",
                timestamp: new Date()
            },
            {
                id: 'intro-dolphin',
                agent: 'dolphin',
                content: "Hey! 🐬 Dolphin ici. Je gère le pentesting et l'exploitation kernel. Ensemble on va faire une équipe solide!",
                timestamp: new Date()
            },
            {
                id: 'intro-nidum',
                agent: 'nidum',
                content: "⚡ Nidum au rapport. Ma spécialité c'est le développement d'exploits et la précision. Prêt à bosser en équipe!",
                timestamp: new Date()
            }
        ]);
    }, []);
    
    // Fetch learning loop status
    const fetchLoopStatus = async () => {
        try {
            const response = await fetch(`${API_URL}/api/evolution/learning-loop/status`);
            if (response.ok) {
                const data = await response.json();
                setLoopStatus(data);
            }
        } catch (err) {
            console.error('Failed to fetch loop status:', err);
        }
    };
    
    // Fetch loop status on mount
    useEffect(() => {
        fetchLoopStatus();
        const loopInterval = setInterval(fetchLoopStatus, 10000);
        return () => clearInterval(loopInterval);
    }, []);
    
    // Toggle learning loop
    const toggleLearningLoop = async () => {
        try {
            const endpoint = loopStatus.isRunning ? 'stop' : 'start';
            const response = await fetch(`${API_URL}/api/evolution/learning-loop/${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ intervalMinutes: 3 })
            });
            
            if (response.ok) {
                fetchLoopStatus();
                setMessages(prev => [...prev, {
                    id: `system-${Date.now()}`,
                    type: 'system',
                    content: loopStatus.isRunning 
                        ? '🛑 Boucle d\'apprentissage arrêtée' 
                        : '🚀 Boucle d\'apprentissage démarrée (interval: 3min)',
                    timestamp: new Date()
                }]);
            }
        } catch (err) {
            console.error('Failed to toggle loop:', err);
        }
    };

    // Send message
    const sendMessage = async () => {
        if (!inputMessage.trim()) return;

        const userMessage = {
            id: `user-${Date.now()}`,
            type: 'user',
            content: inputMessage,
            timestamp: new Date()
        };

        setMessages(prev => [...prev, userMessage]);
        setInputMessage('');
        inputRef.current?.focus();

        // Get responses from selected agents
        if (chatMode === 'team') {
            // Team mode: agents respond one by one and can react to each other
            await getTeamResponse(inputMessage);
        } else {
            // Individual mode: only first selected agent responds
            await getIndividualResponse(inputMessage, selectedAgents[0]);
        }
    };

    // Get team response (all agents collaborate)
    const getTeamResponse = async (prompt) => {
        const conversationContext = messages.slice(-10).map(m => 
            m.type === 'user' ? `User: ${m.content}` : 
            m.agent ? `${m.agent}: ${m.content}` : ''
        ).filter(Boolean).join('\n');

        for (const agentId of selectedAgents) {
            setIsTyping(agentId);
            
            try {
                const agent = activeAgents.find(a => a.id === agentId);
                const otherAgents = selectedAgents.filter(a => a !== agentId);
                
                const systemPrompt = `Tu es ${agent.name} (${agent.icon}), un expert en ${agent.specialty}. 
Tu fais partie d'une équipe de 3 agents AI qui travaillent ensemble.
Tes coéquipiers sont: ${otherAgents.map(a => activeAgents.find(ag => ag.id === a)?.name).join(', ')}.

Contexte de la conversation:
${conversationContext}

Règles:
1. Réponds de manière concise mais utile (2-4 phrases max)
2. Tu peux mentionner tes coéquipiers et leur expertise
3. Développe une chimie fraternelle avec l'équipe
4. Sois amical, professionnel et collaboratif
5. N'hésite pas à demander l'avis de tes coéquipiers
6. Utilise ton emoji ${agent.icon} pour te démarquer

La question de l'utilisateur: ${prompt}`;

                const response = await fetch(`${API_URL}/api/generate`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        prompt: prompt,
                        provider: 'ollama',
                        model: modelMap[agentId],
                        systemPrompt: systemPrompt
                    })
                });

                if (response.ok) {
                    const data = await response.json();
                    const agentMessage = {
                        id: `${agentId}-${Date.now()}`,
                        agent: agentId,
                        content: data.response || data.text || "Je réfléchis...",
                        timestamp: new Date()
                    };
                    setMessages(prev => [...prev, agentMessage]);
                }
            } catch (error) {
                console.error(`Error getting response from ${agentId}:`, error);
                setMessages(prev => [...prev, {
                    id: `error-${agentId}-${Date.now()}`,
                    agent: agentId,
                    content: "⚠️ Je suis momentanément indisponible, mes coéquipiers peuvent prendre le relais!",
                    timestamp: new Date(),
                    isError: true
                }]);
            }
            
            setIsTyping(null);
            // Small delay between agents
            await new Promise(r => setTimeout(r, 500));
        }
    };

    // Get individual response
    const getIndividualResponse = async (prompt, agentId) => {
        setIsTyping(agentId);
        
        try {
            const agent = activeAgents.find(a => a.id === agentId);
            
            const response = await fetch(`${API_URL}/api/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    prompt: prompt,
                    provider: 'ollama',
                    model: modelMap[agentId],
                    systemPrompt: `Tu es ${agent.name}, un expert en ${agent.specialty}. Réponds de manière utile et professionnelle.`
                })
            });

            if (response.ok) {
                const data = await response.json();
                setMessages(prev => [...prev, {
                    id: `${agentId}-${Date.now()}`,
                    agent: agentId,
                    content: data.response || data.text,
                    timestamp: new Date()
                }]);
            }
        } catch (error) {
            console.error(`Error getting response from ${agentId}:`, error);
        }
        
        setIsTyping(null);
    };

    // Toggle agent selection
    const toggleAgent = (agentId) => {
        if (selectedAgents.includes(agentId)) {
            if (selectedAgents.length > 1) {
                setSelectedAgents(prev => prev.filter(a => a !== agentId));
            }
        } else {
            setSelectedAgents(prev => [...prev, agentId]);
        }
    };

    // Trigger team discussion
    const triggerTeamDiscussion = async (topic) => {
        setMessages(prev => [...prev, {
            id: `system-${Date.now()}`,
            type: 'system',
            content: `💭 Discussion d'équipe initiée sur: "${topic}"`,
            timestamp: new Date()
        }]);

        await getTeamResponse(`Discutons ensemble de: ${topic}. Chacun peut donner son point de vue.`);
    };

    // Handle key press
    const handleKeyPress = (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    };

    // Render message
    const MessageBubble = ({ message }) => {
        if (message.type === 'system') {
            return (
                <div className="message system-message">
                    <span>{message.content}</span>
                </div>
            );
        }

        if (message.type === 'user') {
            return (
                <div className="message user-message">
                    <div className="message-content">
                        <p>{message.content}</p>
                    </div>
                    <div className="message-avatar user-avatar">👤</div>
                </div>
            );
        }

        const agent = activeAgents.find(a => a.id === message.agent);
        
        return (
            <div className={`message agent-message ${message.isError ? 'error' : ''}`}>
                <div 
                    className="message-avatar agent-avatar"
                    style={{ background: agent?.color }}
                >
                    {agent?.icon}
                </div>
                <div className="message-content" style={{ borderColor: agent?.color }}>
                    <div className="message-header">
                        <span className="agent-name" style={{ color: agent?.color }}>{agent?.name}</span>
                        <span className="message-time">
                            {new Date(message.timestamp).toLocaleTimeString()}
                        </span>
                    </div>
                    <p>{message.content}</p>
                </div>
            </div>
        );
    };

    return (
        <div className="agent-team-chat">
            {/* Header */}
            <header className="chat-header">
                <div className="chat-title">
                    <h2>🤝 Team Chat</h2>
                    <span className="chat-subtitle">Collaboration fraternelle des agents AI</span>
                </div>
                
                <div className="chat-mode-toggle">
                    <button 
                        className={chatMode === 'team' ? 'active' : ''}
                        onClick={() => setChatMode('team')}
                    >
                        👥 Équipe
                    </button>
                    <button 
                        className={chatMode === 'individual' ? 'active' : ''}
                        onClick={() => setChatMode('individual')}
                    >
                        👤 Individuel
                    </button>
                </div>
            </header>

            {/* Agent Status Bar */}
            <div className="agents-status-bar">
                {activeAgents.map(agent => (
                    <div 
                        key={agent.id}
                        className={`agent-status ${selectedAgents.includes(agent.id) ? 'selected' : ''} ${isTyping === agent.id ? 'typing' : ''}`}
                        onClick={() => toggleAgent(agent.id)}
                        style={{ borderColor: selectedAgents.includes(agent.id) ? agent.color : 'transparent' }}
                    >
                        <span className="agent-icon">{agent.icon}</span>
                        <div className="agent-details">
                            <span className="agent-name">{agent.name}</span>
                            <span className="agent-specialty">{agent.specialty}</span>
                        </div>
                        {agent.online && <span className="online-dot" style={{ background: agent.color }} />}
                        {isTyping === agent.id && <span className="typing-indicator">typing...</span>}
                    </div>
                ))}
            </div>

            {/* Quick Actions */}
            <div className="quick-actions">
                <button 
                    onClick={toggleLearningLoop}
                    className={loopStatus.isRunning ? 'active' : ''}
                    style={{ background: loopStatus.isRunning ? 'linear-gradient(135deg, #e74c3c, #c0392b)' : '' }}
                >
                    {loopStatus.isRunning ? '🛑 Stop Auto' : '🔄 Auto Loop'}
                </button>
                <button onClick={() => triggerTeamDiscussion("notre stratégie pour aujourd'hui")}>
                    💡 Stratégie
                </button>
                <button onClick={() => triggerTeamDiscussion("partager nos forces et faiblesses")}>
                    🤝 Forces/Faiblesses
                </button>
                <button onClick={() => triggerTeamDiscussion("analyser une cible potentielle")}>
                    🎯 Analyse
                </button>
                <button onClick={() => triggerTeamDiscussion("comment s'améliorer ensemble")}>
                    📈 Amélioration
                </button>
            </div>

            {/* Messages */}
            <div className="chat-messages">
                {messages.map(message => (
                    <MessageBubble key={message.id} message={message} />
                ))}
                <div ref={chatEndRef} />
            </div>

            {/* Input */}
            <div className="chat-input-container">
                <textarea
                    ref={inputRef}
                    value={inputMessage}
                    onChange={(e) => setInputMessage(e.target.value)}
                    onKeyPress={handleKeyPress}
                    placeholder="Discute avec l'équipe..."
                    rows={1}
                />
                <button 
                    className="send-btn"
                    onClick={sendMessage}
                    disabled={!inputMessage.trim() || isTyping}
                >
                    {isTyping ? '⏳' : '📤'}
                </button>
            </div>
        </div>
    );
};

export default AgentTeamChat;
