import React, { useState, useRef, useEffect } from 'react';
import { 
    Send, Loader, Bot, User, MapPin, Globe, 
    Minimize2, Maximize2, Trash2, Copy, Wifi, AlertCircle
} from 'lucide-react';
import { API_URL } from '../config';

/**
 * OSINT Agent Chat Component
 * A dedicated chat interface for OSINT investigations with integrated tools
 */
const OSINTAgentChat = ({ 
    onLocationFound,
    initialMessage = null,
    compact = false 
}) => {
    const [messages, setMessages] = useState([
        {
            role: 'assistant',
            content: `🔍 **OSINT Agent Ready**

Je suis votre agent d'investigation OSINT. Je peux vous aider à :
- 🌐 Rechercher des informations sur des IPs et domaines
- 📍 Géolocaliser des adresses IP
- 🔎 Effectuer des vérifications WHOIS
- 👤 Analyser des profils et traces numériques

**Actions rapides disponibles ci-dessus ↑**

Comment puis-je vous aider ?`,
            timestamp: new Date().toISOString(),
            tools: []
        }
    ]);
    const [input, setInput] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [isExpanded, setIsExpanded] = useState(!compact);
    const [provider, setProvider] = useState('ollama'); // Default to ollama
    const [model, setModel] = useState('llama3.1:8b-instruct-q4_K_M');
    const messagesEndRef = useRef(null);
    const inputRef = useRef(null);

    // Scroll to bottom when messages change
    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    // Process initial message if provided
    useEffect(() => {
        if (initialMessage) {
            setInput(initialMessage);
        }
    }, [initialMessage]);

    // Get user's public IP
    const getMyIP = async () => {
        try {
            setIsLoading(true);
            
            // Get public IP from external service
            const ipRes = await fetch('https://api.ipify.org?format=json');
            const ipData = await ipRes.json();
            const myIP = ipData.ip;

            // Add user message
            setMessages(prev => [...prev, {
                role: 'user',
                content: `Quelle est mon adresse IP publique ?`,
                timestamp: new Date().toISOString()
            }]);

            // Lookup the IP
            const lookupRes = await fetch(`${API_URL}/api/ip2location/lookup?ip=${myIP}`);
            const lookupData = await lookupRes.json();

            let responseContent = `🌐 **Votre IP Publique:** \`${myIP}\`\n\n`;
            
            if (lookupData.success && lookupData.data) {
                const d = lookupData.data;
                responseContent += `📍 **Localisation:**\n`;
                responseContent += `- Ville: ${d.city || 'N/A'}\n`;
                responseContent += `- Région: ${d.region || 'N/A'}\n`;
                responseContent += `- Pays: ${d.country?.name || 'N/A'} ${d.country?.flag || ''}\n`;
                responseContent += `- Coordonnées: ${d.coordinates?.latitude}, ${d.coordinates?.longitude}\n\n`;
                responseContent += `🌐 **Réseau:**\n`;
                responseContent += `- FAI: ${d.network?.as_name || 'N/A'}\n`;
                responseContent += `- ASN: ${d.network?.asn || 'N/A'}\n`;
                responseContent += `- Proxy/VPN: ${d.security?.is_proxy ? '⚠️ Oui' : '✅ Non'}\n`;

                if (d.coordinates && onLocationFound) {
                    onLocationFound({
                        lat: d.coordinates.latitude,
                        lng: d.coordinates.longitude,
                        label: `Mon IP - ${d.city}, ${d.country?.name}`
                    });
                }
            } else {
                responseContent += `❌ Impossible de géolocaliser cette IP.`;
            }

            setMessages(prev => [...prev, {
                role: 'assistant',
                content: responseContent,
                timestamp: new Date().toISOString(),
                tools: [{ type: 'ip_lookup', target: myIP, result: lookupData.data }]
            }]);

        } catch (error) {
            setMessages(prev => [...prev, {
                role: 'assistant',
                content: `❌ Erreur lors de la récupération de votre IP: ${error.message}`,
                timestamp: new Date().toISOString(),
                isError: true
            }]);
        } finally {
            setIsLoading(false);
        }
    };

    // Execute WHOIS lookup
    const doWHOIS = async (domain) => {
        try {
            setIsLoading(true);
            
            // Extract domain from input or email
            let targetDomain = domain;
            if (domain.includes('@')) {
                targetDomain = domain.split('@')[1];
            }

            setMessages(prev => [...prev, {
                role: 'user',
                content: `Analyse WHOIS pour: ${targetDomain}`,
                timestamp: new Date().toISOString()
            }]);

            const res = await fetch(`${API_URL}/api/whois/lookup?domain=${targetDomain}`);
            const data = await res.json();

            let responseContent = `🔍 **WHOIS pour:** \`${targetDomain}\`\n\n`;
            
            if (data.success && data.data) {
                const d = data.data;
                responseContent += `📋 **Informations du domaine:**\n`;
                responseContent += `- Registrar: ${d.registrar?.name || 'N/A'}\n`;
                responseContent += `- Créé le: ${d.dates?.created ? new Date(d.dates.created).toLocaleDateString('fr-FR') : 'N/A'}\n`;
                responseContent += `- Expire le: ${d.dates?.expires ? new Date(d.dates.expires).toLocaleDateString('fr-FR') : 'N/A'}\n`;
                responseContent += `- Mis à jour: ${d.dates?.updated ? new Date(d.dates.updated).toLocaleDateString('fr-FR') : 'N/A'}\n\n`;
                
                if (d.nameservers?.length > 0) {
                    responseContent += `🌐 **Serveurs DNS:**\n`;
                    d.nameservers.slice(0, 3).forEach(ns => {
                        responseContent += `- ${ns}\n`;
                    });
                }
            } else {
                responseContent += `❌ Impossible de récupérer les informations WHOIS.`;
            }

            setMessages(prev => [...prev, {
                role: 'assistant',
                content: responseContent,
                timestamp: new Date().toISOString(),
                tools: [{ type: 'whois_lookup', target: targetDomain, result: data.data }]
            }]);

        } catch (error) {
            setMessages(prev => [...prev, {
                role: 'assistant',
                content: `❌ Erreur WHOIS: ${error.message}`,
                timestamp: new Date().toISOString(),
                isError: true
            }]);
        } finally {
            setIsLoading(false);
        }
    };

    // IP Geolocation
    const geolocateIP = async (ip) => {
        try {
            setIsLoading(true);
            
            setMessages(prev => [...prev, {
                role: 'user',
                content: `Géolocalise l'IP: ${ip}`,
                timestamp: new Date().toISOString()
            }]);

            const res = await fetch(`${API_URL}/api/ip2location/lookup?ip=${ip}`);
            const data = await res.json();

            let responseContent = `📍 **Géolocalisation de:** \`${ip}\`\n\n`;
            
            if (data.success && data.data) {
                const d = data.data;
                responseContent += `🗺️ **Localisation:**\n`;
                responseContent += `- Ville: ${d.city || 'N/A'}\n`;
                responseContent += `- Région: ${d.region || 'N/A'}\n`;
                responseContent += `- Pays: ${d.country?.name || 'N/A'} ${d.country?.flag || ''}\n`;
                responseContent += `- Coordonnées: [${d.coordinates?.latitude}, ${d.coordinates?.longitude}](https://www.google.com/maps?q=${d.coordinates?.latitude},${d.coordinates?.longitude})\n\n`;
                responseContent += `🌐 **Réseau:**\n`;
                responseContent += `- FAI: ${d.network?.as_name || 'N/A'}\n`;
                responseContent += `- Timezone: ${d.timezone?.name || 'N/A'}\n`;

                if (d.coordinates && onLocationFound) {
                    onLocationFound({
                        lat: d.coordinates.latitude,
                        lng: d.coordinates.longitude,
                        label: `${ip} - ${d.city}, ${d.country?.name}`
                    });
                }
            } else {
                responseContent += `❌ Impossible de géolocaliser cette IP.`;
            }

            setMessages(prev => [...prev, {
                role: 'assistant',
                content: responseContent,
                timestamp: new Date().toISOString(),
                tools: [{ type: 'ip_lookup', target: ip, result: data.data }]
            }]);

        } catch (error) {
            setMessages(prev => [...prev, {
                role: 'assistant',
                content: `❌ Erreur géolocalisation: ${error.message}`,
                timestamp: new Date().toISOString(),
                isError: true
            }]);
        } finally {
            setIsLoading(false);
        }
    };

    // Send message to LLM
    const sendMessage = async () => {
        if (!input.trim() || isLoading) return;

        const userContent = input.trim();
        
        // Check for pattern matches first
        const ipMatch = userContent.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
        const domainMatch = userContent.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/i);

        // If it's a clear IP lookup request
        if (ipMatch && (userContent.toLowerCase().includes('ip') || userContent.toLowerCase().includes('géoloc') || userContent.toLowerCase().includes('localise'))) {
            setInput('');
            await geolocateIP(ipMatch[0]);
            return;
        }

        // If it's a WHOIS request
        if (domainMatch && (userContent.toLowerCase().includes('whois') || userContent.toLowerCase().includes('domaine'))) {
            setInput('');
            await doWHOIS(domainMatch[0]);
            return;
        }

        // Otherwise, send to LLM
        const userMessage = {
            role: 'user',
            content: userContent,
            timestamp: new Date().toISOString()
        };

        setMessages(prev => [...prev, userMessage]);
        setInput('');
        setIsLoading(true);

        try {
            const res = await fetch(`${API_URL}/chat`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': localStorage.getItem('th3_api_key') || localStorage.getItem('nexus33_token') || ''
                },
                body: JSON.stringify({
                    message: userContent,
                    provider: provider,
                    model: model,
                    systemPrompt: `Tu es un agent OSINT professionnel. Tu aides à effectuer des investigations légales et éthiques.

Pour les recherches d'IP, suggère à l'utilisateur d'utiliser le bouton "📍 Géoloc IP" ou de taper une IP directement.
Pour les recherches WHOIS, suggère d'utiliser le bouton "🔍 WHOIS".
Pour trouver l'IP de l'utilisateur, suggère le bouton "🌐 Mon IP".

Tu peux aussi conseiller sur les techniques OSINT légales:
- Recherche de pseudonymes sur les réseaux sociaux
- Analyse de métadonnées d'images
- Recherche de domaines liés
- Vérification d'emails

Reste toujours éthique et légal dans tes recommandations.`
                })
            });

            const data = await res.json();

            let content = data.response || data.message;
            
            // Handle error responses
            if (!content || data.error) {
                content = `⚠️ Le modèle LLM n'a pas pu répondre. Utilisez les boutons d'action rapide ci-dessus pour:
                
- **🌐 Mon IP** - Voir votre IP publique et sa localisation
- **🔍 WHOIS** - Analyser un domaine (entrez le domaine après)
- **📍 Géoloc IP** - Géolocaliser une IP (entrez l'IP après)`;
            }

            const assistantMessage = {
                role: 'assistant',
                content: content,
                timestamp: new Date().toISOString(),
                tools: []
            };

            setMessages(prev => [...prev, assistantMessage]);

        } catch (error) {
            console.error('[OSINT Chat] Error:', error);
            const errorMessage = {
                role: 'assistant',
                content: `⚠️ Erreur de connexion. Utilisez les boutons d'action rapide:
                
- **🌐 Mon IP** - Récupérer votre IP
- **🔍 WHOIS** - Entrez un domaine et cliquez WHOIS
- **📍 Géoloc IP** - Entrez une IP et cliquez Géoloc`,
                timestamp: new Date().toISOString(),
                isError: true
            };
            setMessages(prev => [...prev, errorMessage]);
        } finally {
            setIsLoading(false);
            inputRef.current?.focus();
        }
    };

    // Quick action handlers
    const handleQuickAction = (action) => {
        switch (action) {
            case 'myip':
                getMyIP();
                break;
            case 'whois':
                if (input.trim()) {
                    doWHOIS(input.trim());
                } else {
                    setInput('Entrez un domaine puis cliquez WHOIS: ');
                    inputRef.current?.focus();
                }
                break;
            case 'geoip':
                if (input.trim()) {
                    const ipMatch = input.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
                    if (ipMatch) {
                        geolocateIP(ipMatch[0]);
                    } else {
                        setMessages(prev => [...prev, {
                            role: 'assistant',
                            content: `⚠️ Veuillez entrer une adresse IP valide (ex: 8.8.8.8)`,
                            timestamp: new Date().toISOString(),
                            isError: true
                        }]);
                    }
                } else {
                    setInput('Entrez une IP: ');
                    inputRef.current?.focus();
                }
                break;
            case 'username':
                if (!input.trim()) {
                    setInput('Recherche le pseudo: ');
                    inputRef.current?.focus();
                } else {
                    setMessages(prev => [...prev, {
                        role: 'user',
                        content: `Recherche le pseudo: ${input}`,
                        timestamp: new Date().toISOString()
                    }, {
                        role: 'assistant',
                        content: `🔍 **Recherche de pseudo:** \`${input.replace('Recherche le pseudo: ', '')}\`

📱 **Sites à vérifier manuellement:**
- [Namechk](https://namechk.com) - Vérifier la disponibilité du pseudo
- [WhatsMyName](https://whatsmyname.app) - Recherche multi-plateforme
- [Sherlock](https://github.com/sherlock-project/sherlock) - Outil CLI avancé
- Google: "${input.replace('Recherche le pseudo: ', '')}" site:twitter.com OR site:instagram.com

⚠️ Note: La recherche automatique de pseudos nécessite une intégration API supplémentaire.`,
                        timestamp: new Date().toISOString()
                    }]);
                    setInput('');
                }
                break;
            default:
                break;
        }
    };

    // Clear chat
    const clearChat = () => {
        setMessages([messages[0]]);
    };

    // Copy message
    const copyMessage = (content) => {
        navigator.clipboard.writeText(content);
    };

    return (
        <div className={`flex flex-col bg-gray-900/90 border border-cyan-800/50 rounded-lg overflow-hidden backdrop-blur ${isExpanded ? 'h-full' : 'h-12'}`}>
            {/* Header */}
            <div 
                className="flex items-center justify-between px-3 py-2 bg-gradient-to-r from-cyan-900/50 to-purple-900/30 border-b border-cyan-800/50 cursor-pointer"
                onClick={() => setIsExpanded(!isExpanded)}
            >
                <div className="flex items-center gap-2">
                    <Bot size={18} className="text-cyan-400" />
                    <span className="font-bold text-cyan-300 text-sm">OSINT AGENT</span>
                    {isLoading && <Loader size={14} className="animate-spin text-cyan-400" />}
                </div>
                <div className="flex items-center gap-2">
                    {isExpanded && (
                        <button
                            onClick={(e) => { e.stopPropagation(); clearChat(); }}
                            className="p-1 text-gray-400 hover:text-red-400 transition-colors"
                            title="Clear chat"
                        >
                            <Trash2 size={14} />
                        </button>
                    )}
                    {isExpanded ? <Minimize2 size={14} className="text-gray-400" /> : <Maximize2 size={14} className="text-gray-400" />}
                </div>
            </div>

            {isExpanded && (
                <>
                    {/* Quick Actions - FUNCTIONAL */}
                    <div className="flex gap-1 p-2 border-b border-gray-800 overflow-x-auto bg-gray-900/50">
                        <button
                            onClick={() => handleQuickAction('myip')}
                            disabled={isLoading}
                            className="px-2 py-1.5 bg-green-900/50 hover:bg-green-800 text-green-300 rounded text-xs whitespace-nowrap transition-colors flex items-center gap-1 disabled:opacity-50"
                        >
                            <Wifi size={12} /> Mon IP
                        </button>
                        <button
                            onClick={() => handleQuickAction('whois')}
                            disabled={isLoading}
                            className="px-2 py-1.5 bg-purple-900/50 hover:bg-purple-800 text-purple-300 rounded text-xs whitespace-nowrap transition-colors flex items-center gap-1 disabled:opacity-50"
                        >
                            <Globe size={12} /> WHOIS
                        </button>
                        <button
                            onClick={() => handleQuickAction('geoip')}
                            disabled={isLoading}
                            className="px-2 py-1.5 bg-blue-900/50 hover:bg-blue-800 text-blue-300 rounded text-xs whitespace-nowrap transition-colors flex items-center gap-1 disabled:opacity-50"
                        >
                            <MapPin size={12} /> Géoloc IP
                        </button>
                        <button
                            onClick={() => handleQuickAction('username')}
                            disabled={isLoading}
                            className="px-2 py-1.5 bg-orange-900/50 hover:bg-orange-800 text-orange-300 rounded text-xs whitespace-nowrap transition-colors flex items-center gap-1 disabled:opacity-50"
                        >
                            <User size={12} /> Username
                        </button>
                    </div>

                    {/* Messages */}
                    <div className="flex-1 overflow-y-auto p-3 space-y-3 min-h-0">
                        {messages.map((msg, idx) => (
                            <div 
                                key={idx} 
                                className={`flex gap-2 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}
                            >
                                <div className={`w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 ${
                                    msg.role === 'user' ? 'bg-cyan-900' : msg.isError ? 'bg-red-900' : 'bg-purple-900'
                                }`}>
                                    {msg.role === 'user' ? <User size={14} /> : msg.isError ? <AlertCircle size={14} /> : <Bot size={14} />}
                                </div>
                                <div className={`flex-1 max-w-[85%] ${msg.role === 'user' ? 'text-right' : ''}`}>
                                    <div className={`inline-block px-3 py-2 rounded-lg text-sm ${
                                        msg.role === 'user' 
                                            ? 'bg-cyan-900/50 text-cyan-100' 
                                            : msg.isError 
                                                ? 'bg-red-900/30 text-red-300 border border-red-700'
                                                : 'bg-gray-800/80 text-gray-200'
                                    }`}>
                                        <div className="whitespace-pre-wrap">{msg.content}</div>
                                        
                                        {/* Tool Results */}
                                        {msg.tools?.length > 0 && (
                                            <div className="mt-2 pt-2 border-t border-gray-700 space-y-2">
                                                {msg.tools.map((tool, tidx) => (
                                                    <div key={tidx} className="text-xs bg-black/40 rounded p-2">
                                                        <div className="flex items-center gap-1 text-cyan-400 mb-1">
                                                            {tool.type === 'ip_lookup' ? <MapPin size={12} /> : <Globe size={12} />}
                                                            <span className="font-mono">{tool.target}</span>
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                    <div className="text-xs text-gray-600 mt-1 flex items-center gap-2">
                                        {new Date(msg.timestamp).toLocaleTimeString()}
                                        {msg.role === 'assistant' && (
                                            <button 
                                                onClick={() => copyMessage(msg.content)}
                                                className="hover:text-gray-400"
                                            >
                                                <Copy size={10} />
                                            </button>
                                        )}
                                    </div>
                                </div>
                            </div>
                        ))}
                        {isLoading && (
                            <div className="flex gap-2">
                                <div className="w-7 h-7 rounded-full bg-purple-900 flex items-center justify-center">
                                    <Bot size={14} />
                                </div>
                                <div className="bg-gray-800/80 px-3 py-2 rounded-lg">
                                    <div className="flex gap-1">
                                        <div className="w-2 h-2 bg-cyan-400 rounded-full animate-bounce" style={{animationDelay: '0ms'}}></div>
                                        <div className="w-2 h-2 bg-cyan-400 rounded-full animate-bounce" style={{animationDelay: '150ms'}}></div>
                                        <div className="w-2 h-2 bg-cyan-400 rounded-full animate-bounce" style={{animationDelay: '300ms'}}></div>
                                    </div>
                                </div>
                            </div>
                        )}
                        <div ref={messagesEndRef} />
                    </div>

                    {/* Input */}
                    <div className="p-3 border-t border-gray-800">
                        <div className="flex gap-2">
                            <input
                                ref={inputRef}
                                type="text"
                                value={input}
                                onChange={(e) => setInput(e.target.value)}
                                onKeyDown={(e) => e.key === 'Enter' && sendMessage()}
                                placeholder="IP, domaine, ou question..."
                                className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-cyan-500 outline-none"
                                disabled={isLoading}
                            />
                            <button
                                onClick={sendMessage}
                                disabled={isLoading || !input.trim()}
                                className="px-4 py-2 bg-cyan-900/50 hover:bg-cyan-800 text-cyan-300 rounded border border-cyan-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                            >
                                <Send size={16} />
                            </button>
                        </div>
                    </div>
                </>
            )}
        </div>
    );
};

export default OSINTAgentChat;
