import React, { useState, useEffect, useCallback } from 'react';
import {
    BookOpen, Plus, Search, Upload, FileText, Mic, Brain, 
    Sparkles, Folder, ChevronRight, MessageSquare, Play, 
    Download, Settings, RefreshCw, Trash2, Edit3, Save,
    ExternalLink, Podcast, Database, Tag, Clock, User,
    Lightbulb, PenTool, Layers, Zap, BookMarked, Globe
} from 'lucide-react';
import { API_URL } from './config';

const OpenNotebookPage = () => {
    // State
    const [loading, setLoading] = useState(false);
    const [searchQuery, setSearchQuery] = useState('');
    
    // Notebook LM Data
    const [domains, setDomains] = useState([]);
    const [selectedDomain, setSelectedDomain] = useState(null);
    const [domainContent, setDomainContent] = useState([]);
    const [lessons, setLessons] = useState([]);
    
    // Chat/Generation state
    const [chatMessages, setChatMessages] = useState([]);
    const [chatInput, setChatInput] = useState('');
    const [generatingPodcast, setGeneratingPodcast] = useState(false);
    const [generatingLesson, setGeneratingLesson] = useState(false);
    
    // New content form
    const [showAddForm, setShowAddForm] = useState(false);
    const [newContent, setNewContent] = useState({ title: '', content: '' });

    // Fetch domains from NotebookLM service
    const fetchDomains = useCallback(async () => {
        try {
            const res = await fetch(`${API_URL}/notebooklm/domains`);
            const data = await res.json();
            setDomains(data.domains || []);
        } catch (err) {
            console.error('Error fetching domains:', err);
            // Fallback domains
            setDomains([
                { name: 'osint', files: ['osint_fundamentals.json'], count: 5 },
                { name: 'network', files: [], count: 0 },
                { name: 'vuln', files: [], count: 0 },
                { name: 'coding', files: [], count: 0 },
                { name: 'custom', files: [], count: 0 }
            ]);
        }
    }, []);

    // Fetch domain content
    const fetchDomainContent = useCallback(async (domain) => {
        if (!domain) return;
        setLoading(true);
        try {
            const res = await fetch(`${API_URL}/notebooklm/${domain}`);
            const data = await res.json();
            setDomainContent(data.files || data.content || []);
        } catch (err) {
            console.error('Error fetching domain content:', err);
            setDomainContent([]);
        }
        setLoading(false);
    }, []);

    // Fetch cached lessons
    const fetchLessons = useCallback(async () => {
        try {
            const res = await fetch(`${API_URL}/notebooklm/lessons/${selectedDomain || 'all'}`);
            const data = await res.json();
            setLessons(data.lessons || data || []);
        } catch (err) {
            console.error('Error fetching lessons:', err);
        }
    }, [selectedDomain]);

    useEffect(() => {
        fetchDomains();
        fetchLessons();
    }, [fetchDomains, fetchLessons]);

    useEffect(() => {
        if (selectedDomain) {
            fetchDomainContent(selectedDomain);
        }
    }, [selectedDomain, fetchDomainContent]);

    // Generate Lesson
    const generateLesson = async () => {
        if (!selectedDomain) return;
        setGeneratingLesson(true);
        try {
            const res = await fetch(`${API_URL}/notebooklm/${selectedDomain}/generate-lesson`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ topic: null })
            });
            const data = await res.json();
            if (data.lesson) {
                setLessons(prev => [...prev, data.lesson]);
            }
        } catch (err) {
            console.error('Error generating lesson:', err);
        }
        setGeneratingLesson(false);
    };

    // Generate Podcast Summary
    const generatePodcast = async () => {
        if (!selectedDomain) return;
        setGeneratingPodcast(true);
        try {
            const res = await fetch(`${API_URL}/notebooklm/${selectedDomain}/podcast`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            const data = await res.json();
            if (data.podcast) {
                setChatMessages(prev => [...prev, {
                    role: 'assistant',
                    content: `🎙️ **Podcast Generated**\n\n${data.podcast.script || data.podcast}`
                }]);
            }
        } catch (err) {
            console.error('Error generating podcast:', err);
        }
        setGeneratingPodcast(false);
    };

    // Add new content
    const addContent = async () => {
        if (!selectedDomain || !newContent.title.trim() || !newContent.content.trim()) return;
        try {
            await fetch(`${API_URL}/notebooklm/${selectedDomain}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    title: newContent.title,
                    content: newContent.content
                })
            });
            setNewContent({ title: '', content: '' });
            setShowAddForm(false);
            fetchDomainContent(selectedDomain);
        } catch (err) {
            console.error('Error adding content:', err);
        }
    };

    // Chat with content
    const sendChatMessage = async () => {
        if (!chatInput.trim()) return;
        const userMessage = { role: 'user', content: chatInput };
        setChatMessages(prev => [...prev, userMessage]);
        setChatInput('');
        
        try {
            const res = await fetch(`${API_URL}/chat`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'x-api-key': localStorage.getItem('th3_api_key') || ''
                },
                body: JSON.stringify({
                    message: `[Context: NotebookLM domain "${selectedDomain}"]\n\n${chatInput}`,
                    provider: 'gemini'
                })
            });
            const data = await res.json();
            setChatMessages(prev => [...prev, {
                role: 'assistant',
                content: data.response || 'Unable to get response'
            }]);
        } catch {
            setChatMessages(prev => [...prev, {
                role: 'assistant',
                content: 'Error communicating with AI service'
            }]);
        }
    };

    // Domain icons mapping
    const getDomainIcon = (name) => {
        const icons = {
            osint: Globe,
            network: Zap,
            vuln: Lightbulb,
            coding: PenTool,
            custom: Layers
        };
        return icons[name] || BookMarked;
    };

    const getDomainColor = (name) => {
        const colors = {
            osint: 'cyan',
            network: 'purple',
            vuln: 'red',
            coding: 'green',
            custom: 'yellow'
        };
        return colors[name] || 'gray';
    };

    return (
        <div className="open-notebook-page h-full w-full flex flex-col bg-transparent text-white overflow-hidden">
            {/* HEADER */}
            <div className="flex justify-between items-center border-b border-gray-800 px-6 py-4 flex-shrink-0 bg-black/30 backdrop-blur-md">
                <div className="flex items-center gap-4">
                    <div className="flex items-center gap-3">
                        <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-orange-500 via-pink-500 to-purple-600 flex items-center justify-center shadow-lg shadow-purple-500/20">
                            <BookOpen size={24} className="text-white" />
                        </div>
                        <div>
                            <h1 className="text-2xl font-bold bg-gradient-to-r from-orange-400 via-pink-400 to-purple-400 bg-clip-text text-transparent">
                                Open Notebook
                            </h1>
                            <p className="text-gray-500 text-xs font-mono">Knowledge Management & AI Learning</p>
                        </div>
                    </div>
                </div>

                <div className="flex items-center gap-3">
                    {/* Open Notebook External */}
                    <a
                        href="http://localhost:8502"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 bg-purple-900/30 hover:bg-purple-800/50 text-purple-300 px-4 py-2 rounded-lg text-sm border border-purple-700 transition-all"
                    >
                        <ExternalLink size={16} />
                        Open Full App
                    </a>
                    
                    <button 
                        onClick={() => { fetchDomains(); fetchLessons(); }}
                        className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-gray-300 px-4 py-2 rounded-lg text-sm border border-gray-700 transition-all"
                    >
                        <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
                        SYNC
                    </button>
                </div>
            </div>

            {/* MAIN CONTENT */}
            <div className="flex-1 flex overflow-hidden min-h-0">
                
                {/* LEFT SIDEBAR - Domains */}
                <div className="w-64 bg-gray-900/50 border-r border-gray-800 flex flex-col flex-shrink-0">
                    <div className="p-4 border-b border-gray-800">
                        <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-3">Knowledge Domains</h3>
                        <div className="relative">
                            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                            <input
                                type="text"
                                placeholder="Search..."
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                className="w-full bg-black/50 border border-gray-700 rounded-lg pl-9 pr-3 py-2 text-sm text-white focus:border-purple-600 outline-none"
                            />
                        </div>
                    </div>
                    
                    <div className="flex-1 overflow-y-auto p-2 space-y-1">
                        {domains.map((domain, idx) => {
                            const DomainIcon = getDomainIcon(domain.name);
                            const color = getDomainColor(domain.name);
                            const isSelected = selectedDomain === domain.name;
                            
                            return (
                                <button
                                    key={domain.name || idx}
                                    onClick={() => setSelectedDomain(domain.name)}
                                    className={`w-full flex items-center gap-3 p-3 rounded-lg transition-all text-left ${
                                        isSelected
                                            ? `bg-${color}-900/50 border border-${color}-600`
                                            : 'hover:bg-gray-800/50 border border-transparent'
                                    }`}
                                    style={isSelected ? {
                                        backgroundColor: 'rgba(147, 51, 234, 0.2)',
                                        borderColor: 'rgb(147, 51, 234)'
                                    } : {}}
                                >
                                    <DomainIcon size={18} className={isSelected ? 'text-purple-400' : 'text-gray-500'} />
                                    <div className="flex-1 min-w-0">
                                        <p className="text-white font-medium capitalize text-sm">{domain.name}</p>
                                        <p className="text-gray-500 text-xs">{domain.files?.length || 0} sources</p>
                                    </div>
                                    <ChevronRight size={14} className="text-gray-600" />
                                </button>
                            );
                        })}
                    </div>

                    {/* Quick Actions */}
                    <div className="p-3 border-t border-gray-800 space-y-2">
                        <button className="w-full flex items-center gap-2 bg-gradient-to-r from-purple-900/50 to-pink-900/50 hover:from-purple-800/50 hover:to-pink-800/50 text-white px-4 py-2 rounded-lg text-sm border border-purple-700 transition-all">
                            <Plus size={16} />
                            New Domain
                        </button>
                    </div>
                </div>

                {/* CENTER - Content & Sources */}
                <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
                    {selectedDomain ? (
                        <>
                            {/* Domain Header */}
                            <div className="p-4 border-b border-gray-800 bg-black/20 flex items-center justify-between flex-shrink-0">
                                <div className="flex items-center gap-3">
                                    <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-purple-600 to-pink-600 flex items-center justify-center">
                                        {React.createElement(getDomainIcon(selectedDomain), { size: 20, className: 'text-white' })}
                                    </div>
                                    <div>
                                        <h2 className="text-xl font-bold text-white capitalize">{selectedDomain}</h2>
                                        <p className="text-gray-500 text-sm">{domainContent.length} sources loaded</p>
                                    </div>
                                </div>
                                <div className="flex gap-2">
                                    <button
                                        onClick={generateLesson}
                                        disabled={generatingLesson}
                                        className="flex items-center gap-2 bg-green-900/50 hover:bg-green-800 text-green-300 px-4 py-2 rounded-lg text-sm border border-green-700 transition-all disabled:opacity-50"
                                    >
                                        {generatingLesson ? (
                                            <RefreshCw size={16} className="animate-spin" />
                                        ) : (
                                            <Brain size={16} />
                                        )}
                                        Generate Lesson
                                    </button>
                                    <button
                                        onClick={generatePodcast}
                                        disabled={generatingPodcast}
                                        className="flex items-center gap-2 bg-orange-900/50 hover:bg-orange-800 text-orange-300 px-4 py-2 rounded-lg text-sm border border-orange-700 transition-all disabled:opacity-50"
                                    >
                                        {generatingPodcast ? (
                                            <RefreshCw size={16} className="animate-spin" />
                                        ) : (
                                            <Podcast size={16} />
                                        )}
                                        Podcast
                                    </button>
                                    <button
                                        onClick={() => setShowAddForm(true)}
                                        className="flex items-center gap-2 bg-purple-900/50 hover:bg-purple-800 text-purple-300 px-4 py-2 rounded-lg text-sm border border-purple-700 transition-all"
                                    >
                                        <Upload size={16} />
                                        Add Content
                                    </button>
                                </div>
                            </div>

                            {/* Content Grid */}
                            <div className="flex-1 flex gap-4 p-4 overflow-hidden min-h-0">
                                {/* Sources Panel */}
                                <div className="w-1/2 bg-gray-900/50 border border-gray-800 rounded-xl overflow-hidden flex flex-col">
                                    <div className="p-4 border-b border-gray-700 bg-gray-800/50 flex items-center gap-2">
                                        <Database size={16} className="text-purple-400" />
                                        <h3 className="font-bold text-white">Sources</h3>
                                    </div>
                                    <div className="flex-1 overflow-y-auto p-3 space-y-2">
                                        {loading ? (
                                            <div className="flex items-center justify-center h-full">
                                                <RefreshCw size={24} className="animate-spin text-purple-400" />
                                            </div>
                                        ) : domainContent.length === 0 ? (
                                            <div className="flex flex-col items-center justify-center h-full text-gray-500 p-8">
                                                <FileText size={48} className="mb-3 opacity-30" />
                                                <p className="text-center">No content yet</p>
                                                <p className="text-sm mt-1">Add sources to start learning</p>
                                            </div>
                                        ) : (
                                            domainContent.map((item, idx) => (
                                                <div
                                                    key={idx}
                                                    className="p-4 bg-black/30 rounded-lg border border-gray-700 hover:border-purple-600 transition-all"
                                                >
                                                    <div className="flex items-start justify-between">
                                                        <div className="flex items-start gap-3">
                                                            <FileText size={18} className="text-purple-400 mt-0.5" />
                                                            <div>
                                                                <h4 className="text-white font-medium">{item.title || `Source ${idx + 1}`}</h4>
                                                                <p className="text-gray-500 text-sm mt-1 line-clamp-2">
                                                                    {item.content 
                                                                        ? (typeof item.content === 'string' 
                                                                            ? item.content.substring(0, 150) + '...'
                                                                            : JSON.stringify(item.content).substring(0, 150) + '...')
                                                                        : 'No content preview available'
                                                                    }
                                                                </p>
                                                                {item.metadata && (
                                                                    <div className="flex gap-2 mt-2">
                                                                        {item.metadata.source && (
                                                                            <span className="text-xs bg-purple-900/30 text-purple-400 px-2 py-0.5 rounded">
                                                                                {item.metadata.source}
                                                                            </span>
                                                                        )}
                                                                    </div>
                                                                )}
                                                            </div>
                                                        </div>
                                                        <button className="text-gray-500 hover:text-red-400 p-1">
                                                            <Trash2 size={14} />
                                                        </button>
                                                    </div>
                                                </div>
                                            ))
                                        )}
                                    </div>
                                </div>

                                {/* Notes/Lessons Panel */}
                                <div className="w-1/2 bg-gray-900/50 border border-gray-800 rounded-xl overflow-hidden flex flex-col">
                                    <div className="p-4 border-b border-gray-700 bg-gray-800/50 flex items-center gap-2">
                                        <Sparkles size={16} className="text-yellow-400" />
                                        <h3 className="font-bold text-white">Generated Lessons</h3>
                                    </div>
                                    <div className="flex-1 overflow-y-auto p-3 space-y-2">
                                        {lessons.filter(l => l.domain === selectedDomain).length === 0 ? (
                                            <div className="flex flex-col items-center justify-center h-full text-gray-500 p-8">
                                                <Brain size={48} className="mb-3 opacity-30" />
                                                <p className="text-center">No lessons generated</p>
                                                <p className="text-sm mt-1">Click "Generate Lesson" to create</p>
                                            </div>
                                        ) : (
                                            lessons.filter(l => l.domain === selectedDomain).map((lesson, idx) => (
                                                <div
                                                    key={idx}
                                                    className="p-4 bg-black/30 rounded-lg border border-gray-700 hover:border-yellow-600 transition-all"
                                                >
                                                    <div className="flex items-start gap-3">
                                                        <Lightbulb size={18} className="text-yellow-400 mt-0.5" />
                                                        <div className="flex-1">
                                                            <h4 className="text-white font-medium">{lesson.topic || 'Lesson'}</h4>
                                                            <p className="text-gray-500 text-sm mt-1">
                                                                {lesson.summary || 'Generated lesson content'}
                                                            </p>
                                                            <div className="flex gap-2 mt-2">
                                                                <span className="text-xs text-gray-500 flex items-center gap-1">
                                                                    <Clock size={10} />
                                                                    {lesson.createdAt ? new Date(lesson.createdAt).toLocaleDateString() : 'Recently'}
                                                                </span>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            ))
                                        )}
                                    </div>
                                </div>
                            </div>
                        </>
                    ) : (
                        <div className="flex-1 flex flex-col items-center justify-center text-gray-500 p-8">
                            <BookOpen size={80} className="mb-6 opacity-20" />
                            <h2 className="text-2xl font-bold text-gray-400 mb-2">Select a Domain</h2>
                            <p className="text-center max-w-md">
                                Choose a knowledge domain from the sidebar to view sources, generate lessons, and create podcast summaries.
                            </p>
                        </div>
                    )}
                </div>

                {/* RIGHT SIDEBAR - Chat */}
                <div className="w-80 bg-gray-900/50 border-l border-gray-800 flex flex-col flex-shrink-0">
                    <div className="p-4 border-b border-gray-800 flex items-center gap-2">
                        <MessageSquare size={18} className="text-cyan-400" />
                        <h3 className="font-bold text-white">AI Assistant</h3>
                    </div>
                    
                    <div className="flex-1 overflow-y-auto p-3 space-y-3">
                        {chatMessages.length === 0 ? (
                            <div className="text-center text-gray-500 p-4">
                                <MessageSquare size={32} className="mx-auto mb-2 opacity-30" />
                                <p className="text-sm">Ask questions about your content</p>
                            </div>
                        ) : (
                            chatMessages.map((msg, idx) => (
                                <div
                                    key={idx}
                                    className={`p-3 rounded-lg ${
                                        msg.role === 'user'
                                            ? 'bg-cyan-900/30 border border-cyan-700 ml-4'
                                            : 'bg-gray-800/50 border border-gray-700 mr-4'
                                    }`}
                                >
                                    <p className="text-sm text-white whitespace-pre-wrap">{msg.content}</p>
                                </div>
                            ))
                        )}
                    </div>

                    <div className="p-3 border-t border-gray-800">
                        <div className="flex gap-2">
                            <input
                                type="text"
                                value={chatInput}
                                onChange={(e) => setChatInput(e.target.value)}
                                onKeyDown={(e) => e.key === 'Enter' && sendChatMessage()}
                                placeholder="Ask about your content..."
                                className="flex-1 bg-black/50 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:border-cyan-600 outline-none"
                            />
                            <button
                                onClick={sendChatMessage}
                                className="bg-cyan-900/50 hover:bg-cyan-800 text-cyan-300 p-2 rounded-lg border border-cyan-700"
                            >
                                <Play size={16} />
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            {/* ADD CONTENT MODAL */}
            {showAddForm && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm">
                    <div className="bg-gray-900 border border-purple-600 rounded-xl p-6 w-[600px] max-h-[80vh] overflow-y-auto shadow-2xl shadow-purple-500/20">
                        <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                            <Upload size={20} className="text-purple-400" />
                            Add Content to {selectedDomain}
                        </h3>
                        
                        <div className="space-y-4">
                            <div>
                                <label className="text-sm text-gray-400 block mb-1">Title</label>
                                <input
                                    type="text"
                                    value={newContent.title}
                                    onChange={(e) => setNewContent(prev => ({ ...prev, title: e.target.value }))}
                                    placeholder="Content title..."
                                    className="w-full bg-black border border-gray-700 rounded-lg px-4 py-2 text-white focus:border-purple-600 outline-none"
                                />
                            </div>
                            <div>
                                <label className="text-sm text-gray-400 block mb-1">Content</label>
                                <textarea
                                    value={newContent.content}
                                    onChange={(e) => setNewContent(prev => ({ ...prev, content: e.target.value }))}
                                    placeholder="Paste or type your content here..."
                                    rows={10}
                                    className="w-full bg-black border border-gray-700 rounded-lg px-4 py-3 text-white focus:border-purple-600 outline-none resize-none"
                                />
                            </div>
                        </div>

                        <div className="flex gap-3 mt-6">
                            <button
                                onClick={() => setShowAddForm(false)}
                                className="flex-1 bg-gray-800 text-gray-400 py-2 rounded-lg hover:bg-gray-700 transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={addContent}
                                className="flex-1 bg-purple-900 text-purple-300 border border-purple-700 py-2 rounded-lg hover:bg-purple-800 transition-colors font-bold flex items-center justify-center gap-2"
                            >
                                <Save size={16} />
                                Save Content
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default OpenNotebookPage;
