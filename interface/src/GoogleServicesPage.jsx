import React, { useState, useEffect, useCallback } from 'react';
import {
    Calendar, Mail, Folder, RefreshCw, ChevronRight, Clock, 
    Star, Inbox, Send, Trash2, FileText, Image, Video, Archive,
    Download, Eye, ExternalLink, Search, Filter, Plus, Settings,
    CheckCircle, AlertCircle, User, Users, MapPin, Link2
} from 'lucide-react';
import { API_URL } from './config';

const GoogleServicesPage = () => {
    // State
    const [activeTab, setActiveTab] = useState('calendar');
    const [loading, setLoading] = useState(false);
    const [googleStatus, setGoogleStatus] = useState({});
    const [searchQuery, setSearchQuery] = useState('');
    
    // Google Data
    const [events, setEvents] = useState([]);
    const [emails, setEmails] = useState([]);
    const [files, setFiles] = useState([]);
    const [tasks, setTasks] = useState([]);
    
    // Selection states
    const [selectedEmail, setSelectedEmail] = useState(null);
    const [selectedEvent, setSelectedEvent] = useState(null);
    const [selectedFile, setSelectedFile] = useState(null);

    const ACCOUNTS = ['th3thirty3@gmail.com', 'mikegauthierguillet@gmail.com', 'mgauthierguillet@gmail.com'];

    // Fetch Google Status
    const fetchGoogleStatus = useCallback(async () => {
        try {
            const res = await fetch(`${API_URL}/google/status`);
            const data = await res.json();
            setGoogleStatus(data || {});
        } catch (err) {
            console.error('Error fetching Google status:', err);
        }
    }, []);

    // Fetch All Google Data
    const fetchAllData = useCallback(async () => {
        setLoading(true);
        try {
            const [eventsRes, emailsRes, filesRes, tasksRes] = await Promise.all([
                fetch(`${API_URL}/google/calendar`).catch(() => ({ json: () => ({ events: [] }) })),
                fetch(`${API_URL}/google/emails`).catch(() => ({ json: () => ({ emails: [] }) })),
                fetch(`${API_URL}/google/drive`).catch(() => ({ json: () => ({ files: [] }) })),
                fetch(`${API_URL}/google/tasks`).catch(() => ({ json: () => ({ tasks: [] }) }))
            ]);

            const eventsData = await eventsRes.json();
            const emailsData = await emailsRes.json();
            const filesData = await filesRes.json();
            const tasksData = await tasksRes.json();

            setEvents(eventsData.events || []);
            setEmails(emailsData.emails || []);
            setFiles(filesData.files || []);
            setTasks(tasksData.tasks || []);
        } catch (err) {
            console.error('Error fetching Google data:', err);
        }
        setLoading(false);
    }, []);

    useEffect(() => {
        fetchGoogleStatus();
        fetchAllData();
        const interval = setInterval(fetchAllData, 60000); // Refresh every minute
        return () => clearInterval(interval);
    }, [fetchGoogleStatus, fetchAllData]);

    // Connect Google Account
    const connectGoogle = (email) => {
        window.open(`${API_URL}/auth/google?email=${email}`, '_blank', 'width=500,height=600');
    };

    // Complete/Uncomplete a Google Task
    const completeGoogleTask = async (taskId, isCompleted) => {
        try {
            const res = await fetch(`${API_URL}/google/tasks/${taskId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ completed: !isCompleted })
            });
            const data = await res.json();
            if (data.success) {
                // Update local state
                setTasks(prev => prev.map(t => 
                    t.id === taskId 
                        ? { ...t, status: !isCompleted ? 'completed' : 'needsAction' }
                        : t
                ));
            }
        } catch (err) {
            console.error('Error completing task:', err);
        }
    };

    // Format date helper
    const formatDate = (dateStr) => {
        if (!dateStr) return '';
        const date = new Date(dateStr);
        return date.toLocaleDateString('fr-CA', { 
            weekday: 'short', 
            month: 'short', 
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    };

    // Get file icon based on mime type
    const getFileIcon = (mimeType) => {
        if (mimeType?.includes('folder')) return <Folder className="text-yellow-400" size={18} />;
        if (mimeType?.includes('image')) return <Image className="text-pink-400" size={18} />;
        if (mimeType?.includes('video')) return <Video className="text-purple-400" size={18} />;
        if (mimeType?.includes('document') || mimeType?.includes('text')) return <FileText className="text-blue-400" size={18} />;
        return <FileText className="text-gray-400" size={18} />;
    };

    // Tab configuration
    const tabs = [
        { id: 'calendar', label: 'CALENDAR', icon: Calendar, color: 'purple', count: events.length },
        { id: 'gmail', label: 'GMAIL', icon: Mail, color: 'red', count: emails.length },
        { id: 'drive', label: 'DRIVE', icon: Folder, color: 'yellow', count: files.length },
        { id: 'tasks', label: 'TASKS', icon: CheckCircle, color: 'green', count: tasks.length }
    ];

    return (
        <div className="google-services-page h-full w-full flex flex-col bg-transparent text-white overflow-hidden">
            {/* HEADER */}
            <div className="flex justify-between items-center border-b border-gray-800 px-6 py-4 flex-shrink-0 bg-black/30 backdrop-blur-md">
                <div className="flex items-center gap-4">
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 via-red-500 to-yellow-500 flex items-center justify-center shadow-lg">
                            <span className="text-white font-bold text-lg">G</span>
                        </div>
                        <div>
                            <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-400 via-red-400 to-yellow-400 bg-clip-text text-transparent">
                                Google Services
                            </h1>
                            <p className="text-gray-500 text-xs font-mono">Workspace Integration Hub</p>
                        </div>
                    </div>
                </div>

                <div className="flex items-center gap-4">
                    {/* Account Status */}
                    <div className="flex gap-2">
                        {ACCOUNTS.map(email => (
                            <button
                                key={email}
                                onClick={() => !googleStatus[email] && connectGoogle(email)}
                                className={`text-xs px-3 py-1.5 rounded-lg border transition-all ${
                                    googleStatus[email]
                                        ? 'bg-green-900/30 border-green-600 text-green-400 cursor-default'
                                        : 'bg-red-900/20 border-red-800 text-red-400 hover:bg-red-900/40 cursor-pointer'
                                }`}
                                title={email}
                            >
                                {email.split('@')[0]} {googleStatus[email] ? '✓' : '✗'}
                            </button>
                        ))}
                    </div>

                    {/* Refresh Button */}
                    <button 
                        onClick={fetchAllData}
                        className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-gray-300 px-4 py-2 rounded-lg text-sm border border-gray-700 transition-all"
                    >
                        <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
                        SYNC
                    </button>
                </div>
            </div>

            {/* TAB NAVIGATION */}
            <div className="flex gap-1 px-6 py-3 bg-black/20 border-b border-gray-800 flex-shrink-0">
                {tabs.map(tab => {
                    const Icon = tab.icon;
                    const isActive = activeTab === tab.id;
                    return (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                                isActive
                                    ? `bg-${tab.color}-900/50 text-${tab.color}-400 border border-${tab.color}-700`
                                    : 'text-gray-400 hover:text-white hover:bg-gray-800/50'
                            }`}
                            style={isActive ? {
                                backgroundColor: `rgba(var(--${tab.color}-900), 0.5)`,
                                borderColor: `var(--${tab.color}-700)`
                            } : {}}
                        >
                            <Icon size={16} />
                            {tab.label}
                            <span className={`ml-1 px-2 py-0.5 rounded-full text-xs ${
                                isActive ? 'bg-white/10' : 'bg-gray-800'
                            }`}>
                                {tab.count}
                            </span>
                        </button>
                    );
                })}
            </div>

            {/* MAIN CONTENT */}
            <div className="flex-1 flex overflow-hidden p-4 gap-4 min-h-0">
                
                {/* ===== CALENDAR TAB ===== */}
                {activeTab === 'calendar' && (
                    <>
                        {/* Events List */}
                        <div className="w-1/3 bg-gray-900/50 border border-purple-900/50 rounded-xl overflow-hidden flex flex-col">
                            <div className="p-4 border-b border-purple-900/30 bg-purple-900/20">
                                <div className="flex items-center gap-2 text-purple-400">
                                    <Calendar size={18} />
                                    <h3 className="font-bold">Upcoming Events</h3>
                                </div>
                            </div>
                            <div className="flex-1 overflow-y-auto p-2 space-y-2">
                                {events.length === 0 ? (
                                    <div className="flex flex-col items-center justify-center h-full text-gray-500">
                                        <Calendar size={48} className="mb-3 opacity-30" />
                                        <p>No upcoming events</p>
                                    </div>
                                ) : (
                                    events.map((event, idx) => (
                                        <div
                                            key={event.id || idx}
                                            onClick={() => setSelectedEvent(event)}
                                            className={`p-3 rounded-lg cursor-pointer transition-all ${
                                                selectedEvent?.id === event.id
                                                    ? 'bg-purple-900/50 border border-purple-500'
                                                    : 'bg-black/30 border border-gray-800 hover:border-purple-700'
                                            }`}
                                        >
                                            <h4 className="text-white font-medium text-sm truncate">
                                                {event.summary || 'Untitled Event'}
                                            </h4>
                                            <div className="flex items-center gap-2 mt-2 text-xs text-gray-400">
                                                <Clock size={12} />
                                                {formatDate(event.start?.dateTime || event.start?.date)}
                                            </div>
                                            {event.location && (
                                                <div className="flex items-center gap-2 mt-1 text-xs text-gray-500">
                                                    <MapPin size={12} />
                                                    <span className="truncate">{event.location}</span>
                                                </div>
                                            )}
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>

                        {/* Event Details */}
                        <div className="flex-1 bg-gray-900/50 border border-purple-900/50 rounded-xl overflow-hidden flex flex-col">
                            <div className="p-4 border-b border-purple-900/30 bg-purple-900/20">
                                <h3 className="font-bold text-purple-400">Event Details</h3>
                            </div>
                            <div className="flex-1 p-6 overflow-y-auto">
                                {selectedEvent ? (
                                    <div className="space-y-6">
                                        <div>
                                            <h2 className="text-2xl font-bold text-white mb-2">
                                                {selectedEvent.summary || 'Untitled Event'}
                                            </h2>
                                            <div className="flex items-center gap-4 text-gray-400">
                                                <div className="flex items-center gap-2">
                                                    <Clock size={16} />
                                                    {formatDate(selectedEvent.start?.dateTime || selectedEvent.start?.date)}
                                                </div>
                                            </div>
                                        </div>

                                        {selectedEvent.location && (
                                            <div className="bg-black/30 p-4 rounded-lg border border-gray-800">
                                                <div className="flex items-center gap-2 text-gray-400 mb-2">
                                                    <MapPin size={16} />
                                                    <span className="font-medium">Location</span>
                                                </div>
                                                <p className="text-white">{selectedEvent.location}</p>
                                            </div>
                                        )}

                                        {selectedEvent.description && (
                                            <div className="bg-black/30 p-4 rounded-lg border border-gray-800">
                                                <h4 className="text-gray-400 mb-2 font-medium">Description</h4>
                                                <p className="text-gray-300 text-sm whitespace-pre-wrap">
                                                    {selectedEvent.description}
                                                </p>
                                            </div>
                                        )}

                                        {selectedEvent.attendees && selectedEvent.attendees.length > 0 && (
                                            <div className="bg-black/30 p-4 rounded-lg border border-gray-800">
                                                <div className="flex items-center gap-2 text-gray-400 mb-3">
                                                    <Users size={16} />
                                                    <span className="font-medium">Attendees ({selectedEvent.attendees.length})</span>
                                                </div>
                                                <div className="space-y-2">
                                                    {selectedEvent.attendees.map((att, i) => (
                                                        <div key={i} className="flex items-center gap-2 text-sm">
                                                            <User size={14} className="text-gray-500" />
                                                            <span className="text-gray-300">{att.email}</span>
                                                            {att.responseStatus === 'accepted' && (
                                                                <CheckCircle size={12} className="text-green-400" />
                                                            )}
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                        )}

                                        {selectedEvent.htmlLink && (
                                            <a
                                                href={selectedEvent.htmlLink}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="inline-flex items-center gap-2 bg-purple-900/50 hover:bg-purple-800 text-purple-300 px-4 py-2 rounded-lg border border-purple-700 transition-all"
                                            >
                                                <ExternalLink size={16} />
                                                Open in Google Calendar
                                            </a>
                                        )}
                                    </div>
                                ) : (
                                    <div className="flex flex-col items-center justify-center h-full text-gray-500">
                                        <Calendar size={64} className="mb-4 opacity-20" />
                                        <p className="text-lg">Select an event to view details</p>
                                    </div>
                                )}
                            </div>
                        </div>
                    </>
                )}

                {/* ===== GMAIL TAB ===== */}
                {activeTab === 'gmail' && (
                    <>
                        {/* Email List */}
                        <div className="w-1/3 bg-gray-900/50 border border-red-900/50 rounded-xl overflow-hidden flex flex-col">
                            <div className="p-4 border-b border-red-900/30 bg-red-900/20">
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-2 text-red-400">
                                        <Mail size={18} />
                                        <h3 className="font-bold">Inbox</h3>
                                    </div>
                                    <div className="flex gap-1">
                                        <button className="p-1.5 rounded hover:bg-red-900/50 text-gray-400 hover:text-red-400">
                                            <Inbox size={14} />
                                        </button>
                                        <button className="p-1.5 rounded hover:bg-red-900/50 text-gray-400 hover:text-red-400">
                                            <Star size={14} />
                                        </button>
                                        <button className="p-1.5 rounded hover:bg-red-900/50 text-gray-400 hover:text-red-400">
                                            <Send size={14} />
                                        </button>
                                    </div>
                                </div>
                            </div>
                            <div className="flex-1 overflow-y-auto">
                                {emails.length === 0 ? (
                                    <div className="flex flex-col items-center justify-center h-full text-gray-500">
                                        <Mail size={48} className="mb-3 opacity-30" />
                                        <p>No emails found</p>
                                    </div>
                                ) : (
                                    emails.map((email, idx) => (
                                        <div
                                            key={email.id || idx}
                                            onClick={() => setSelectedEmail(email)}
                                            className={`p-4 border-b border-gray-800 cursor-pointer transition-all ${
                                                selectedEmail?.id === email.id
                                                    ? 'bg-red-900/30 border-l-2 border-l-red-500'
                                                    : 'hover:bg-gray-800/50'
                                            }`}
                                        >
                                            <div className="flex items-start justify-between gap-2">
                                                <div className="flex-1 min-w-0">
                                                    <p className="text-white font-medium text-sm truncate">
                                                        {email.from?.split('<')[0]?.trim() || 'Unknown Sender'}
                                                    </p>
                                                    <p className="text-gray-300 text-sm truncate mt-1">
                                                        {email.subject || 'No Subject'}
                                                    </p>
                                                    <p className="text-gray-500 text-xs truncate mt-1">
                                                        {email.snippet || ''}
                                                    </p>
                                                </div>
                                                <span className="text-xs text-gray-500 whitespace-nowrap">
                                                    {email.date ? new Date(email.date).toLocaleDateString('fr-CA', { month: 'short', day: 'numeric' }) : ''}
                                                </span>
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>

                        {/* Email Content */}
                        <div className="flex-1 bg-gray-900/50 border border-red-900/50 rounded-xl overflow-hidden flex flex-col">
                            <div className="p-4 border-b border-red-900/30 bg-red-900/20 flex items-center justify-between">
                                <h3 className="font-bold text-red-400">Message</h3>
                                {selectedEmail && (
                                    <div className="flex gap-2">
                                        <button className="p-1.5 rounded hover:bg-red-900/50 text-gray-400">
                                            <Archive size={16} />
                                        </button>
                                        <button className="p-1.5 rounded hover:bg-red-900/50 text-gray-400">
                                            <Trash2 size={16} />
                                        </button>
                                    </div>
                                )}
                            </div>
                            <div className="flex-1 p-6 overflow-y-auto">
                                {selectedEmail ? (
                                    <div className="space-y-4">
                                        <div className="border-b border-gray-800 pb-4">
                                            <h2 className="text-xl font-bold text-white mb-3">
                                                {selectedEmail.subject || 'No Subject'}
                                            </h2>
                                            <div className="flex items-center gap-3">
                                                <div className="w-10 h-10 rounded-full bg-gradient-to-br from-red-500 to-orange-500 flex items-center justify-center">
                                                    <User size={20} className="text-white" />
                                                </div>
                                                <div>
                                                    <p className="text-white font-medium">
                                                        {selectedEmail.from?.split('<')[0]?.trim() || 'Unknown'}
                                                    </p>
                                                    <p className="text-gray-500 text-xs">
                                                        {selectedEmail.from?.match(/<(.+)>/)?.[1] || selectedEmail.from}
                                                    </p>
                                                </div>
                                                <span className="ml-auto text-xs text-gray-500">
                                                    {selectedEmail.date ? formatDate(selectedEmail.date) : ''}
                                                </span>
                                            </div>
                                        </div>
                                        <div className="text-gray-300 text-sm leading-relaxed whitespace-pre-wrap">
                                            {selectedEmail.body || selectedEmail.snippet || 'No content available'}
                                        </div>
                                    </div>
                                ) : (
                                    <div className="flex flex-col items-center justify-center h-full text-gray-500">
                                        <Mail size={64} className="mb-4 opacity-20" />
                                        <p className="text-lg">Select an email to read</p>
                                    </div>
                                )}
                            </div>
                        </div>
                    </>
                )}

                {/* ===== DRIVE TAB ===== */}
                {activeTab === 'drive' && (
                    <>
                        {/* Files List */}
                        <div className="w-2/5 bg-gray-900/50 border border-yellow-900/50 rounded-xl overflow-hidden flex flex-col">
                            <div className="p-4 border-b border-yellow-900/30 bg-yellow-900/20">
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-2 text-yellow-400">
                                        <Folder size={18} />
                                        <h3 className="font-bold">My Drive</h3>
                                    </div>
                                    <button className="p-1.5 rounded hover:bg-yellow-900/50 text-yellow-400">
                                        <Plus size={16} />
                                    </button>
                                </div>
                                {/* Search */}
                                <div className="mt-3 relative">
                                    <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                                    <input
                                        type="text"
                                        placeholder="Search files..."
                                        value={searchQuery}
                                        onChange={(e) => setSearchQuery(e.target.value)}
                                        className="w-full bg-black/50 border border-gray-700 rounded-lg pl-9 pr-3 py-2 text-sm text-white focus:border-yellow-600 outline-none"
                                    />
                                </div>
                            </div>
                            <div className="flex-1 overflow-y-auto p-2 space-y-1">
                                {files.length === 0 ? (
                                    <div className="flex flex-col items-center justify-center h-full text-gray-500">
                                        <Folder size={48} className="mb-3 opacity-30" />
                                        <p>No files found</p>
                                    </div>
                                ) : (
                                    files
                                        .filter(f => !searchQuery || f.name?.toLowerCase().includes(searchQuery.toLowerCase()))
                                        .map((file, idx) => (
                                            <div
                                                key={file.id || idx}
                                                onClick={() => setSelectedFile(file)}
                                                className={`flex items-center gap-3 p-3 rounded-lg cursor-pointer transition-all ${
                                                    selectedFile?.id === file.id
                                                        ? 'bg-yellow-900/30 border border-yellow-600'
                                                        : 'hover:bg-gray-800/50 border border-transparent'
                                                }`}
                                            >
                                                {getFileIcon(file.mimeType)}
                                                <div className="flex-1 min-w-0">
                                                    <p className="text-white text-sm truncate">{file.name}</p>
                                                    <p className="text-gray-500 text-xs">
                                                        {file.modifiedTime ? new Date(file.modifiedTime).toLocaleDateString() : ''}
                                                    </p>
                                                </div>
                                                <ChevronRight size={16} className="text-gray-600" />
                                            </div>
                                        ))
                                )}
                            </div>
                        </div>

                        {/* File Details */}
                        <div className="flex-1 bg-gray-900/50 border border-yellow-900/50 rounded-xl overflow-hidden flex flex-col">
                            <div className="p-4 border-b border-yellow-900/30 bg-yellow-900/20">
                                <h3 className="font-bold text-yellow-400">File Details</h3>
                            </div>
                            <div className="flex-1 p-6 overflow-y-auto">
                                {selectedFile ? (
                                    <div className="space-y-6">
                                        <div className="flex items-start gap-4">
                                            <div className="w-16 h-16 rounded-xl bg-yellow-900/30 flex items-center justify-center border border-yellow-700">
                                                {getFileIcon(selectedFile.mimeType)}
                                            </div>
                                            <div>
                                                <h2 className="text-xl font-bold text-white">{selectedFile.name}</h2>
                                                <p className="text-gray-500 text-sm mt-1">{selectedFile.mimeType}</p>
                                            </div>
                                        </div>

                                        <div className="grid grid-cols-2 gap-4">
                                            <div className="bg-black/30 p-4 rounded-lg border border-gray-800">
                                                <p className="text-gray-500 text-xs mb-1">Size</p>
                                                <p className="text-white">{selectedFile.size ? `${(selectedFile.size / 1024).toFixed(1)} KB` : 'N/A'}</p>
                                            </div>
                                            <div className="bg-black/30 p-4 rounded-lg border border-gray-800">
                                                <p className="text-gray-500 text-xs mb-1">Modified</p>
                                                <p className="text-white">{selectedFile.modifiedTime ? new Date(selectedFile.modifiedTime).toLocaleDateString() : 'N/A'}</p>
                                            </div>
                                        </div>

                                        {selectedFile.owners && (
                                            <div className="bg-black/30 p-4 rounded-lg border border-gray-800">
                                                <p className="text-gray-500 text-xs mb-2">Owner</p>
                                                <div className="flex items-center gap-2">
                                                    <User size={14} className="text-gray-400" />
                                                    <span className="text-white">{selectedFile.owners?.[0]?.displayName || 'Unknown'}</span>
                                                </div>
                                            </div>
                                        )}

                                        <div className="flex gap-3">
                                            {selectedFile.webViewLink && (
                                                <a
                                                    href={selectedFile.webViewLink}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="flex items-center gap-2 bg-yellow-900/50 hover:bg-yellow-800 text-yellow-300 px-4 py-2 rounded-lg border border-yellow-700 transition-all"
                                                >
                                                    <Eye size={16} />
                                                    View
                                                </a>
                                            )}
                                            {selectedFile.webContentLink && (
                                                <a
                                                    href={selectedFile.webContentLink}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-gray-300 px-4 py-2 rounded-lg border border-gray-700 transition-all"
                                                >
                                                    <Download size={16} />
                                                    Download
                                                </a>
                                            )}
                                        </div>
                                    </div>
                                ) : (
                                    <div className="flex flex-col items-center justify-center h-full text-gray-500">
                                        <Folder size={64} className="mb-4 opacity-20" />
                                        <p className="text-lg">Select a file to view details</p>
                                    </div>
                                )}
                            </div>
                        </div>
                    </>
                )}

                {/* ===== TASKS TAB ===== */}
                {activeTab === 'tasks' && (
                    <div className="flex-1 bg-gray-900/50 border border-green-900/50 rounded-xl overflow-hidden flex flex-col">
                        <div className="p-4 border-b border-green-900/30 bg-green-900/20 flex items-center justify-between">
                            <div className="flex items-center gap-2 text-green-400">
                                <CheckCircle size={18} />
                                <h3 className="font-bold">Tasks</h3>
                            </div>
                            <button className="flex items-center gap-2 bg-green-900/50 hover:bg-green-800 text-green-300 px-3 py-1.5 rounded-lg border border-green-700 text-sm">
                                <Plus size={14} />
                                Add Task
                            </button>
                        </div>
                        <div className="flex-1 overflow-y-auto p-4">
                            {tasks.length === 0 ? (
                                <div className="flex flex-col items-center justify-center h-full text-gray-500">
                                    <CheckCircle size={64} className="mb-4 opacity-20" />
                                    <p className="text-lg">No tasks found</p>
                                    <p className="text-sm mt-2">Create a task to get started</p>
                                </div>
                            ) : (
                                <div className="space-y-2">
                                    {tasks.map((task, idx) => (
                                        <div
                                            key={task.id || idx}
                                            className={`flex items-center gap-3 p-4 bg-black/30 rounded-lg border transition-all cursor-pointer ${
                                                task.status === 'completed' 
                                                    ? 'border-green-700/50 bg-green-900/10' 
                                                    : 'border-gray-800 hover:border-green-700'
                                            }`}
                                            onClick={() => completeGoogleTask(task.id, task.status === 'completed')}
                                        >
                                            <button 
                                                className="text-gray-500 hover:text-green-400 transition-colors"
                                                onClick={(e) => {
                                                    e.stopPropagation();
                                                    completeGoogleTask(task.id, task.status === 'completed');
                                                }}
                                            >
                                                {task.status === 'completed' ? (
                                                    <CheckCircle size={20} className="text-green-400" />
                                                ) : (
                                                    <div className="w-5 h-5 rounded-full border-2 border-gray-600 hover:border-green-400 transition-colors" />
                                                )}
                                            </button>
                                            <div className="flex-1">
                                                <p className={`text-white transition-all ${
                                                    task.status === 'completed' ? 'line-through opacity-50' : ''
                                                }`}>
                                                    {task.title || 'Untitled Task'}
                                                </p>
                                                {task.due && (
                                                    <p className="text-gray-500 text-xs mt-1 flex items-center gap-1">
                                                        <Clock size={12} />
                                                        Due: {new Date(task.due).toLocaleDateString()}
                                                    </p>
                                                )}
                                                {task.notes && (
                                                    <p className="text-gray-600 text-xs mt-1 truncate">{task.notes}</p>
                                                )}
                                            </div>
                                            {task.status === 'completed' && (
                                                <span className="text-xs text-green-500 bg-green-900/30 px-2 py-1 rounded">Done</span>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default GoogleServicesPage;
