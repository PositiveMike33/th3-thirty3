import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Mail, RefreshCw, AlertCircle, Inbox, ExternalLink, CheckCircle, XCircle } from 'lucide-react';
import { API_URL } from '../config';

const GmailSidebar = () => {
    const navigate = useNavigate();
    const [emails, setEmails] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [connected, setConnected] = useState(false);

    const fetchEmails = async () => {
        setLoading(true);
        setError(null);
        try {
            const res = await fetch(`${API_URL}/google/emails`);
            const data = await res.json();

            if (data.error) {
                setError(data.error);
                setConnected(false);
            } else {
                setEmails(data.emails || []);
                setConnected(true);
            }
        } catch (err) {
            setError('Connexion Gmail requise');
            setConnected(false);
        }
        setLoading(false);
    };

    useEffect(() => {
        fetchEmails();
        // Refresh every 60 seconds
        const interval = setInterval(fetchEmails, 60000);
        return () => clearInterval(interval);
    }, []);

    const handleConnect = () => {
        window.location.href = `${API_URL}/auth/google?email=th3thirty3@gmail.com`;
    };

    return (
        <div className="h-full flex flex-col">
            {/* Header */}
            <div className="flex items-center justify-between border-b border-red-900/50 pb-2 mb-3">
                <div className="flex items-center gap-2">
                    <Mail size={16} className="text-red-500" />
                    <span className="text-sm font-bold text-white tracking-wider">GMAIL INBOX</span>
                </div>
                <div className="flex items-center gap-2">
                    {connected ? (
                        <CheckCircle size={12} className="text-green-500" />
                    ) : (
                        <XCircle size={12} className="text-red-500" />
                    )}
                    <button
                        onClick={fetchEmails}
                        className="text-gray-500 hover:text-white transition-colors"
                        disabled={loading}
                    >
                        <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
                    </button>
                </div>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto space-y-2">
                {!connected && !loading && (
                    <div className="flex flex-col items-center justify-center h-full text-center p-4">
                        <AlertCircle size={32} className="text-red-500/50 mb-3" />
                        <p className="text-xs text-gray-500 mb-3">Gmail non connecté</p>
                        <button
                            onClick={handleConnect}
                            className="bg-red-600 hover:bg-red-500 text-white text-xs px-4 py-2 rounded font-bold flex items-center gap-2"
                        >
                            <Mail size={12} />
                            CONNECTER
                        </button>
                    </div>
                )}

                {loading && (
                    <div className="flex items-center justify-center h-full">
                        <RefreshCw size={24} className="text-red-500 animate-spin" />
                    </div>
                )}

                {connected && emails.length === 0 && !loading && (
                    <div className="flex flex-col items-center justify-center h-full text-center p-4">
                        <Inbox size={32} className="text-gray-600 mb-3" />
                        <p className="text-xs text-gray-500">Aucun email non lu</p>
                    </div>
                )}

                {connected && emails.map((email, index) => (
                    <div
                        key={email.id || index}
                        onClick={() => navigate(`/email/${email.id}`)}
                        className="bg-black/40 border border-red-900/30 rounded p-2 hover:border-red-500/50 hover:bg-red-900/10 transition-all cursor-pointer group"
                    >
                        <div className="flex items-start gap-2">
                            <div className="w-2 h-2 bg-red-500 rounded-full mt-1.5 flex-shrink-0" />
                            <div className="flex-1 min-w-0">
                                <p className="text-xs font-bold text-white truncate">
                                    {email.from?.split('<')[0]?.trim() || 'Inconnu'}
                                </p>
                                <p className="text-[10px] text-gray-400 truncate">
                                    {email.subject || '(Sans sujet)'}
                                </p>
                                <p className="text-[9px] text-gray-600 truncate mt-1">
                                    {email.snippet?.substring(0, 60)}...
                                </p>
                            </div>
                        </div>
                    </div>
                ))}
            </div>

            {/* Footer */}
            {connected && (
                <div className="border-t border-gray-800 pt-2 mt-2">
                    <a
                        href="https://mail.google.com"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center justify-center gap-2 text-xs text-gray-500 hover:text-red-400 transition-colors"
                    >
                        <ExternalLink size={10} />
                        Ouvrir Gmail
                    </a>
                </div>
            )}
        </div>
    );
};

export default GmailSidebar;
