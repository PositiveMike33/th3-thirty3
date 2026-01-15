import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Mail, Clock, User, RefreshCw, ExternalLink } from 'lucide-react';
import { API_URL } from './config';

const EmailDetailPage = () => {
    const { id } = useParams();
    const navigate = useNavigate();
    const [email, setEmail] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchEmail = async () => {
            setLoading(true);
            try {
                const res = await fetch(`${API_URL}/google/emails/${id}`);
                const data = await res.json();
                if (data.error) {
                    setError(data.error);
                } else {
                    setEmail(data);
                }
            } catch (err) {
                setError('Erreur de chargement');
            }
            setLoading(false);
        };
        fetchEmail();
    }, [id]);

    if (loading) {
        return (
            <div className="flex-1 flex items-center justify-center bg-black text-cyan-300">
                <RefreshCw size={48} className="animate-spin text-red-500" />
            </div>
        );
    }

    if (error) {
        return (
            <div className="flex-1 flex flex-col items-center justify-center bg-black text-cyan-300">
                <Mail size={48} className="text-red-500 mb-4" />
                <h2 className="text-xl mb-2">Erreur</h2>
                <p className="text-gray-500">{error}</p>
                <button
                    onClick={() => navigate(-1)}
                    className="mt-4 px-4 py-2 bg-gray-800 rounded hover:bg-gray-700"
                >
                    Retour
                </button>
            </div>
        );
    }

    return (
        <div className="flex-1 flex flex-col bg-black text-gray-300 overflow-hidden">
            {/* Header */}
            <div className="bg-gray-900/80 border-b border-red-900/50 p-4 flex items-center gap-4">
                <button
                    onClick={() => navigate(-1)}
                    className="p-2 hover:bg-gray-800 rounded-full transition-colors"
                >
                    <ArrowLeft size={20} className="text-red-500" />
                </button>
                <div className="flex-1">
                    <h1 className="text-xl font-bold text-white truncate">{email?.subject}</h1>
                </div>
                <a
                    href={`https://mail.google.com/mail/u/0/#inbox/${id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 px-3 py-1.5 bg-red-600 hover:bg-red-500 text-white rounded text-sm"
                >
                    <ExternalLink size={14} />
                    Ouvrir dans Gmail
                </a>
            </div>

            {/* Email Info */}
            <div className="bg-gray-900/50 border-b border-gray-800 p-4">
                <div className="flex items-center gap-3 mb-2">
                    <div className="w-10 h-10 bg-red-900/30 rounded-full flex items-center justify-center">
                        <User size={20} className="text-red-500" />
                    </div>
                    <div>
                        <div className="font-bold text-white">{email?.from}</div>
                        <div className="text-xs text-gray-500">À: {email?.to}</div>
                    </div>
                </div>
                <div className="flex items-center gap-2 text-xs text-gray-500 mt-2">
                    <Clock size={12} />
                    <span>{email?.date}</span>
                </div>
            </div>

            {/* Email Body */}
            <div className="flex-1 overflow-auto p-6 bg-gray-950">
                {email?.body ? (
                    <div
                        className="email-content prose prose-invert max-w-none"
                        dangerouslySetInnerHTML={{ __html: email.body }}
                    />
                ) : (
                    <div className="text-gray-500 italic">
                        {email?.snippet || 'Aucun contenu disponible'}
                    </div>
                )}
            </div>

            <style>{`
                .email-content {
                    color: #e0e0e0;
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                }
                .email-content a {
                    color: #ef4444;
                }
                .email-content img {
                    max-width: 100%;
                    height: auto;
                }
                .email-content table {
                    max-width: 100%;
                }
            `}</style>
        </div>
    );
};

export default EmailDetailPage;
