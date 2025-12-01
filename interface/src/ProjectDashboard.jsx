import React, { useState, useEffect } from 'react';
import { ExternalLink, Calendar, Briefcase, RefreshCw } from 'lucide-react';

const ProjectDashboard = () => {
    const dartUrl = "https://app.itsdart.com/";
    const calendarUrl = "https://calendar.google.com/";

    const [events, setEvents] = useState("Chargement...");
    const [loading, setLoading] = useState(false);

    const fetchCalendar = async () => {
        setLoading(true);
        try {
            const res = await fetch('http://localhost:3000/google/calendar');
            const data = await res.json();
            setEvents(data.events || "Aucun événement trouvé.");
        } catch (e) {
            setEvents("Erreur de chargement du calendrier.");
        }
        setLoading(false);
    };

    useEffect(() => {
        fetchCalendar();
    }, []);

    return (
        <div className="flex-1 p-8 bg-black text-cyan-300 overflow-y-auto bg-[url('/grid.png')]">
            <h2 className="text-2xl font-bold tracking-widest mb-8 border-b border-cyan-900 pb-4 flex items-center gap-3">
                <Briefcase className="text-cyan-500" /> MISSION CONTROL
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

                {/* DART AI CARD */}
                <div className="bg-gray-900/50 border border-cyan-800 p-6 rounded-lg backdrop-blur hover:border-cyan-500 transition-all group">
                    <div className="flex justify-between items-start mb-4">
                        <h3 className="text-xl font-bold text-white group-hover:text-cyan-400 transition-colors">DART AI</h3>
                        <span className="bg-cyan-900/50 text-cyan-300 text-xs px-2 py-1 rounded border border-cyan-700">PROJECTS</span>
                    </div>
                    <p className="text-gray-400 text-sm mb-6 h-12">
                        Gestion de projet, tâches et sprints. Accès direct à l'espace de travail.
                    </p>
                    <div className="flex flex-col gap-2">
                        <div className="text-xs text-gray-500 font-mono mb-2">WORKSPACE: kok90kMp4rU4</div>
                        <a
                            href={dartUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center justify-center gap-2 bg-cyan-700 hover:bg-cyan-600 text-white py-3 rounded font-bold transition-all shadow-[0_0_15px_rgba(8,145,178,0.3)] hover:shadow-[0_0_25px_rgba(34,211,238,0.5)]"
                        >
                            <ExternalLink size={18} />
                            OUVRIR DART
                        </a>
                    </div>
                </div>

                {/* GOOGLE CALENDAR CARD (EMBEDDED) */}
                <div className="bg-gray-900/50 border border-purple-800 p-6 rounded-lg backdrop-blur hover:border-purple-500 transition-all group flex flex-col h-[600px]">
                    <div className="flex justify-between items-start mb-4">
                        <h3 className="text-xl font-bold text-white group-hover:text-purple-400 transition-colors">CALENDRIER</h3>
                        <span className="bg-purple-900/50 text-purple-300 text-xs px-2 py-1 rounded border border-purple-700">SCHEDULE</span>
                    </div>

                    {/* Live Events Widget (API) - Kept for quick summary */}
                    <div className="bg-black/60 border border-gray-700 rounded p-2 mb-4 h-24 overflow-y-auto font-mono text-xs scrollbar-thin scrollbar-thumb-purple-900">
                        <div className="flex justify-between items-center mb-1 border-b border-gray-700 pb-1">
                            <span className="text-gray-500">PROCHAINS (API)</span>
                            <button onClick={fetchCalendar} disabled={loading} className="text-purple-400 hover:text-white">
                                <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
                            </button>
                        </div>
                        <pre className="whitespace-pre-wrap text-gray-300 leading-relaxed">
                            {events}
                        </pre>
                    </div>

                    {/* Embed Iframe */}
                    <div className="flex-1 bg-white rounded overflow-hidden">
                        <iframe
                            src="https://calendar.google.com/calendar/embed?height=600&wkst=2&bgcolor=%23ffffff&ctz=America%2FToronto&showTitle=0&showNav=1&showDate=1&showPrint=0&showTabs=1&showCalendars=0&mode=WEEK"
                            style={{ borderWidth: 0 }}
                            width="100%"
                            height="100%"
                            frameBorder="0"
                            scrolling="no"
                            title="Google Calendar"
                        ></iframe>
                    </div>
                </div>

            </div>
        </div>
    );
};

export default ProjectDashboard;
