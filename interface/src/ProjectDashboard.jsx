import React, { useState, useEffect } from 'react';
import {
    Briefcase, Plus, Trash2, CheckCircle, Circle,
    ArrowRight, Layout, Terminal, Loader, Save,
    Calendar, Mail, FileText, Map as MapIcon, RefreshCw
} from 'lucide-react';

const API_URL = 'http://localhost:3000';

const ProjectDashboard = () => {
    // Project State
    const [projects, setProjects] = useState([]);
    const [activeProject, setActiveProject] = useState(null);
    // const [loading, setLoading] = useState(false); // Unused
    // const [loading, setLoading] = useState(false); // Removed unused state
    const [showNewProjectInput, setShowNewProjectInput] = useState(false);
    const [newProjectName, setNewProjectName] = useState("");
    const [newTaskContent, setNewTaskContent] = useState("");

    // Google State
    const [googleData, setGoogleData] = useState({
        events: [],
        emails: [],
        tasks: [],
        files: []
    });
    const [googleLoading, setGoogleLoading] = useState(false);

    // Agent State
    const [agents, setAgents] = useState([]);
    const [showAgentModal, setShowAgentModal] = useState(false);
    const [selectedAgent, setSelectedAgent] = useState("");
    const [agentTask, setAgentTask] = useState("");

    // --- DATA FETCHING ---

    const fetchAgents = async () => {
        try {
            const res = await fetch(`${API_URL}/models?computeMode=cloud`);
            const data = await res.json();
            // The backend returns { local: [], cloud: [] }
            const allModels = [...(data.local || []), ...(data.cloud || [])];
            // Filter for AnythingLLM agents
            const agentList = allModels.filter(m => m.provider === 'anythingllm');
            console.log("Agents found:", agentList);
            setAgents(agentList);
            if (agentList.length > 0 && !selectedAgent) {
                setSelectedAgent(agentList[0].id);
            }
        } catch (error) {
            console.error("Error fetching agents:", error);
        }
    };

    const fetchProjects = React.useCallback(async () => {
        try {
            const res = await fetch(`${API_URL}/projects`);
            const data = await res.json();
            setProjects(data);
            setActiveProject(current => {
                if (current) {
                    const updated = data.find(p => p.id === current.id);
                    return updated || current;
                }
                return current;
            });
        } catch (error) {
            console.error("Error fetching projects:", error);
        }
    }, []);

    const fetchGoogleData = React.useCallback(async () => {
        setGoogleLoading(true);
        try {
            const [eventsRes, emailsRes, tasksRes, filesRes] = await Promise.all([
                fetch(`${API_URL}/google/calendar`),
                fetch(`${API_URL}/google/emails`),
                fetch(`${API_URL}/google/tasks`),
                fetch(`${API_URL}/google/drive`)
            ]);

            const events = await eventsRes.json();
            const emails = await emailsRes.json();
            const tasks = await tasksRes.json();
            const files = await filesRes.json();

            setGoogleData({
                events: events.events || [],
                emails: emails.emails || [],
                tasks: tasks.tasks || [],
                files: files.files || []
            });
        } catch (error) {
            console.error("Error fetching Google data:", error);
        }
        setGoogleLoading(false);
    }, []);

    useEffect(() => {
        fetchProjects();
        fetchGoogleData();

        // Real-time refresh every 10s (was 60s)
        const interval = setInterval(fetchGoogleData, 10000);
        return () => clearInterval(interval);
    }, [fetchProjects, fetchGoogleData]);

    // --- PROJECT ACTIONS ---

    const handleCreateProject = async () => {
        if (!newProjectName.trim()) return;
        try {
            const res = await fetch(`${API_URL}/projects`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: newProjectName, description: "New Project" })
            });
            const project = await res.json();
            setProjects([...projects, project]);
            setActiveProject(project);
            setNewProjectName("");
            setShowNewProjectInput(false);
        } catch (error) {
            console.error("Error creating project:", error);
        }
    };

    const handleDeleteProject = async (id) => {
        if (!confirm("Supprimer ce projet ?")) return;
        try {
            await fetch(`${API_URL}/projects/${id}`, { method: 'DELETE' });
            setProjects(projects.filter(p => p.id !== id));
            if (activeProject?.id === id) setActiveProject(null);
        } catch (error) {
            console.error("Error deleting project:", error);
        }
    };

    const handleAddTask = async (status = 'todo') => {
        if (!newTaskContent.trim() || !activeProject) return;
        try {
            await fetch(`${API_URL}/projects/${activeProject.id}/tasks`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: newTaskContent, status })
            });
            await fetchProjects();
            setNewTaskContent("");
        } catch (error) {
            console.error("Error adding task:", error);
        }
    };

    const handleMoveTask = async (taskId, newStatus) => {
        if (!activeProject) return;
        try {
            await fetch(`${API_URL}/projects/${activeProject.id}/tasks/${taskId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: newStatus })
            });
            fetchProjects();
        } catch (error) {
            console.error("Error moving task:", error);
        }
    };

    const handleDeleteTask = async (taskId) => {
        if (!activeProject) return;
        try {
            await fetch(`${API_URL}/projects/${activeProject.id}/tasks/${taskId}`, { method: 'DELETE' });
            fetchProjects();
        } catch (error) {
            console.error("Error deleting task:", error);
        }
    };

    // --- RENDER HELPERS ---

    const renderColumn = (title, status, icon) => {
        const tasks = activeProject?.tasks.filter(t => t.status === status) || [];
        return (
            <div className="flex-1 bg-gray-900/50 border border-gray-800 rounded-lg p-4 flex flex-col min-h-[300px]">
                <div className="flex items-center gap-2 mb-4 border-b border-gray-700 pb-2">
                    {icon}
                    <h3 className="font-bold text-gray-300 uppercase text-xs tracking-wider">{title}</h3>
                    <span className="ml-auto bg-gray-800 text-xs px-2 py-0.5 rounded-full text-gray-400">{tasks.length}</span>
                </div>

                <div className="flex-1 flex flex-col gap-2 overflow-y-auto max-h-[400px]">
                    {tasks.map(task => (
                        <div key={task.id} className="bg-black/40 border border-gray-700 p-3 rounded hover:border-cyan-500/50 transition-all group relative">
                            <p className="text-gray-300 text-sm mb-2">{task.content}</p>
                            <div className="flex justify-between items-center mt-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                <button onClick={() => handleDeleteTask(task.id)} className="text-red-500 hover:text-red-400">
                                    <Trash2 size={12} />
                                </button>
                                <div className="flex gap-1">
                                    {status !== 'todo' && (
                                        <button onClick={() => handleMoveTask(task.id, 'todo')} className="text-gray-500 hover:text-white" title="Move to Todo">
                                            <Circle size={12} />
                                        </button>
                                    )}
                                    {status !== 'in-progress' && (
                                        <button onClick={() => handleMoveTask(task.id, 'in-progress')} className="text-blue-500 hover:text-blue-400" title="Move to In Progress">
                                            <ArrowRight size={12} />
                                        </button>
                                    )}
                                    {status !== 'done' && (
                                        <button onClick={() => handleMoveTask(task.id, 'done')} className="text-green-500 hover:text-green-400" title="Move to Done">
                                            <CheckCircle size={12} />
                                        </button>
                                    )}
                                </div>
                            </div>
                        </div>
                    ))}
                </div>

                {status === 'todo' && (
                    <div className="mt-4 pt-4 border-t border-gray-800">
                        <div className="flex gap-2">
                            <input
                                type="text"
                                value={newTaskContent}
                                onChange={(e) => setNewTaskContent(e.target.value)}
                                onKeyDown={(e) => e.key === 'Enter' && handleAddTask()}
                                placeholder="Nouvelle tâche..."
                                className="flex-1 bg-black border border-gray-700 rounded px-3 py-2 text-xs text-white focus:border-cyan-500 outline-none"
                            />
                            <button onClick={() => handleAddTask()} className="bg-cyan-900/50 hover:bg-cyan-800 text-cyan-300 p-2 rounded border border-cyan-700">
                                <Plus size={14} />
                            </button>
                        </div>
                    </div>
                )}
            </div>
        );
    };

    return (
        <div className="flex h-full bg-transparent text-cyan-300 overflow-hidden">
            {/* SIDEBAR */}
            <div className="w-64 border-r border-gray-800 bg-gray-900/30 flex flex-col p-4 shrink-0">
                <div className="flex items-center gap-2 mb-8 text-cyan-500">
                    <Layout size={24} />
                    <h1 className="font-bold tracking-widest text-lg">DART AI</h1>
                </div>

                <div className="flex-1 overflow-y-auto">
                    <h2 className="text-xs font-mono text-gray-500 mb-4 uppercase">Projets Actifs</h2>
                    <div className="flex flex-col gap-2">
                        {projects.map(p => (
                            <button
                                key={p.id}
                                onClick={() => setActiveProject(p)}
                                className={`text-left px-3 py-2 rounded text-sm transition-all flex justify-between items-center group ${activeProject?.id === p.id ? 'bg-cyan-900/30 text-cyan-300 border border-cyan-800' : 'text-gray-400 hover:bg-gray-800 hover:text-white'}`}
                            >
                                <span className="truncate">{p.name}</span>
                                {activeProject?.id === p.id && (
                                    <Trash2 size={12} className="opacity-0 group-hover:opacity-100 text-red-500 hover:text-red-400" onClick={(e) => { e.stopPropagation(); handleDeleteProject(p.id); }} />
                                )}
                            </button>
                        ))}
                    </div>
                </div>

                <div className="mt-4 pt-4 border-t border-gray-800">
                    {showNewProjectInput ? (
                        <div className="flex flex-col gap-2">
                            <input
                                autoFocus
                                type="text"
                                value={newProjectName}
                                onChange={(e) => setNewProjectName(e.target.value)}
                                onKeyDown={(e) => e.key === 'Enter' && handleCreateProject()}
                                placeholder="Nom du projet..."
                                className="bg-black border border-gray-700 rounded px-2 py-1 text-sm text-white focus:border-cyan-500 outline-none"
                            />
                            <div className="flex gap-2">
                                <button onClick={handleCreateProject} className="flex-1 bg-cyan-700 text-white text-xs py-1 rounded hover:bg-cyan-600">Créer</button>
                                <button onClick={() => setShowNewProjectInput(false)} className="flex-1 bg-gray-800 text-gray-400 text-xs py-1 rounded hover:bg-gray-700">Annuler</button>
                            </div>
                        </div>
                    ) : (
                        <button onClick={() => setShowNewProjectInput(true)} className="w-full flex items-center justify-center gap-2 border border-dashed border-gray-700 text-gray-500 py-2 rounded hover:border-cyan-500 hover:text-cyan-500 transition-all text-sm">
                            <Plus size={14} /> Nouveau Projet
                        </button>
                    )}
                </div>
            </div>

            {/* MAIN CONTENT GRID */}
            <div className="flex-1 p-6 overflow-y-auto grid grid-cols-12 gap-6 auto-rows-min">

                {/* HEADER */}
                <div className="col-span-12 flex justify-between items-end border-b border-gray-800 pb-4 mb-2">
                    <div>
                        <h2 className="text-3xl font-bold text-white mb-1">{activeProject ? activeProject.name : "DASHBOARD"}</h2>
                        <p className="text-gray-500 text-sm font-mono">{activeProject ? activeProject.id : "Vue d'ensemble"}</p>
                    </div>
                    <div className="flex gap-2">
                        <button onClick={fetchGoogleData} className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded text-sm border border-gray-700">
                            <RefreshCw size={14} className={googleLoading ? "animate-spin" : ""} />
                            SYNC
                        </button>
                        <button
                            onClick={() => {
                                fetchAgents();
                                setShowAgentModal(true);
                            }}
                            className="flex items-center gap-2 bg-cyan-900/30 hover:bg-cyan-800 text-cyan-300 px-3 py-1.5 rounded text-sm border border-cyan-800"
                        >
                            <Terminal size={14} />
                            AI ASSISTANT
                        </button>
                    </div>
                </div>

                {/* AGENT MODAL */}
                {showAgentModal && (
                    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm">
                        <div className="bg-gray-900 border border-cyan-500 rounded-lg p-6 w-96 shadow-[0_0_30px_rgba(34,211,238,0.2)]">
                            <h3 className="text-lg font-bold text-cyan-400 mb-4 flex items-center gap-2">
                                <Terminal size={20} /> DÉPLOIEMENT AGENT
                            </h3>

                            {/* Agent Selector */}
                            <div className="mb-4">
                                <label className="text-xs text-gray-500 block mb-1">SÉLECTIONNER L'AGENT (Workspace)</label>
                                <select
                                    value={selectedAgent}
                                    onChange={(e) => setSelectedAgent(e.target.value)}
                                    className="w-full bg-black border border-gray-700 rounded p-2 text-sm text-white focus:border-cyan-500 outline-none"
                                >
                                    <option value="">-- Choisir un Agent --</option>
                                    {agents.map(agent => (
                                        <option key={agent.id} value={agent.id}>
                                            {agent.name.replace('[AGENT] ', '')}
                                        </option>
                                    ))}
                                </select>
                            </div>

                            {/* Task Input */}
                            <div className="mb-6">
                                <label className="text-xs text-gray-500 block mb-1">MISSION</label>
                                <textarea
                                    value={agentTask}
                                    onChange={(e) => setAgentTask(e.target.value)}
                                    placeholder="Ex: Analyse ce projet et liste les risques..."
                                    className="w-full bg-black border border-gray-700 rounded p-2 text-sm text-white focus:border-cyan-500 outline-none h-24 resize-none"
                                />
                            </div>

                            {/* Actions */}
                            <div className="flex gap-3">
                                <button
                                    onClick={() => setShowAgentModal(false)}
                                    className="flex-1 bg-gray-800 text-gray-400 py-2 rounded hover:bg-gray-700 transition-colors"
                                >
                                    ANNULER
                                </button>
                                <button
                                    onClick={() => {
                                        if (!selectedAgent || !agentTask.trim()) return;

                                        // Trigger Agent
                                        fetch(`${API_URL}/chat`, {
                                            method: 'POST',
                                            headers: {
                                                'Content-Type': 'application/json',
                                                'x-api-key': localStorage.getItem('th3_api_key') || ''
                                            },
                                            body: JSON.stringify({
                                                message: `[AGENT TASK] ${agentTask} (Context: Project ${activeProject?.name})`,
                                                provider: 'anythingllm',
                                                model: selectedAgent // Pass the selected workspace slug
                                            })
                                        }).catch(err => console.error("Agent trigger failed", err));

                                        setShowAgentModal(false);
                                        setAgentTask("");
                                        alert("Agent déployé. Vérifiez le moniteur.");
                                    }}
                                    className="flex-1 bg-cyan-900 text-cyan-300 border border-cyan-700 py-2 rounded hover:bg-cyan-800 transition-colors font-bold"
                                >
                                    EXÉCUTER
                                </button>
                            </div>
                        </div>
                    </div>
                )}

                {/* MAPS (Main Feature - Swapped) */}
                <div className="col-span-12 lg:col-span-8 bg-gray-900/50 border border-gray-800 rounded-lg p-1 min-h-[500px] relative group">
                    <div className="absolute top-2 left-2 bg-black/80 text-white text-xs px-2 py-1 rounded z-10 flex items-center gap-2">
                        <MapIcon size={12} /> TRAFIC / MAPS
                    </div>
                    <iframe
                        width="100%"
                        height="100%"
                        frameBorder="0"
                        style={{ border: 0, filter: 'invert(90%) hue-rotate(180deg)' }}
                        src={`https://www.google.com/maps/embed?pb=!1m14!1m12!1m3!1d44750.0!2d-73.5673!3d45.5017!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!5e0!3m2!1sen!2sca!4v1600000000000!5m2!1sen!2sca&layer=t`}
                        allowFullScreen
                    ></iframe>
                </div>

                {/* GOOGLE WIDGETS SIDEBAR */}
                <div className="col-span-12 lg:col-span-4 flex flex-col gap-6">

                    {/* CALENDAR */}
                    <div className="bg-gray-900/50 border border-purple-900/50 rounded-lg p-4 backdrop-blur">
                        <div className="flex items-center gap-2 mb-3 text-purple-400">
                            <Calendar size={16} />
                            <h3 className="font-bold text-xs tracking-wider">AGENDA</h3>
                        </div>
                        <div className="flex flex-col gap-2 max-h-48 overflow-y-auto pr-1 scrollbar-thin scrollbar-thumb-purple-900">
                            {googleData.events.length > 0 ? googleData.events.map((e, i) => (
                                <div key={i} className="text-xs bg-black/40 p-2 rounded border-l-2 border-purple-500">
                                    <div className="font-bold text-gray-300">{e.summary}</div>
                                    <div className="text-gray-500">{new Date(e.start.dateTime || e.start.date).toLocaleString()}</div>
                                </div>
                            )) : <div className="text-xs text-gray-500 italic">Rien de prévu.</div>}
                        </div>
                    </div>

                    {/* TASKS */}
                    <div className="bg-gray-900/50 border border-blue-900/50 rounded-lg p-4 backdrop-blur">
                        <div className="flex items-center gap-2 mb-3 text-blue-400">
                            <CheckCircle size={16} />
                            <h3 className="font-bold text-xs tracking-wider">GOOGLE TASKS</h3>
                        </div>
                        <div className="flex flex-col gap-2 max-h-48 overflow-y-auto pr-1 scrollbar-thin scrollbar-thumb-blue-900">
                            {googleData.tasks.length > 0 ? googleData.tasks.map((t, i) => (
                                <div key={i} className="text-xs flex items-start gap-2">
                                    <input type="checkbox" className="mt-0.5" readOnly />
                                    <span className="text-gray-300">{t.title}</span>
                                </div>
                            )) : <div className="text-xs text-gray-500 italic">Tout est fait.</div>}
                        </div>
                    </div>

                    {/* EMAILS */}
                    <div className="bg-gray-900/50 border border-red-900/50 rounded-lg p-4 backdrop-blur">
                        <div className="flex items-center gap-2 mb-3 text-red-400">
                            <Mail size={16} />
                            <h3 className="font-bold text-xs tracking-wider">GMAIL (Non lus)</h3>
                        </div>
                        <div className="flex flex-col gap-2 max-h-48 overflow-y-auto pr-1 scrollbar-thin scrollbar-thumb-red-900">
                            {googleData.emails.length > 0 ? googleData.emails.map((e, i) => (
                                <div key={i} className="text-xs bg-black/40 p-2 rounded border border-gray-800 hover:border-red-900 transition-colors">
                                    <div className="font-bold text-gray-200 truncate">{e.from}</div>
                                    <div className="text-gray-400 truncate">{e.subject}</div>
                                </div>
                            )) : <div className="text-xs text-gray-500 italic">Boîte de réception vide.</div>}
                        </div>
                    </div>

                    {/* DRIVE */}
                    <div className="bg-gray-900/50 border border-green-900/50 rounded-lg p-4 backdrop-blur">
                        <div className="flex items-center gap-2 mb-3 text-green-400">
                            <FileText size={16} />
                            <h3 className="font-bold text-xs tracking-wider">DRIVE (Récents)</h3>
                        </div>
                        <div className="flex flex-col gap-2 max-h-48 overflow-y-auto pr-1 scrollbar-thin scrollbar-thumb-green-900">
                            {googleData.files.length > 0 ? googleData.files.map((f, i) => (
                                <a key={i} href={f.webViewLink} target="_blank" rel="noopener noreferrer" className="text-xs flex items-center gap-2 text-gray-400 hover:text-green-400 transition-colors">
                                    <FileText size={12} />
                                    <span className="truncate">{f.name}</span>
                                </a>
                            )) : <div className="text-xs text-gray-500 italic">Aucun fichier récent.</div>}
                        </div>
                    </div>

                </div>

                {/* KANBAN BOARD (Bottom Full Width) */}
                {
                    activeProject ? (
                        <div className="col-span-12 grid grid-cols-3 gap-4 h-fit">
                            {renderColumn("À FAIRE", 'todo', <Circle size={16} className="text-gray-500" />)}
                            {renderColumn("EN COURS", 'in-progress', <Loader size={16} className="text-blue-500 animate-spin-slow" />)}
                            {renderColumn("TERMINÉ", 'done', <CheckCircle size={16} className="text-green-500" />)}
                        </div>
                    ) : (
                        <div className="col-span-12 flex flex-col items-center justify-center text-gray-600 border border-dashed border-gray-800 rounded-lg min-h-[200px]">
                            <Briefcase size={48} className="mb-4 opacity-20" />
                            <p>Sélectionnez un projet pour voir les tâches.</p>
                        </div>
                    )
                }

            </div >
        </div >
    );
};

export default ProjectDashboard;
