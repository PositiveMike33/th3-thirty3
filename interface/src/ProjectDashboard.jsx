import React, { useState, useEffect } from 'react';
import {
    Briefcase, Plus, Trash2, CheckCircle, Circle,
    ArrowRight, Layout, Terminal, Loader, Save,
    Calendar, Mail, Folder, Map as MapIcon, RefreshCw, TrendingUp
} from 'lucide-react';
import ModelIntelligenceDashboard from './components/ModelIntelligenceDashboard';
import { API_URL } from './config';

const ProjectDashboard = () => {
    // Project State
    const [_projects, setProjects] = useState([]);
    const [activeProject, setActiveProject] = useState(null);
    // const [loading, setLoading] = useState(false); // Unused
    // const [loading, setLoading] = useState(false); // Removed unused state
    // Sidebar was removed - these states are kept for potential future use
     
    const [_showNewProjectInput, _setShowNewProjectInput] = useState(false);
     
    const [_newProjectName, _setNewProjectName] = useState("");
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

    const fetchAgents = React.useCallback(async () => {
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
    }, [selectedAgent]);

    const fetchProjects = React.useCallback(async () => {
        try {
            const res = await fetch(`${API_URL}/projects`);
            const data = await res.json();
            // Ensure data is an array before setting
            const projectsArray = Array.isArray(data) ? data : (data.projects || []);
            setProjects(projectsArray);
            setActiveProject(current => {
                if (current) {
                    const updated = projectsArray.find(p => p.id === current.id);
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
        let isMounted = true;
        
        const initData = async () => {
            if (isMounted) {
                await fetchGoogleData();
                await fetchAgents();
            }
        };
        
        initData();

        // Real-time refresh every 30s
        const interval = setInterval(() => {
            if (isMounted) fetchGoogleData();
        }, 30000);
        
        return () => {
            isMounted = false;
            clearInterval(interval);
        };
    }, [fetchGoogleData, fetchAgents]);

    // --- PROJECT ACTIONS ---

    // Project CRUD functions - kept for API but sidebar removed
     
    const _handleCreateProject = async (name) => {
        if (!name?.trim()) return;
        try {
            const res = await fetch(`${API_URL}/projects`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, description: "New Project" })
            });
            const project = await res.json();
            setProjects(prev => [...prev, project]);
            setActiveProject(project);
        } catch (error) {
            console.error("Error creating project:", error);
        }
    };

     
    const _handleDeleteProject = async (id) => {
        if (!confirm("Supprimer ce projet ?")) return;
        try {
            await fetch(`${API_URL}/projects/${id}`, { method: 'DELETE' });
            setProjects(prev => prev.filter(p => p.id !== id));
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
        <div 
            className="flex flex-col w-full bg-transparent text-cyan-300 overflow-hidden"
            style={{ height: 'calc(100vh - 130px)' }}
        >
            {/* HEADER - Fixed height */}
            <div className="flex justify-between items-end border-b border-gray-800 p-4 flex-shrink-0">
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

            {/* MAIN CONTENT - Takes remaining height */}
            <div 
                className="flex gap-4 p-4"
                style={{ height: 'calc(100vh - 200px)' }}
            >

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

                {/* MAPS (75% Width) */}
                <div 
                    className="bg-gray-900/50 border border-gray-800 rounded-lg relative group overflow-hidden shadow-2xl shadow-black"
                    style={{ width: '75%', height: '100%' }}
                >
                    <div className="absolute top-2 left-2 bg-black/80 text-white text-xs px-2 py-1 rounded z-10 flex items-center gap-2 border border-gray-700">
                        <MapIcon size={12} /> TRAFIC / MAPS
                    </div>
                    <iframe
                        className="absolute inset-0 w-full h-full"
                        style={{ border: 0 }}
                        allowFullScreen
                        loading="lazy"
                        referrerPolicy="no-referrer-when-downgrade"
                        src="https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d178794.6234978716!2d-73.711873!3d45.5576996!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x4cc91a541c64b70d%3A0x654e3138211fefef!2sMontr%C3%A9al%2C%20QC!5e0!3m2!1sen!2sca!4v1709848293000!5m2!1sen!2sca"
                    ></iframe>
                </div>

                {/* RIGHT SIDEBAR - Model Progress + Google Widgets (25% Width) */}
                <div 
                    className="flex flex-col gap-3 overflow-hidden"
                    style={{ width: '25%', height: '100%' }}
                >

                    {/* MODEL INTELLIGENCE DASHBOARD - Main Feature */}
                    <div className="bg-gray-900/50 border border-cyan-900/50 rounded-lg p-4 backdrop-blur flex-1 overflow-hidden flex flex-col min-h-[300px]">
                        <ModelIntelligenceDashboard />
                    </div>

                    {/* CALENDAR - Compact */}
                    <div className="bg-gray-900/50 border border-purple-900/50 rounded-lg p-3 backdrop-blur overflow-hidden flex flex-col max-h-[150px]">
                        <div className="flex items-center gap-2 mb-2 text-purple-400 shrink-0">
                            <Calendar size={14} />
                            <h3 className="font-bold text-xs tracking-wider">AGENDA</h3>
                            <span className="ml-auto text-xs text-gray-500">{googleData.events.length}</span>
                        </div>
                        <div className="flex flex-col gap-1 overflow-y-auto pr-1 scrollbar-thin scrollbar-thumb-purple-900 flex-1">
                            {googleData.events.length > 0 ? googleData.events.slice(0, 3).map((e, i) => (
                                <div key={i} className="text-xs bg-black/40 p-2 rounded border-l-2 border-purple-500">
                                    <div className="font-bold text-gray-300 truncate">{e.summary}</div>
                                    <div className="text-gray-500 text-xs">{new Date(e.start.dateTime || e.start.date).toLocaleDateString()}</div>
                                </div>
                            )) : <div className="text-xs text-gray-500 italic">Rien de prévu.</div>}
                        </div>
                    </div>

                    {/* EMAILS - Compact */}
                    <div className="bg-gray-900/50 border border-red-900/50 rounded-lg p-3 backdrop-blur overflow-hidden flex flex-col max-h-[150px]">
                        <div className="flex items-center gap-2 mb-2 text-red-400 shrink-0">
                            <Mail size={14} />
                            <h3 className="font-bold text-xs tracking-wider">GMAIL</h3>
                            <span className="ml-auto text-xs text-gray-500">{googleData.emails.length}</span>
                        </div>
                        <div className="flex flex-col gap-1 overflow-y-auto pr-1 scrollbar-thin scrollbar-thumb-red-900 flex-1">
                            {googleData.emails.length > 0 ? googleData.emails.slice(0, 3).map((e, i) => (
                                <div key={i} className="text-xs bg-black/40 p-1.5 rounded border border-gray-800 hover:border-red-900 transition-colors">
                                    <div className="font-bold text-gray-200 truncate text-xs">{e.from}</div>
                                    <div className="text-gray-400 truncate text-xs">{e.subject}</div>
                                </div>
                            )) : <div className="text-xs text-gray-500 italic">Boîte vide.</div>}
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
