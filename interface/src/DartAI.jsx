import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
    Target, Plus, Trash2, Edit3, CheckCircle, Circle, Clock, 
    ChevronDown, Tag, Calendar, Loader2, RefreshCw, ListTodo, 
    ChevronRight, MoreVertical, X, Check, Rocket, Sparkles, 
    BarChart3, Star, FolderKanban, Users, Settings, Inbox, 
    Layout, Filter, SortAsc, Search, ArrowRight, ExternalLink,
    LayoutGrid, List, Zap, Bell, MessageSquare, ChevronUp,
    GripVertical, Flag, Archive, Eye, Play, Pause, GitBranch
} from 'lucide-react';
import { API_URL } from './config';

const DartAI = () => {
    const [tasks, setTasks] = useState([]);
    const [googleTasks, setGoogleTasks] = useState([]);
    const [loading, setLoading] = useState(false);
    const [activeView, setActiveView] = useState('board'); // board, list, timeline
    const [selectedProject, setSelectedProject] = useState('all');
    const [showCreateModal, setShowCreateModal] = useState(false);
    const [searchQuery, setSearchQuery] = useState('');
    const [filterStatus, setFilterStatus] = useState('all');
    const [sortBy] = useState('priority');
    const [showAIPanel, setShowAIPanel] = useState(false);
    const [aiPrompt, setAiPrompt] = useState('');
    const [aiResponse, setAiResponse] = useState('');
    const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
    const [showGoogleSync] = useState(true);
    
    const [newTask, setNewTask] = useState({
        title: '',
        description: '',
        priority: 'medium',
        dueDate: '',
        status: 'todo',
        labels: [],
        assignee: 'Me'
    });

    // Projects for sidebar
    const projects = [
        { id: 'all', name: 'All Tasks', icon: Inbox, color: 'purple' },
        { id: 'security', name: 'Security Research', icon: Target, color: 'red' },
        { id: 'development', name: 'Development', icon: GitBranch, color: 'blue' },
        { id: 'osint', name: 'OSINT Projects', icon: Search, color: 'green' },
        { id: 'personal', name: 'Personal', icon: Star, color: 'yellow' }
    ];

    // Load tasks on mount
    useEffect(() => {
        loadTasks();
        loadGoogleTasks();
    }, []);

    const loadTasks = async () => {
        setLoading(true);
        try {
            const res = await fetch(`${API_URL}/api/dart/tasks`);
            const data = await res.json();
            if (data.success) {
                setTasks(data.tasks);
            }
        } catch (error) {
            console.error('Failed to load tasks:', error);
        } finally {
            setLoading(false);
        }
    };

    const loadGoogleTasks = async () => {
        try {
            const res = await fetch(`${API_URL}/google/tasks?email=th3thirty3@gmail.com`);
            const data = await res.json();
            if (data.tasks) {
                setGoogleTasks(data.tasks.slice(0, 5)); // Show top 5 Google Tasks
            }
        } catch (error) {
            console.error('Failed to load Google Tasks:', error);
        }
    };

    const createTask = async (e) => {
        e?.preventDefault();
        if (!newTask.title.trim()) return;

        setLoading(true);
        try {
            const res = await fetch(`${API_URL}/api/dart/tasks/create`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(newTask)
            });
            const data = await res.json();
            if (data.success) {
                setNewTask({ title: '', description: '', priority: 'medium', dueDate: '', status: 'todo', labels: [], assignee: 'Me' });
                setShowCreateModal(false);
                loadTasks();
            }
        } catch (error) {
            console.error('Failed to create task:', error);
        } finally {
            setLoading(false);
        }
    };

    const toggleTaskStatus = async (taskId, currentStatus) => {
        const newStatus = currentStatus === 'completed' ? 'todo' : 'completed';
        try {
            const res = await fetch(`${API_URL}/api/dart/tasks/${taskId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: newStatus })
            });
            const data = await res.json();
            if (data.success) {
                setTasks(prev => prev.map(t => 
                    (t.id === taskId || t.dart_id === taskId)
                        ? { ...t, status: newStatus }
                        : t
                ));
            }
        } catch (error) {
            console.error('Failed to toggle task status:', error);
        }
    };

    const breakdownWithAI = async () => {
        if (!aiPrompt.trim()) return;
        setLoading(true);
        try {
            const res = await fetch(`${API_URL}/api/dart/tasks/breakdown`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ taskDescription: aiPrompt })
            });
            const data = await res.json();
            if (data.success) {
                setAiResponse(data.breakdown);
            }
        } catch (error) {
            console.error('Failed to breakdown task:', error);
        } finally {
            setLoading(false);
        }
    };

    // Filter and sort tasks
    const filteredTasks = tasks.filter(task => {
        const matchesSearch = task.title?.toLowerCase().includes(searchQuery.toLowerCase());
        const matchesFilter = filterStatus === 'all' || task.status === filterStatus;
        return matchesSearch && matchesFilter;
    }).sort((a, b) => {
        if (sortBy === 'priority') {
            const priorityOrder = { high: 0, medium: 1, low: 2 };
            return (priorityOrder[a.priority] || 1) - (priorityOrder[b.priority] || 1);
        }
        if (sortBy === 'date') {
            return new Date(a.dueDate || '9999') - new Date(b.dueDate || '9999');
        }
        return 0;
    });

    // Group tasks by status for Kanban
    const tasksByStatus = {
        todo: filteredTasks.filter(t => t.status === 'todo' || !t.status),
        in_progress: filteredTasks.filter(t => t.status === 'in_progress'),
        completed: filteredTasks.filter(t => t.status === 'completed')
    };

    const getPriorityColor = (priority) => {
        switch(priority) {
            case 'high': return 'text-red-400 bg-red-500/10 border-red-500/30';
            case 'medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
            case 'low': return 'text-green-400 bg-green-500/10 border-green-500/30';
            default: return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
        }
    };

    // Task Card Component
    const TaskCard = ({ task, compact = false }) => (
        <div 
            className={`group bg-gray-900/80 hover:bg-gray-800/90 border border-gray-700/50 hover:border-purple-500/40 rounded-xl transition-all cursor-pointer ${compact ? 'p-3' : 'p-4'}`}
            onClick={() => toggleTaskStatus(task.id || task.dart_id, task.status)}
        >
            <div className="flex items-start gap-3">
                <button 
                    className="mt-0.5 flex-shrink-0"
                    onClick={(e) => {
                        e.stopPropagation();
                        toggleTaskStatus(task.id || task.dart_id, task.status);
                    }}
                >
                    {task.status === 'completed' ? (
                        <CheckCircle size={18} className="text-green-400" />
                    ) : task.status === 'in_progress' ? (
                        <Play size={18} className="text-blue-400" />
                    ) : (
                        <Circle size={18} className="text-gray-500 group-hover:text-purple-400 transition-colors" />
                    )}
                </button>
                <div className="flex-1 min-w-0">
                    <h4 className={`font-medium text-sm leading-tight ${task.status === 'completed' ? 'text-gray-500 line-through' : 'text-white'}`}>
                        {task.title}
                    </h4>
                    {!compact && task.description && (
                        <p className="text-xs text-gray-500 mt-1 line-clamp-2">{task.description}</p>
                    )}
                    <div className="flex items-center gap-2 mt-2 flex-wrap">
                        <span className={`text-[10px] px-2 py-0.5 rounded-full border font-medium ${getPriorityColor(task.priority)}`}>
                            {(task.priority || 'MEDIUM').toUpperCase()}
                        </span>
                        {task.dueDate && (
                            <span className="text-[10px] text-gray-500 flex items-center gap-1">
                                <Calendar size={10} />
                                {new Date(task.dueDate).toLocaleDateString()}
                            </span>
                        )}
                    </div>
                </div>
                <div className="opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1">
                    <button className="p-1 hover:bg-gray-700 rounded"><MoreVertical size={14} /></button>
                </div>
            </div>
        </div>
    );

    // Kanban Column Component
    const KanbanColumn = ({ title, status, tasks, color, icon: Icon }) => (
        <div className="flex-1 min-w-[300px] max-w-[350px]">
            <div className={`flex items-center gap-2 mb-4 pb-2 border-b border-${color}-500/30`}>
                <Icon size={16} className={`text-${color}-400`} />
                <h3 className="font-semibold text-sm text-white">{title}</h3>
                <span className="text-xs text-gray-500 bg-gray-800 px-2 py-0.5 rounded-full">{tasks.length}</span>
            </div>
            <div className="space-y-2 min-h-[200px]">
                {tasks.map((task, idx) => (
                    <TaskCard key={task.id || task.dart_id || idx} task={task} />
                ))}
                {tasks.length === 0 && (
                    <div className="text-center py-8 text-gray-600 text-sm">
                        No tasks
                    </div>
                )}
            </div>
        </div>
    );

    return (
        <div className="flex h-full bg-gray-950 text-white overflow-hidden">
            {/* Sidebar */}
            <div className={`${sidebarCollapsed ? 'w-16' : 'w-64'} bg-gray-900/50 border-r border-gray-800 flex flex-col transition-all duration-300`}>
                {/* Sidebar Header */}
                <div className="p-4 border-b border-gray-800">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-purple-500 to-cyan-500 flex items-center justify-center">
                                <Rocket size={18} className="text-white" />
                            </div>
                            {!sidebarCollapsed && (
                                <div>
                                    <h1 className="font-bold text-lg bg-gradient-to-r from-purple-400 to-cyan-400 bg-clip-text text-transparent">
                                        DART
                                    </h1>
                                </div>
                            )}
                        </div>
                        <button 
                            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
                            className="p-1.5 hover:bg-gray-800 rounded-lg transition-colors"
                        >
                            {sidebarCollapsed ? <ChevronRight size={16} /> : <ChevronDown size={16} />}
                        </button>
                    </div>
                </div>

                {/* Quick Actions */}
                {!sidebarCollapsed && (
                    <div className="p-3">
                        <button 
                            onClick={() => setShowCreateModal(true)}
                            className="w-full flex items-center gap-2 px-3 py-2.5 bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 rounded-lg font-medium text-sm transition-all"
                        >
                            <Plus size={16} />
                            New Task
                        </button>
                    </div>
                )}

                {/* Navigation */}
                <nav className="flex-1 p-2 space-y-1 overflow-y-auto">
                    {projects.map(project => (
                        <button
                            key={project.id}
                            onClick={() => setSelectedProject(project.id)}
                            className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-all ${
                                selectedProject === project.id 
                                    ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30' 
                                    : 'text-gray-400 hover:bg-gray-800 hover:text-white'
                            }`}
                        >
                            <project.icon size={16} className={selectedProject === project.id ? `text-${project.color}-400` : ''} />
                            {!sidebarCollapsed && project.name}
                        </button>
                    ))}
                </nav>

                {/* Google Tasks Sync Section */}
                {!sidebarCollapsed && showGoogleSync && (
                    <div className="p-3 border-t border-gray-800">
                        <div className="flex items-center justify-between mb-2">
                            <span className="text-xs font-medium text-gray-500 uppercase tracking-wide">Google Tasks</span>
                            <Link to="/google" className="text-xs text-purple-400 hover:text-purple-300 flex items-center gap-1">
                                View All <ExternalLink size={10} />
                            </Link>
                        </div>
                        <div className="space-y-1">
                            {googleTasks.slice(0, 3).map((task, idx) => (
                                <div key={idx} className="flex items-center gap-2 p-2 bg-gray-800/50 rounded-lg text-xs">
                                    <Circle size={12} className="text-red-400" />
                                    <span className="truncate text-gray-300">{task.title}</span>
                                </div>
                            ))}
                            {googleTasks.length === 0 && (
                                <div className="text-xs text-gray-600 text-center py-2">No Google Tasks</div>
                            )}
                        </div>
                    </div>
                )}

                {/* AI Assistant Button */}
                {!sidebarCollapsed && (
                    <div className="p-3 border-t border-gray-800">
                        <button 
                            onClick={() => setShowAIPanel(!showAIPanel)}
                            className="w-full flex items-center gap-2 px-3 py-2 bg-gradient-to-r from-purple-900/50 to-cyan-900/50 hover:from-purple-800/50 hover:to-cyan-800/50 border border-purple-500/30 rounded-lg text-sm transition-all"
                        >
                            <Sparkles size={16} className="text-purple-400" />
                            <span>AI Assistant</span>
                        </button>
                    </div>
                )}
            </div>

            {/* Main Content */}
            <div className="flex-1 flex flex-col overflow-hidden">
                {/* Top Bar */}
                <div className="h-14 border-b border-gray-800 flex items-center justify-between px-6 bg-gray-900/30">
                    <div className="flex items-center gap-4">
                        <h2 className="font-semibold text-lg">
                            {projects.find(p => p.id === selectedProject)?.name || 'All Tasks'}
                        </h2>
                        <div className="flex items-center gap-1 bg-gray-800 rounded-lg p-1">
                            {[
                                { id: 'board', icon: LayoutGrid, label: 'Board' },
                                { id: 'list', icon: List, label: 'List' }
                            ].map(view => (
                                <button
                                    key={view.id}
                                    onClick={() => setActiveView(view.id)}
                                    className={`p-1.5 rounded-md transition-all ${
                                        activeView === view.id ? 'bg-purple-600 text-white' : 'text-gray-400 hover:text-white'
                                    }`}
                                    title={view.label}
                                >
                                    <view.icon size={16} />
                                </button>
                            ))}
                        </div>
                    </div>

                    <div className="flex items-center gap-3">
                        {/* Search */}
                        <div className="relative">
                            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                            <input
                                type="text"
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                placeholder="Search tasks..."
                                className="w-48 pl-9 pr-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-sm focus:border-purple-500 outline-none"
                            />
                        </div>

                        {/* Filter */}
                        <select
                            value={filterStatus}
                            onChange={(e) => setFilterStatus(e.target.value)}
                            className="px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-sm focus:border-purple-500 outline-none"
                        >
                            <option value="all">All Status</option>
                            <option value="todo">To Do</option>
                            <option value="in_progress">In Progress</option>
                            <option value="completed">Completed</option>
                        </select>

                        {/* Refresh */}
                        <button 
                            onClick={loadTasks}
                            disabled={loading}
                            className="p-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
                        >
                            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
                        </button>
                    </div>
                </div>

                {/* Content Area */}
                <div className="flex-1 overflow-auto p-6">
                    {/* AI Panel */}
                    {showAIPanel && (
                        <div className="mb-6 bg-gradient-to-br from-purple-900/20 to-cyan-900/20 border border-purple-500/30 rounded-xl p-5">
                            <div className="flex items-center justify-between mb-4">
                                <div className="flex items-center gap-3">
                                    <div className="w-10 h-10 rounded-full bg-gradient-to-br from-purple-500 to-cyan-500 flex items-center justify-center">
                                        <Sparkles size={20} className="text-white" />
                                    </div>
                                    <div>
                                        <h3 className="font-bold">AI Task Breakdown</h3>
                                        <p className="text-xs text-gray-400">Describe your goal and let AI create subtasks</p>
                                    </div>
                                </div>
                                <button onClick={() => setShowAIPanel(false)} className="p-1 hover:bg-gray-800 rounded">
                                    <X size={16} />
                                </button>
                            </div>
                            <textarea
                                value={aiPrompt}
                                onChange={(e) => setAiPrompt(e.target.value)}
                                placeholder="E.g., Build a security audit workflow for web applications..."
                                className="w-full bg-black/50 border border-purple-500/30 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:border-purple-500 outline-none mb-3 h-24 resize-none text-sm"
                            />
                            <button
                                onClick={breakdownWithAI}
                                disabled={loading || !aiPrompt.trim()}
                                className="px-4 py-2 bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 rounded-lg font-medium text-sm transition-all disabled:opacity-50"
                            >
                                {loading ? 'Analyzing...' : '✨ Generate Breakdown'}
                            </button>
                            {aiResponse && (
                                <div className="mt-4 bg-black/50 border border-purple-500/20 rounded-lg p-4">
                                    <pre className="text-sm text-gray-300 whitespace-pre-wrap font-mono">{aiResponse}</pre>
                                </div>
                            )}
                        </div>
                    )}

                    {/* Stats Row */}
                    <div className="grid grid-cols-4 gap-4 mb-6">
                        {[
                            { label: 'Total Tasks', value: tasks.length, icon: ListTodo, color: 'purple' },
                            { label: 'To Do', value: tasksByStatus.todo.length, icon: Circle, color: 'gray' },
                            { label: 'In Progress', value: tasksByStatus.in_progress.length, icon: Play, color: 'blue' },
                            { label: 'Completed', value: tasksByStatus.completed.length, icon: CheckCircle, color: 'green' }
                        ].map((stat, idx) => (
                            <div key={idx} className="bg-gray-900/50 border border-gray-800 rounded-xl p-4">
                                <div className="flex items-center justify-between">
                                    <div>
                                        <p className="text-xs text-gray-500">{stat.label}</p>
                                        <p className="text-2xl font-bold mt-1">{stat.value}</p>
                                    </div>
                                    <div className={`w-10 h-10 rounded-lg bg-${stat.color}-500/10 flex items-center justify-center`}>
                                        <stat.icon size={20} className={`text-${stat.color}-400`} />
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* Board View */}
                    {activeView === 'board' && (
                        <div className="flex gap-6 overflow-x-auto pb-4">
                            <KanbanColumn title="To Do" status="todo" tasks={tasksByStatus.todo} color="gray" icon={Circle} />
                            <KanbanColumn title="In Progress" status="in_progress" tasks={tasksByStatus.in_progress} color="blue" icon={Play} />
                            <KanbanColumn title="Completed" status="completed" tasks={tasksByStatus.completed} color="green" icon={CheckCircle} />
                        </div>
                    )}

                    {/* List View */}
                    {activeView === 'list' && (
                        <div className="bg-gray-900/50 border border-gray-800 rounded-xl overflow-hidden">
                            <div className="grid grid-cols-12 gap-4 p-3 bg-gray-800/50 text-xs font-medium text-gray-400 uppercase tracking-wide">
                                <div className="col-span-1">Status</div>
                                <div className="col-span-5">Task</div>
                                <div className="col-span-2">Priority</div>
                                <div className="col-span-2">Due Date</div>
                                <div className="col-span-2">Actions</div>
                            </div>
                            <div className="divide-y divide-gray-800">
                                {filteredTasks.map((task, idx) => (
                                    <div key={task.id || task.dart_id || idx} className="grid grid-cols-12 gap-4 p-3 hover:bg-gray-800/30 transition-colors items-center">
                                        <div className="col-span-1">
                                            <button onClick={() => toggleTaskStatus(task.id || task.dart_id, task.status)}>
                                                {task.status === 'completed' ? (
                                                    <CheckCircle size={18} className="text-green-400" />
                                                ) : (
                                                    <Circle size={18} className="text-gray-500 hover:text-purple-400 transition-colors" />
                                                )}
                                            </button>
                                        </div>
                                        <div className="col-span-5">
                                            <p className={`font-medium text-sm ${task.status === 'completed' ? 'text-gray-500 line-through' : 'text-white'}`}>
                                                {task.title}
                                            </p>
                                            {task.description && <p className="text-xs text-gray-500 truncate">{task.description}</p>}
                                        </div>
                                        <div className="col-span-2">
                                            <span className={`text-xs px-2 py-1 rounded-full border ${getPriorityColor(task.priority)}`}>
                                                {(task.priority || 'Medium').toUpperCase()}
                                            </span>
                                        </div>
                                        <div className="col-span-2 text-sm text-gray-400">
                                            {task.dueDate ? new Date(task.dueDate).toLocaleDateString() : '-'}
                                        </div>
                                        <div className="col-span-2 flex items-center gap-2">
                                            <button className="p-1.5 hover:bg-gray-700 rounded transition-colors">
                                                <Edit3 size={14} className="text-gray-400" />
                                            </button>
                                            <button className="p-1.5 hover:bg-gray-700 rounded transition-colors">
                                                <Trash2 size={14} className="text-gray-400" />
                                            </button>
                                        </div>
                                    </div>
                                ))}
                                {filteredTasks.length === 0 && (
                                    <div className="text-center py-12 text-gray-500">
                                        <ListTodo size={48} className="mx-auto mb-3 opacity-50" />
                                        <p>No tasks found</p>
                                    </div>
                                )}
                            </div>
                        </div>
                    )}
                </div>
            </div>

            {/* Create Task Modal */}
            {showCreateModal && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50">
                    <div className="bg-gray-900 border border-gray-700 rounded-2xl w-full max-w-lg p-6 shadow-2xl">
                        <div className="flex items-center justify-between mb-6">
                            <h2 className="text-xl font-bold">Create New Task</h2>
                            <button onClick={() => setShowCreateModal(false)} className="p-2 hover:bg-gray-800 rounded-lg">
                                <X size={20} />
                            </button>
                        </div>
                        <form onSubmit={createTask} className="space-y-4">
                            <div>
                                <label className="text-xs font-medium text-gray-400 uppercase tracking-wide mb-1 block">Title</label>
                                <input
                                    type="text"
                                    value={newTask.title}
                                    onChange={(e) => setNewTask({ ...newTask, title: e.target.value })}
                                    placeholder="What needs to be done?"
                                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:border-purple-500 outline-none"
                                    autoFocus
                                />
                            </div>
                            <div>
                                <label className="text-xs font-medium text-gray-400 uppercase tracking-wide mb-1 block">Description</label>
                                <textarea
                                    value={newTask.description}
                                    onChange={(e) => setNewTask({ ...newTask, description: e.target.value })}
                                    placeholder="Add more details..."
                                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:border-purple-500 outline-none h-24 resize-none"
                                />
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="text-xs font-medium text-gray-400 uppercase tracking-wide mb-1 block">Priority</label>
                                    <select
                                        value={newTask.priority}
                                        onChange={(e) => setNewTask({ ...newTask, priority: e.target.value })}
                                        className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white focus:border-purple-500 outline-none"
                                    >
                                        <option value="low">🟢 Low</option>
                                        <option value="medium">🟡 Medium</option>
                                        <option value="high">🔴 High</option>
                                    </select>
                                </div>
                                <div>
                                    <label className="text-xs font-medium text-gray-400 uppercase tracking-wide mb-1 block">Due Date</label>
                                    <input
                                        type="date"
                                        value={newTask.dueDate}
                                        onChange={(e) => setNewTask({ ...newTask, dueDate: e.target.value })}
                                        className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white focus:border-purple-500 outline-none"
                                    />
                                </div>
                            </div>
                            <div className="flex justify-end gap-3 pt-4">
                                <button
                                    type="button"
                                    onClick={() => setShowCreateModal(false)}
                                    className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg font-medium transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={loading || !newTask.title.trim()}
                                    className="px-6 py-2 bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 rounded-lg font-medium transition-all disabled:opacity-50"
                                >
                                    Create Task
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default DartAI;
