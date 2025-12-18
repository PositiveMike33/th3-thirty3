import React, { useState, useEffect } from 'react';
import { Target, Plus, Trash2, Edit3, CheckCircle, Circle, AlertTriangle, Clock, Filter, ChevronDown, Tag, Calendar, User, Loader2, RefreshCw, ArrowUpDown, ListTodo, ChevronRight, MoreVertical, X, Check, Rocket, Sparkles, BarChart3, Star } from 'lucide-react';
import { API_URL } from './config';

const DartAI = () => {
    const [tasks, setTasks] = useState([]);
    const [loading, setLoading] = useState(false);
    const [activeTab, setActiveTab] = useState('tasks'); // tasks, planning, analytics
    const [newTask, setNewTask] = useState({
        title: '',
        description: '',
        priority: 'medium',
        dueDate: ''
    });
    const [showAIPanel, setShowAIPanel] = useState(false);
    const [aiPrompt, setAiPrompt] = useState('');
    const [aiResponse, setAiResponse] = useState('');

    // Load tasks on mount
    useEffect(() => {
        loadTasks();
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

    const createTask = async (e) => {
        e.preventDefault();
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
                setNewTask({ title: '', description: '', priority: 'medium', dueDate: '' });
                loadTasks();
            }
        } catch (error) {
            console.error('Failed to create task:', error);
        } finally {
            setLoading(false);
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

    return (
        <div className="flex-1 h-full bg-gradient-to-br from-gray-950 via-purple-950/20 to-gray-950 text-white overflow-hidden flex flex-col">
            {/* Header */}
            <div className="border-b border-purple-500/20 bg-black/40 backdrop-blur-sm">
                <div className="max-w-7xl mx-auto px-6 py-4">
                    <div className="flex justify-between items-center">
                        <div className="flex items-center gap-4">
                            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500 to-cyan-500 flex items-center justify-center">
                                <Rocket className="text-white" size={24} />
                            </div>
                            <div>
                                <h1 className="text-2xl font-bold bg-gradient-to-r from-purple-400 to-cyan-400 bg-clip-text text-transparent">
                                    DART AI
                                </h1>
                                <p className="text-xs text-gray-500">AI-Native Project Management</p>
                            </div>
                        </div>
                        <div className="flex items-center gap-3">
                            <button 
                                onClick={() => setShowAIPanel(!showAIPanel)}
                                className="px-4 py-2 bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 rounded-lg font-semibold flex items-center gap-2 transition-all shadow-lg shadow-purple-500/20"
                            >
                                <Sparkles size={16} />
                                AI Assistant
                            </button>
                            <button 
                                onClick={loadTasks}
                                disabled={loading}
                                className="p-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
                            >
                                <RefreshCw size={18} className={loading ? 'animate-spin' : ''} />
                            </button>
                        </div>
                    </div>

                    {/* Navigation Tabs */}
                    <div className="flex gap-6 mt-6">
                        {[
                            { id: 'tasks', label: 'Tasks', icon: CheckCircle },
                            { id: 'planning', label: 'Planning', icon: Target },
                            { id: 'analytics', label: 'Analytics', icon: BarChart3 }
                        ].map(tab => (
                            <button
                                key={tab.id}
                                onClick={() => setActiveTab(tab.id)}
                                className={`pb-3 px-2 flex items-center gap-2 font-medium transition-all border-b-2 ${
                                    activeTab === tab.id
                                        ? 'border-purple-500 text-white'
                                        : 'border-transparent text-gray-500 hover:text-gray-300'
                                }`}
                            >
                                <tab.icon size={16} />
                                {tab.label}
                            </button>
                        ))}
                    </div>
                </div>
            </div>

            <div className="flex-1 overflow-auto">
                <div className="max-w-7xl mx-auto px-6 py-8">
                    {/* AI Assistant Panel */}
                    {showAIPanel && (
                        <div className="mb-6 bg-gradient-to-br from-purple-900/30 to-cyan-900/30 border border-purple-500/30 rounded-2xl p-6 backdrop-blur-sm">
                            <div className="flex items-center gap-3 mb-4">
                                <div className="w-10 h-10 rounded-full bg-gradient-to-br from-purple-500 to-cyan-500 flex items-center justify-center">
                                    <Sparkles className="text-white" size={20} />
                                </div>
                                <div>
                                    <h3 className="font-bold text-lg">AI Task Breakdown</h3>
                                    <p className="text-xs text-gray-400">Describe your goal and let AI create a roadmap</p>
                                </div>
                            </div>
                            <textarea
                                value={aiPrompt}
                                onChange={(e) => setAiPrompt(e.target.value)}
                                placeholder="E.g., Build a full-stack authentication system with JWT and OAuth2..."
                                className="w-full bg-black/50 border border-purple-500/30 rounded-xl px-4 py-3 text-white placeholder-gray-500 focus:border-purple-500 outline-none mb-3 h-32 resize-none"
                            />
                            <button
                                onClick={breakdownWithAI}
                                disabled={loading || !aiPrompt.trim()}
                                className="w-full py-3 bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 rounded-xl font-semibold transition-all disabled:opacity-50 shadow-lg shadow-purple-500/20"
                            >
                                {loading ? '🤖 AI is analyzing...' : '✨ Generate Task Breakdown'}
                            </button>
                            {aiResponse && (
                                <div className="mt-4 bg-black/50 border border-purple-500/20 rounded-xl p-4">
                                    <h4 className="text-sm font-bold text-purple-400 mb-2">AI Breakdown:</h4>
                                    <pre className="text-sm text-gray-300 whitespace-pre-wrap font-mono">{aiResponse}</pre>
                                </div>
                            )}
                        </div>
                    )}

                    {/* Main Content based on active tab */}
                    {activeTab === 'tasks' && (
                        <>
                            {/* Quick Create Task */}
                            <div className="bg-black/40 border border-purple-500/20 rounded-2xl p-6 mb-6 backdrop-blur-sm">
                                <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
                                    <Plus className="text-purple-400" size={20} />
                                    Quick Add Task
                                </h2>
                                <form onSubmit={createTask} className="space-y-4">
                                    <input
                                        type="text"
                                        value={newTask.title}
                                        onChange={(e) => setNewTask({ ...newTask, title: e.target.value })}
                                        placeholder="What needs to be done?"
                                        className="w-full bg-black/50 border border-purple-500/30 rounded-xl px-4 py-3 text-white placeholder-gray-500 focus:border-purple-500 outline-none"
                                    />
                                    <div className="grid grid-cols-3 gap-3">
                                        <select
                                            value={newTask.priority}
                                            onChange={(e) => setNewTask({ ...newTask, priority: e.target.value })}
                                            className="bg-black/50 border border-purple-500/30 rounded-xl px-4 py-2 text-white focus:border-purple-500 outline-none"
                                        >
                                            <option value="low">Low Priority</option>
                                            <option value="medium">Medium Priority</option>
                                            <option value="high">High Priority</option>
                                        </select>
                                        <input
                                            type="date"
                                            value={newTask.dueDate}
                                            onChange={(e) => setNewTask({ ...newTask, dueDate: e.target.value })}
                                            className="bg-black/50 border border-purple-500/30 rounded-xl px-4 py-2 text-white focus:border-purple-500 outline-none"
                                        />
                                        <button
                                            type="submit"
                                            disabled={loading || !newTask.title.trim()}
                                            className="bg-purple-600 hover:bg-purple-500 rounded-xl font-semibold transition-all disabled:opacity-50"
                                        >
                                            Add Task
                                        </button>
                                    </div>
                                </form>
                            </div>

                            {/* Task List */}
                            <div className="bg-black/40 border border-purple-500/20 rounded-2xl p-6 backdrop-blur-sm">
                                <div className="flex justify-between items-center mb-6">
                                    <h2 className="text-xl font-bold flex items-center gap-2">
                                        <CheckCircle className="text-green-400" size={20} />
                                        Active Tasks ({tasks.length})
                                    </h2>
                                    <div className="flex items-center gap-2 text-xs text-gray-500">
                                        <Calendar size={14} />
                                        Today
                                    </div>
                                </div>

                                {loading ? (
                                    <div className="text-center py-12 text-gray-500">
                                        <RefreshCw className="animate-spin mx-auto mb-3" size={32} />
                                        <p>Loading tasks...</p>
                                    </div>
                                ) : tasks.length === 0 ? (
                                    <div className="text-center py-12 text-gray-500">
                                        <Target size={48} className="mx-auto mb-4 opacity-50" />
                                        <p className="text-lg font-medium mb-2">No tasks yet</p>
                                        <p className="text-sm">Add your first task above or use AI to generate a project plan</p>
                                    </div>
                                ) : (
                                    <div className="space-y-3">
                                        {tasks.map((task, index) => (
                                            <div 
                                                key={task.id || task.dart_id || index}
                                                className="group bg-gradient-to-r from-black/60 to-purple-900/10 border border-purple-500/20 rounded-xl p-4 hover:border-purple-500/50 transition-all cursor-pointer"
                                            >
                                                <div className="flex justify-between items-start mb-2">
                                                    <div className="flex items-start gap-3 flex-1">
                                                        <div className="mt-1 w-5 h-5 rounded border-2 border-purple-500/50 group-hover:border-purple-400 transition-colors" />
                                                        <div className="flex-1">
                                                            <h3 className="font-semibold text-white group-hover:text-purple-300 transition-colors">
                                                                {task.title}
                                                            </h3>
                                                            {task.description && (
                                                                <p className="text-sm text-gray-400 mt-1">{task.description}</p>
                                                            )}
                                                        </div>
                                                    </div>
                                                    <div className="flex items-center gap-2">
                                                        <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                                                            task.priority === 'high' ? 'bg-red-500/20 text-red-300 border border-red-500/30' :
                                                            task.priority === 'medium' ? 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30' :
                                                            'bg-green-500/20 text-green-300 border border-green-500/30'
                                                        }`}>
                                                            {(task.priority || 'normal').toUpperCase()}
                                                        </span>
                                                    </div>
                                                </div>
                                                <div className="flex justify-between items-center text-xs text-gray-500 mt-3">
                                                    <span className="flex items-center gap-1">
                                                        <Star size={12} className="text-purple-400" />
                                                        {task.status || 'todo'}
                                                    </span>
                                                    {task.dueDate && (
                                                        <span className="flex items-center gap-1">
                                                            <Calendar size={12} />
                                                            {new Date(task.dueDate).toLocaleDateString()}
                                                        </span>
                                                    )}
                                                    <span className="opacity-50">#{(task.id || task.dart_id || 'N/A').slice(0, 6)}</span>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </>
                    )}

                    {activeTab === 'planning' && (
                        <div className="bg-black/40 border border-purple-500/20 rounded-2xl p-12 text-center backdrop-blur-sm">
                            <Target size={64} className="mx-auto mb-4 text-purple-400 opacity-50" />
                            <h3 className="text-2xl font-bold mb-2">Project Planning</h3>
                            <p className="text-gray-400">Advanced planning features coming soon...</p>
                        </div>
                    )}

                    {activeTab === 'analytics' && (
                        <div className="bg-black/40 border border-purple-500/20 rounded-2xl p-12 text-center backdrop-blur-sm">
                            <BarChart3 size={64} className="mx-auto mb-4 text-cyan-400 opacity-50" />
                            <h3 className="text-2xl font-bold mb-2">Analytics Dashboard</h3>
                            <p className="text-gray-400">Team performance metrics coming soon...</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default DartAI;
