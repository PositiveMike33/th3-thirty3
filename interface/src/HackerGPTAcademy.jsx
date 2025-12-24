import { useState, useEffect, useCallback } from 'react';
import { 
    GraduationCap, Trophy, Target, Clock, Play, CheckCircle, 
    XCircle, Star, Award, Zap, BookOpen, Code, Shield, 
    Terminal, Users, TrendingUp, ArrowRight, RefreshCw,
    Brain, Crosshair, FileText, AlertTriangle
} from 'lucide-react';
import { API_URL } from './config';

export default function HackerGPTAcademy() {
    const [activeTab, setActiveTab] = useState('dashboard');
    const [modules, setModules] = useState([]);
    const [userProgress, setUserProgress] = useState(null);
    const [leaderboard, setLeaderboard] = useState([]);
    const [academyStatus, setAcademyStatus] = useState(null);
    const [currentSession, setCurrentSession] = useState(null);
    const [currentExercise, setCurrentExercise] = useState(null);
    const [answer, setAnswer] = useState('');
    const [feedback, setFeedback] = useState(null);
    const [loading, setLoading] = useState(false);
    const [challenge, setChallenge] = useState(null);
    const [labs, setLabs] = useState([]);

    const userId = 'user_' + (localStorage.getItem('userId') || 'default');

    // Load academy data
    const loadData = useCallback(async () => {
        try {
            const [statusRes, modulesRes, progressRes, leaderboardRes, labsRes] = await Promise.all([
                fetch(`${API_URL}/api/hackergpt-academy/status`),
                fetch(`${API_URL}/api/hackergpt-academy/modules`),
                fetch(`${API_URL}/api/hackergpt-academy/progress/${userId}`),
                fetch(`${API_URL}/api/hackergpt-academy/leaderboard`),
                fetch(`${API_URL}/api/hackergpt-academy/labs`)
            ]);

            const status = await statusRes.json();
            const modulesData = await modulesRes.json();
            const progress = await progressRes.json();
            const lb = await leaderboardRes.json();
            const labsData = await labsRes.json();

            if (status.success) setAcademyStatus(status);
            if (modulesData.success) setModules(modulesData.modules);
            if (progress.success) setUserProgress(progress);
            if (lb.success) setLeaderboard(lb.leaderboard);
            if (labsData.success) setLabs(labsData.labs);
        } catch (error) {
            console.error('Error loading academy data:', error);
        }
    }, [userId]);

    useEffect(() => {
        let mounted = true;
        const fetchData = async () => {
            try {
                const [statusRes, modulesRes, progressRes, leaderboardRes, labsRes] = await Promise.all([
                    fetch(`${API_URL}/api/hackergpt-academy/status`),
                    fetch(`${API_URL}/api/hackergpt-academy/modules`),
                    fetch(`${API_URL}/api/hackergpt-academy/progress/${userId}`),
                    fetch(`${API_URL}/api/hackergpt-academy/leaderboard`),
                    fetch(`${API_URL}/api/hackergpt-academy/labs`)
                ]);

                if (!mounted) return;

                const status = await statusRes.json();
                const modulesData = await modulesRes.json();
                const progress = await progressRes.json();
                const lb = await leaderboardRes.json();
                const labsData = await labsRes.json();

                if (status.success) setAcademyStatus(status);
                if (modulesData.success) setModules(modulesData.modules);
                if (progress.success) setUserProgress(progress);
                if (lb.success) setLeaderboard(lb.leaderboard);
                if (labsData.success) setLabs(labsData.labs);
            } catch (error) {
                console.error('Error loading academy data:', error);
            }
        };
        fetchData();
        return () => { mounted = false; };
    }, [userId]);

    // Start training
    const startTraining = async (moduleId) => {
        setLoading(true);
        try {
            const res = await fetch(`${API_URL}/api/hackergpt-academy/training/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ userId, moduleId })
            });
            const data = await res.json();
            if (data.success) {
                setCurrentSession(data.session);
                setCurrentExercise(data.session.firstExercise);
                setActiveTab('training');
                setFeedback(null);
                setAnswer('');
            }
        } catch (error) {
            console.error('Error starting training:', error);
        }
        setLoading(false);
    };

    // Submit answer
    const submitAnswer = async () => {
        if (!currentSession || !answer.trim()) return;
        setLoading(true);
        try {
            const res = await fetch(`${API_URL}/api/hackergpt-academy/training/${currentSession.id}/submit`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ answer })
            });
            const data = await res.json();
            if (data.success) {
                setFeedback(data.evaluation);
                if (data.isComplete) {
                    setTimeout(() => {
                        setCurrentSession(null);
                        setCurrentExercise(null);
                        setActiveTab('dashboard');
                        loadData();
                    }, 5000);
                } else {
                    setCurrentExercise(data.nextExercise);
                    setAnswer('');
                }
            }
        } catch (error) {
            console.error('Error submitting:', error);
        }
        setLoading(false);
    };

    // Get random challenge
    const getRandomChallenge = async (difficulty = 'intermediate') => {
        try {
            const res = await fetch(`${API_URL}/api/hackergpt-academy/challenge/random?difficulty=${difficulty}`);
            const data = await res.json();
            if (data.success) {
                setChallenge(data.challenge);
                setActiveTab('challenge');
            }
        } catch (error) {
            console.error('Error getting challenge:', error);
        }
    };

    const getDifficultyColor = (difficulty) => {
        switch (difficulty) {
            case 'beginner': return 'bg-green-500/20 text-green-400 border-green-500/30';
            case 'intermediate': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
            case 'advanced': return 'bg-red-500/20 text-red-400 border-red-500/30';
            default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
        }
    };

    const getCategoryIcon = (category) => {
        switch (category) {
            case 'reconnaissance': return <Crosshair className="w-5 h-5" />;
            case 'exploitation': return <Zap className="w-5 h-5" />;
            case 'network': return <Shield className="w-5 h-5" />;
            case 'reporting': return <FileText className="w-5 h-5" />;
            case 'red_team': return <Target className="w-5 h-5" />;
            default: return <Code className="w-5 h-5" />;
        }
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900/20 to-gray-900 text-white p-6">
            {/* Header */}
            <div className="mb-8">
                <div className="flex items-center gap-4 mb-4">
                    <div className="p-3 bg-gradient-to-br from-purple-500 to-pink-500 rounded-xl">
                        <GraduationCap className="w-8 h-8" />
                    </div>
                    <div>
                        <h1 className="text-3xl font-bold bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">
                            HackerGPT Academy
                        </h1>
                        <p className="text-gray-400">Entraînement • Enseignement • Évaluation</p>
                    </div>
                    {academyStatus?.hackerAIConnected && (
                        <div className="ml-auto flex items-center gap-2 px-4 py-2 bg-green-500/20 border border-green-500/30 rounded-lg">
                            <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                            <span className="text-green-400 text-sm">HackerAI Connecté</span>
                        </div>
                    )}
                </div>

                {/* User Stats Bar */}
                {userProgress && (
                    <div className="grid grid-cols-5 gap-4 mb-6">
                        <div className="bg-gray-800/50 backdrop-blur rounded-xl p-4 border border-gray-700/50">
                            <div className="flex items-center gap-2 text-purple-400 mb-2">
                                <Star className="w-4 h-4" />
                                <span className="text-sm">Niveau</span>
                            </div>
                            <div className="text-2xl font-bold">{userProgress.level}</div>
                        </div>
                        <div className="bg-gray-800/50 backdrop-blur rounded-xl p-4 border border-gray-700/50">
                            <div className="flex items-center gap-2 text-yellow-400 mb-2">
                                <Trophy className="w-4 h-4" />
                                <span className="text-sm">XP Total</span>
                            </div>
                            <div className="text-2xl font-bold">{userProgress.totalXP}</div>
                        </div>
                        <div className="bg-gray-800/50 backdrop-blur rounded-xl p-4 border border-gray-700/50">
                            <div className="flex items-center gap-2 text-green-400 mb-2">
                                <CheckCircle className="w-4 h-4" />
                                <span className="text-sm">Modules</span>
                            </div>
                            <div className="text-2xl font-bold">{userProgress.completedModules?.length || 0}/{modules.length}</div>
                        </div>
                        <div className="bg-gray-800/50 backdrop-blur rounded-xl p-4 border border-gray-700/50">
                            <div className="flex items-center gap-2 text-blue-400 mb-2">
                                <Award className="w-4 h-4" />
                                <span className="text-sm">Rang</span>
                            </div>
                            <div className="text-lg font-bold truncate">{userProgress.rank}</div>
                        </div>
                        <div className="bg-gray-800/50 backdrop-blur rounded-xl p-4 border border-gray-700/50">
                            <div className="flex items-center gap-2 text-pink-400 mb-2">
                                <Brain className="w-4 h-4" />
                                <span className="text-sm">Sessions</span>
                            </div>
                            <div className="text-2xl font-bold">{userProgress.sessions?.length || 0}</div>
                        </div>
                    </div>
                )}

                {/* Navigation Tabs */}
                <div className="flex gap-2 mb-6">
                    {['dashboard', 'modules', 'challenges', 'labs', 'leaderboard'].map(tab => (
                        <button
                            key={tab}
                            onClick={() => setActiveTab(tab)}
                            className={`px-4 py-2 rounded-lg font-medium transition-all ${
                                activeTab === tab 
                                    ? 'bg-purple-500 text-white' 
                                    : 'bg-gray-800/50 text-gray-400 hover:bg-gray-700/50'
                            }`}
                        >
                            {tab.charAt(0).toUpperCase() + tab.slice(1)}
                        </button>
                    ))}
                </div>
            </div>

            {/* Dashboard Tab */}
            {activeTab === 'dashboard' && (
                <div className="grid grid-cols-3 gap-6">
                    {/* Quick Actions */}
                    <div className="col-span-2 space-y-6">
                        <div className="bg-gray-800/50 backdrop-blur rounded-xl p-6 border border-gray-700/50">
                            <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
                                <Zap className="w-5 h-5 text-yellow-400" />
                                Actions Rapides
                            </h2>
                            <div className="grid grid-cols-3 gap-4">
                                <button 
                                    onClick={() => getRandomChallenge('beginner')}
                                    className="p-4 bg-green-500/20 border border-green-500/30 rounded-xl hover:bg-green-500/30 transition-all text-left"
                                >
                                    <div className="text-green-400 font-bold mb-1">Challenge Facile</div>
                                    <div className="text-sm text-gray-400">Débutant • 2 min</div>
                                </button>
                                <button 
                                    onClick={() => getRandomChallenge('intermediate')}
                                    className="p-4 bg-yellow-500/20 border border-yellow-500/30 rounded-xl hover:bg-yellow-500/30 transition-all text-left"
                                >
                                    <div className="text-yellow-400 font-bold mb-1">Challenge Moyen</div>
                                    <div className="text-sm text-gray-400">Intermédiaire • 3 min</div>
                                </button>
                                <button 
                                    onClick={() => getRandomChallenge('advanced')}
                                    className="p-4 bg-red-500/20 border border-red-500/30 rounded-xl hover:bg-red-500/30 transition-all text-left"
                                >
                                    <div className="text-red-400 font-bold mb-1">Challenge Expert</div>
                                    <div className="text-sm text-gray-400">Avancé • 5 min</div>
                                </button>
                            </div>
                        </div>

                        {/* Recommended Modules */}
                        <div className="bg-gray-800/50 backdrop-blur rounded-xl p-6 border border-gray-700/50">
                            <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
                                <BookOpen className="w-5 h-5 text-purple-400" />
                                Modules Recommandés
                            </h2>
                            <div className="space-y-3">
                                {modules.slice(0, 3).map(module => (
                                    <div 
                                        key={module.id}
                                        className="flex items-center justify-between p-4 bg-gray-900/50 rounded-lg border border-gray-700/30 hover:border-purple-500/30 transition-all"
                                    >
                                        <div className="flex items-center gap-4">
                                            <div className="p-2 bg-purple-500/20 rounded-lg text-purple-400">
                                                {getCategoryIcon(module.category)}
                                            </div>
                                            <div>
                                                <div className="font-medium">{module.name}</div>
                                                <div className="text-sm text-gray-400">{module.duration} • {module.exerciseCount} exercices</div>
                                            </div>
                                        </div>
                                        <button
                                            onClick={() => startTraining(module.id)}
                                            disabled={loading}
                                            className="flex items-center gap-2 px-4 py-2 bg-purple-500/20 border border-purple-500/30 rounded-lg hover:bg-purple-500/30 transition-all"
                                        >
                                            <Play className="w-4 h-4" />
                                            Commencer
                                        </button>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>

                    {/* Sidebar */}
                    <div className="space-y-6">
                        {/* Academy Stats */}
                        <div className="bg-gray-800/50 backdrop-blur rounded-xl p-6 border border-gray-700/50">
                            <h3 className="font-bold mb-4 flex items-center gap-2">
                                <TrendingUp className="w-5 h-5 text-blue-400" />
                                Statistiques Globales
                            </h3>
                            <div className="space-y-3">
                                <div className="flex justify-between">
                                    <span className="text-gray-400">Sessions Totales</span>
                                    <span className="font-bold">{academyStatus?.globalStats?.totalSessions || 0}</span>
                                </div>
                                <div className="flex justify-between">
                                    <span className="text-gray-400">Exercices Complétés</span>
                                    <span className="font-bold">{academyStatus?.globalStats?.totalExercises || 0}</span>
                                </div>
                                <div className="flex justify-between">
                                    <span className="text-gray-400">Examens Passés</span>
                                    <span className="font-bold">{academyStatus?.globalStats?.totalExams || 0}</span>
                                </div>
                                <div className="flex justify-between">
                                    <span className="text-gray-400">Utilisateurs</span>
                                    <span className="font-bold">{academyStatus?.totalUsers || 1}</span>
                                </div>
                            </div>
                        </div>

                        {/* Mini Leaderboard */}
                        <div className="bg-gray-800/50 backdrop-blur rounded-xl p-6 border border-gray-700/50">
                            <h3 className="font-bold mb-4 flex items-center gap-2">
                                <Trophy className="w-5 h-5 text-yellow-400" />
                                Top 5
                            </h3>
                            <div className="space-y-2">
                                {leaderboard.slice(0, 5).map((user, idx) => (
                                    <div key={user.userId} className="flex items-center gap-3 p-2 bg-gray-900/30 rounded-lg">
                                        <span className={`w-6 h-6 flex items-center justify-center rounded-full text-sm font-bold ${
                                            idx === 0 ? 'bg-yellow-500 text-black' :
                                            idx === 1 ? 'bg-gray-400 text-black' :
                                            idx === 2 ? 'bg-orange-600 text-white' :
                                            'bg-gray-700 text-gray-300'
                                        }`}>{idx + 1}</span>
                                        <span className="flex-1 truncate">{user.rank}</span>
                                        <span className="text-purple-400 font-bold">{user.totalXP} XP</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Modules Tab */}
            {activeTab === 'modules' && (
                <div className="grid grid-cols-3 gap-6">
                    {modules.map(module => (
                        <div 
                            key={module.id}
                            className="bg-gray-800/50 backdrop-blur rounded-xl p-6 border border-gray-700/50 hover:border-purple-500/30 transition-all group"
                        >
                            <div className="flex items-start justify-between mb-4">
                                <div className="p-3 bg-purple-500/20 rounded-xl text-purple-400">
                                    {getCategoryIcon(module.category)}
                                </div>
                                <span className={`px-3 py-1 rounded-full text-xs font-medium border ${getDifficultyColor(module.difficulty)}`}>
                                    {module.difficulty}
                                </span>
                            </div>
                            <h3 className="text-xl font-bold mb-2">{module.name}</h3>
                            <div className="flex items-center gap-4 text-sm text-gray-400 mb-4">
                                <span className="flex items-center gap-1">
                                    <Clock className="w-4 h-4" />
                                    {module.duration}
                                </span>
                                <span className="flex items-center gap-1">
                                    <Target className="w-4 h-4" />
                                    {module.exerciseCount} exercices
                                </span>
                            </div>
                            <div className="mb-4">
                                <h4 className="text-sm font-medium text-gray-400 mb-2">Objectifs:</h4>
                                <ul className="text-sm text-gray-300 space-y-1">
                                    {module.objectives?.slice(0, 3).map((obj, i) => (
                                        <li key={i} className="flex items-start gap-2">
                                            <ArrowRight className="w-3 h-3 mt-1 text-purple-400 flex-shrink-0" />
                                            {obj}
                                        </li>
                                    ))}
                                </ul>
                            </div>
                            <div className="flex gap-2">
                                <button
                                    onClick={() => startTraining(module.id)}
                                    disabled={loading}
                                    className="flex-1 flex items-center justify-center gap-2 py-3 bg-purple-500 hover:bg-purple-600 rounded-lg font-medium transition-all"
                                >
                                    <Play className="w-4 h-4" />
                                    Commencer
                                </button>
                                {module.hasExam && (
                                    <button className="px-4 py-3 bg-gray-700/50 hover:bg-gray-700 rounded-lg transition-all">
                                        <Award className="w-4 h-4" />
                                    </button>
                                )}
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {/* Training Tab */}
            {activeTab === 'training' && currentExercise && (
                <div className="max-w-4xl mx-auto">
                    <div className="bg-gray-800/50 backdrop-blur rounded-xl p-8 border border-purple-500/30">
                        <div className="flex items-center justify-between mb-6">
                            <h2 className="text-2xl font-bold">{currentExercise.title || 'Exercice'}</h2>
                            <span className="px-4 py-2 bg-purple-500/20 rounded-lg text-purple-400">
                                {currentSession?.module}
                            </span>
                        </div>

                        <div className="mb-6">
                            <h3 className="text-lg font-medium mb-3 text-gray-300">Question:</h3>
                            <div className="p-4 bg-gray-900/50 rounded-lg border border-gray-700/50">
                                <p className="text-lg">{currentExercise.prompt}</p>
                            </div>
                        </div>

                        {currentExercise.hints && currentExercise.hints.length > 0 && (
                            <div className="mb-6">
                                <h4 className="text-sm font-medium text-yellow-400 mb-2 flex items-center gap-2">
                                    <AlertTriangle className="w-4 h-4" />
                                    Indices:
                                </h4>
                                <div className="flex flex-wrap gap-2">
                                    {currentExercise.hints.map((hint, i) => (
                                        <span key={i} className="px-3 py-1 bg-yellow-500/10 border border-yellow-500/20 rounded-full text-sm text-yellow-300">
                                            {hint}
                                        </span>
                                    ))}
                                </div>
                            </div>
                        )}

                        <div className="mb-6">
                            <h3 className="text-lg font-medium mb-3 text-gray-300">Votre Réponse:</h3>
                            <textarea
                                value={answer}
                                onChange={(e) => setAnswer(e.target.value)}
                                placeholder="Écrivez votre réponse ici..."
                                className="w-full h-40 p-4 bg-gray-900/50 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:border-purple-500 focus:ring-1 focus:ring-purple-500 outline-none resize-none font-mono"
                            />
                        </div>

                        {feedback && (
                            <div className={`mb-6 p-4 rounded-lg border ${feedback.passed ? 'bg-green-500/10 border-green-500/30' : 'bg-red-500/10 border-red-500/30'}`}>
                                <div className="flex items-center gap-2 mb-2">
                                    {feedback.passed ? (
                                        <CheckCircle className="w-5 h-5 text-green-400" />
                                    ) : (
                                        <XCircle className="w-5 h-5 text-red-400" />
                                    )}
                                    <span className={`font-bold ${feedback.passed ? 'text-green-400' : 'text-red-400'}`}>
                                        Score: {feedback.score}/{feedback.maxScore}
                                    </span>
                                </div>
                                <p className="text-gray-300">{feedback.feedback}</p>
                            </div>
                        )}

                        <button
                            onClick={submitAnswer}
                            disabled={loading || !answer.trim()}
                            className="w-full py-4 bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600 rounded-lg font-bold text-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                        >
                            {loading ? (
                                <>
                                    <RefreshCw className="w-5 h-5 animate-spin" />
                                    Évaluation...
                                </>
                            ) : (
                                <>
                                    <CheckCircle className="w-5 h-5" />
                                    Soumettre
                                </>
                            )}
                        </button>
                    </div>
                </div>
            )}

            {/* Challenge Tab */}
            {activeTab === 'challenge' && challenge && (
                <div className="max-w-3xl mx-auto">
                    <div className="bg-gray-800/50 backdrop-blur rounded-xl p-8 border border-yellow-500/30">
                        <div className="flex items-center justify-between mb-6">
                            <h2 className="text-2xl font-bold flex items-center gap-3">
                                <Zap className="w-6 h-6 text-yellow-400" />
                                {challenge.title}
                            </h2>
                            <div className="flex items-center gap-3">
                                <span className={`px-3 py-1 rounded-full text-sm border ${getDifficultyColor(challenge.difficulty)}`}>
                                    {challenge.difficulty}
                                </span>
                                <span className="flex items-center gap-1 text-yellow-400">
                                    <Trophy className="w-4 h-4" />
                                    {challenge.points} pts
                                </span>
                            </div>
                        </div>
                        <div className="p-4 bg-gray-900/50 rounded-lg border border-gray-700/50 mb-6">
                            <p className="text-lg">{challenge.prompt}</p>
                        </div>
                        <div className="flex justify-between">
                            <button
                                onClick={() => getRandomChallenge(challenge.difficulty)}
                                className="px-6 py-3 bg-gray-700/50 hover:bg-gray-700 rounded-lg transition-all flex items-center gap-2"
                            >
                                <RefreshCw className="w-4 h-4" />
                                Autre Challenge
                            </button>
                            <button
                                onClick={() => setActiveTab('training')}
                                className="px-6 py-3 bg-yellow-500/20 border border-yellow-500/30 hover:bg-yellow-500/30 rounded-lg transition-all flex items-center gap-2"
                            >
                                <Terminal className="w-4 h-4" />
                                Résoudre
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Challenges Tab */}
            {activeTab === 'challenges' && !challenge && (
                <div className="grid grid-cols-3 gap-6">
                    {['beginner', 'intermediate', 'advanced'].map(diff => (
                        <button
                            key={diff}
                            onClick={() => getRandomChallenge(diff)}
                            className={`p-8 rounded-xl border transition-all hover:scale-105 ${getDifficultyColor(diff)}`}
                        >
                            <Zap className="w-12 h-12 mx-auto mb-4" />
                            <h3 className="text-xl font-bold mb-2 capitalize">{diff}</h3>
                            <p className="text-sm opacity-70">Challenge aléatoire</p>
                        </button>
                    ))}
                </div>
            )}

            {/* Labs Tab */}
            {activeTab === 'labs' && (
                <div className="grid grid-cols-2 gap-6">
                    {labs.map(lab => (
                        <div 
                            key={lab.id}
                            className="bg-gray-800/50 backdrop-blur rounded-xl p-6 border border-gray-700/50 hover:border-blue-500/30 transition-all"
                        >
                            <div className="flex items-start justify-between mb-4">
                                <h3 className="text-xl font-bold">{lab.name}</h3>
                                <span className={`px-3 py-1 rounded-full text-xs border ${getDifficultyColor(lab.difficulty)}`}>
                                    {lab.difficulty}
                                </span>
                            </div>
                            <p className="text-gray-400 mb-4">{lab.description}</p>
                            <div className="flex items-center gap-4 text-sm text-gray-400 mb-4">
                                <span>{lab.estimatedTime}</span>
                                <span>•</span>
                                <span>{lab.environment}</span>
                            </div>
                            <div className="flex flex-wrap gap-2 mb-4">
                                {lab.tools.map(tool => (
                                    <span key={tool} className="px-2 py-1 bg-blue-500/10 border border-blue-500/20 rounded text-xs text-blue-300">
                                        {tool}
                                    </span>
                                ))}
                            </div>
                            <button className="w-full py-3 bg-blue-500/20 border border-blue-500/30 hover:bg-blue-500/30 rounded-lg transition-all flex items-center justify-center gap-2">
                                <Play className="w-4 h-4" />
                                Lancer le Lab
                            </button>
                        </div>
                    ))}
                </div>
            )}

            {/* Leaderboard Tab */}
            {activeTab === 'leaderboard' && (
                <div className="max-w-3xl mx-auto">
                    <div className="bg-gray-800/50 backdrop-blur rounded-xl p-6 border border-gray-700/50">
                        <h2 className="text-2xl font-bold mb-6 flex items-center gap-3">
                            <Trophy className="w-6 h-6 text-yellow-400" />
                            Classement Global
                        </h2>
                        <div className="space-y-3">
                            {leaderboard.map((user, idx) => (
                                <div 
                                    key={user.userId}
                                    className={`flex items-center gap-4 p-4 rounded-xl border transition-all ${
                                        idx < 3 ? 'bg-gradient-to-r from-yellow-500/10 to-transparent border-yellow-500/30' : 'bg-gray-900/30 border-gray-700/30'
                                    }`}
                                >
                                    <span className={`w-10 h-10 flex items-center justify-center rounded-full text-lg font-bold ${
                                        idx === 0 ? 'bg-yellow-500 text-black' :
                                        idx === 1 ? 'bg-gray-400 text-black' :
                                        idx === 2 ? 'bg-orange-600 text-white' :
                                        'bg-gray-700 text-gray-300'
                                    }`}>{idx + 1}</span>
                                    <div className="flex-1">
                                        <div className="font-bold">{user.rank}</div>
                                        <div className="text-sm text-gray-400">Niveau {user.level} • {user.completedModules} modules</div>
                                    </div>
                                    <div className="text-right">
                                        <div className="text-xl font-bold text-purple-400">{user.totalXP}</div>
                                        <div className="text-sm text-gray-400">XP</div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
