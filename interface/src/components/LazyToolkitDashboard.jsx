import React, { useState, useEffect, useRef } from 'react';
import {
    Zap, Terminal, Shield, Database, Search,
    CheckCircle, XCircle, Loader, Play, Activity
} from 'lucide-react';
import { API_URL } from '../config';
import { useAuth } from '../contexts/AuthContext';

const LazyToolkitDashboard = () => {
    const { token } = useAuth();
    const [target, setTarget] = useState('');
    const [jobId, setJobId] = useState(null);
    const [status, setStatus] = useState(null);
    const [loading, setLoading] = useState(false);
    const logsEndRef = useRef(null);

    // Auto-scroll logs
    useEffect(() => {
        logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [status?.logs]);

    // Polling effect
    useEffect(() => {
        if (!jobId || status?.status === 'completed' || status?.status === 'failed') return;

        const interval = setInterval(async () => {
            try {
                const res = await fetch(`${API_URL}/api/hexstrike/lazy/status/${jobId}`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                const data = await res.json();
                setStatus(data);
            } catch (err) {
                console.error("Polling error", err);
            }
        }, 1000);

        return () => clearInterval(interval);
    }, [jobId, status?.status, token]);

    const startPipeline = async () => {
        if (!target) return;
        setLoading(true);
        setStatus(null);
        try {
            const res = await fetch(`${API_URL}/api/hexstrike/lazy/start`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ target })
            });
            const data = await res.json();
            if (data.success) {
                setJobId(data.jobId);
                setStatus({ status: 'starting', logs: [], progress: 0 });
            }
        } catch (err) {
            console.error(err);
        }
        setLoading(false);
    };

    const getStepColor = (stepName) => {
        const steps = ['init', 'osmedias', 'hackify', 'sqlmap', 'metasploit', 'finished'];
        const currentIdx = steps.indexOf(status?.step || 'init');
        const stepIdx = steps.indexOf(stepName);

        if (stepIdx < currentIdx) return 'text-green-500'; // Done
        if (stepIdx === currentIdx) return 'text-yellow-400'; // Active
        return 'text-gray-600'; // Pending
    };

    return (
        <div className="h-full flex gap-4 p-4 overflow-hidden bg-gray-900 text-white font-mono">
            {/* Left Panel: Control & Progress */}
            <div className="w-1/3 flex flex-col gap-4">
                <div className="bg-black/50 border border-purple-500/30 rounded-lg p-6">
                    <div className="flex items-center gap-3 mb-6">
                        <div className="p-3 bg-purple-900/50 rounded-lg border border-purple-500/50">
                            <Zap size={32} className="text-purple-400" />
                        </div>
                        <div>
                            <h2 className="text-2xl font-bold tracking-wider text-purple-100">LAZY TOOLKIT</h2>
                            <p className="text-xs text-purple-400/70">"Work Smart, Not Hard"</p>
                        </div>
                    </div>

                    <div className="flex gap-2 mb-4">
                        <input
                            type="text"
                            value={target}
                            onChange={(e) => setTarget(e.target.value)}
                            placeholder="Target Domain (e.g., example.com)"
                            className="flex-1 bg-gray-900 border border-gray-700 rounded px-4 py-3 text-purple-300 focus:border-purple-500 outline-none placeholder-gray-600"
                        />
                        <button
                            onClick={startPipeline}
                            disabled={loading || (status && status.status === 'running')}
                            className="bg-purple-600 hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed text-white px-6 py-3 rounded font-bold transition-all shadow-lg shadow-purple-900/30"
                        >
                            {loading ? <Loader className="animate-spin" /> : <Play size={20} />}
                        </button>
                    </div>

                    {/* Steps Visualization */}
                    <div className="space-y-4 mt-8">
                        {[
                            { id: 'osmedias', label: '1. Osmedias (Recon Chains)', icon: Search },
                            { id: 'hackify', label: '2. Hackify (Strategic logic)', icon: Activity },
                            { id: 'faux_society', label: '3. Faux Society (Launcher)', icon: Terminal },
                            { id: 'sqlmap', label: '4. SQLMap (Injection Autopilot)', icon: Database },
                            { id: 'metasploit', label: '5. Metasploit (Validation)', icon: Shield }
                        ].map((step, idx) => (
                            <div key={step.id} className={`flex items-center gap-4 p-3 rounded-lg border transition-all ${status?.step === step.id
                                    ? 'bg-purple-900/20 border-purple-500/50'
                                    : 'bg-gray-800/30 border-transparent text-gray-500'
                                }`}>
                                <div className={`${getStepColor(step.id)}`}>
                                    <step.icon size={20} />
                                </div>
                                <span className={`font-bold text-sm ${getStepColor(step.id)}`}>
                                    {step.label}
                                </span>
                                {status?.step === step.id && <Loader size={14} className="ml-auto animate-spin text-purple-500" />}
                                {getStepColor(step.id) === 'text-green-500' && <CheckCircle size={14} className="ml-auto text-green-500" />}
                            </div>
                        ))}
                    </div>
                </div>

                {/* Progress Bar */}
                {status && (
                    <div className="bg-black/50 border border-gray-800 rounded-lg p-4">
                        <div className="flex justify-between text-xs text-gray-400 mb-2">
                            <span>PROGRESS</span>
                            <span>{status.progress}%</span>
                        </div>
                        <div className="w-full bg-gray-800 h-2 rounded-full overflow-hidden">
                            <div
                                className="bg-gradient-to-r from-purple-600 to-cyan-500 h-full transition-all duration-500"
                                style={{ width: `${status.progress}%` }}
                            />
                        </div>
                    </div>
                )}
            </div>

            {/* Right Panel: Logs & Results */}
            <div className="flex-1 flex flex-col gap-4">
                {/* Live Logs */}
                <div className="flex-1 bg-black border border-gray-800 rounded-lg overflow-hidden flex flex-col">
                    <div className="bg-gray-900 p-2 text-xs text-gray-500 border-b border-gray-800 font-bold flex items-center gap-2">
                        <Terminal size={14} /> LIVE TERMINAL OUTPUT
                    </div>
                    <div className="flex-1 p-4 font-mono text-xs overflow-y-auto space-y-1">
                        {!status ? (
                            <div className="text-gray-600 text-center mt-20">Waiting for target...</div>
                        ) : (
                            status.logs.map((log, i) => (
                                <div key={i} className="text-gray-300 break-all border-l-2 border-transparent hover:border-purple-500 pl-2">
                                    <span className="text-purple-500 opacity-50 mr-2">{log.split(']')[0]}]</span>
                                    {log.split(']')[1]}
                                </div>
                            ))
                        )}
                        <div ref={logsEndRef} />
                    </div>
                </div>

                {/* Findings Summary */}
                {status?.results && (
                    <div className="h-1/3 bg-gray-900 border border-gray-800 rounded-lg p-4 overflow-y-auto">
                        <h3 className="text-sm font-bold text-white mb-2 flex items-center gap-2">
                            <Shield size={16} className="text-cyan-500" /> FINDINGS SUMMARY
                        </h3>
                        <div className="space-y-2 text-xs">
                            {status.results.vulnerabilities.length > 0 ? (
                                status.results.vulnerabilities.map((vuln, i) => (
                                    <div key={i} className="bg-red-900/20 border border-red-700/50 p-2 rounded text-red-200">
                                        <span className="font-bold block">[CRITICAL] {vuln.type}</span>
                                        <span className="opacity-70">{vuln.host} via {vuln.tool}</span>
                                    </div>
                                ))
                            ) : (
                                <div className="text-gray-500 italic">No vulnerabilities found yet...</div>
                            )}

                            {status.results.targets.length > 0 && (
                                <div className="mt-4">
                                    <span className="text-gray-400 block mb-1">Targets Analyzed:</span>
                                    <div className="flex flex-wrap gap-2">
                                        {status.results.targets.map((t, i) => (
                                            <span key={i} className="bg-gray-800 px-2 py-1 rounded text-cyan-400 border border-gray-700">
                                                {t.host} ({t.type})
                                            </span>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default LazyToolkitDashboard;
