import React, { useState, useEffect, useCallback } from 'react';
import { API_URL } from './config';

/**
 * KPI Dashboard - Pilier XI du Codex Operandi
 * SOC Personnel : Vision globale des métriques critiques
 */
const KPIDashboard = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');

  const loadDashboard = useCallback(async () => {
    try {
      setLoading(true);
      const response = await fetch(`${API_URL}/api/dashboard/summary`);
      const result = await response.json();
      if (result.success) {
        setData(result);
        setError(null);
      } else {
        setError(result.error);
      }
    } catch {
      setError('Connexion au serveur impossible');
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    let isMounted = true;
    
    const fetchDashboard = async () => {
      try {
        const response = await fetch(`${API_URL}/api/dashboard/summary`);
        const result = await response.json();
        if (isMounted) {
          if (result.success) {
            setData(result);
            setError(null);
          } else {
            setError(result.error);
          }
          setLoading(false);
        }
      } catch {
        if (isMounted) {
          setError('Connexion au serveur impossible');
          setLoading(false);
        }
      }
    };
    
    fetchDashboard();
    const interval = setInterval(fetchDashboard, 5 * 60 * 1000);
    
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const getStatusColor = (status) => {
    const colors = {
      secure: 'from-green-500 to-emerald-500',
      optimal: 'from-green-500 to-emerald-500',
      compliant: 'from-green-500 to-emerald-500',
      active: 'from-blue-500 to-cyan-500',
      caution: 'from-yellow-500 to-amber-500',
      warning: 'from-orange-500 to-red-500',
      critical: 'from-red-600 to-rose-700',
      unknown: 'from-gray-500 to-gray-600'
    };
    return colors[status] || colors.unknown;
  };

  const getSovereigntyColor = (index) => {
    if (index >= 80) return 'text-green-400';
    if (index >= 60) return 'text-yellow-400';
    if (index >= 40) return 'text-orange-400';
    return 'text-red-400';
  };

  if (loading && !data) {
    return (
      <div className="w-full h-full flex items-center justify-center bg-gray-900">
        <div className="text-center">
          <div className="animate-spin w-12 h-12 border-4 border-purple-500 border-t-transparent rounded-full mx-auto mb-4"></div>
          <p className="text-gray-400">Chargement du SOC Personnel...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full h-full overflow-y-auto bg-gradient-to-br from-gray-900 via-black to-gray-900 text-white p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold bg-gradient-to-r from-purple-400 to-pink-500 bg-clip-text text-transparent">
                🎯 SOC Personnel
              </h1>
              <p className="text-gray-400 text-sm mt-1">
                Pilier XI - Dashboard KPI | Codex Operandi
              </p>
            </div>
            <button 
              onClick={loadDashboard}
              className="px-4 py-2 bg-purple-600/30 hover:bg-purple-600/50 border border-purple-500/30 rounded-lg transition-all"
            >
              🔄 Actualiser
            </button>
          </div>
        </div>

        {error && (
          <div className="mb-6 bg-red-900/30 border border-red-500/50 rounded-lg p-4">
            <p className="text-red-400">⚠️ {error}</p>
          </div>
        )}

        {data && (
          <>
            {/* Sovereignty Index - Main KPI */}
            <div className="mb-8 bg-gradient-to-r from-purple-900/50 to-indigo-900/50 border border-purple-500/30 rounded-2xl p-8 text-center">
              <p className="text-purple-400 text-sm mb-2">INDICE DE SOUVERAINETÉ</p>
              <div className={`text-7xl font-bold ${getSovereigntyColor(data.sovereigntyIndex)}`}>
                {data.sovereigntyIndex}
              </div>
              <div className="w-full bg-gray-700 rounded-full h-3 mt-4 max-w-md mx-auto">
                <div 
                  className={`h-3 rounded-full bg-gradient-to-r ${data.sovereigntyIndex >= 60 ? 'from-green-500 to-emerald-400' : 'from-red-500 to-orange-400'}`}
                  style={{ width: `${data.sovereigntyIndex}%` }}
                ></div>
              </div>
              <p className="text-gray-500 text-xs mt-2">
                Dernière mise à jour: {new Date(data.timestamp).toLocaleString('fr-CA')}
              </p>
            </div>

            {/* Tabs */}
            <div className="flex gap-2 mb-6 overflow-x-auto">
              {['overview', 'security', 'productivity', 'bio', 'compliance'].map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-4 py-2 rounded-lg font-medium transition-all whitespace-nowrap ${
                    activeTab === tab 
                      ? 'bg-purple-600 text-white' 
                      : 'bg-gray-800/50 text-gray-400 hover:bg-gray-700'
                  }`}
                >
                  {tab === 'overview' && '📊 Vue Globale'}
                  {tab === 'security' && '🛡️ Sécurité'}
                  {tab === 'productivity' && '⚡ Productivité'}
                  {tab === 'bio' && '🧬 Bio'}
                  {tab === 'compliance' && '⚖️ Conformité'}
                </button>
              ))}
            </div>

            {/* Overview Tab */}
            {activeTab === 'overview' && (
              <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
                {/* Security Card */}
                <div className={`bg-gradient-to-br ${getStatusColor(data.metrics.security.status)} p-[1px] rounded-xl`}>
                  <div className="bg-gray-900 rounded-xl p-5 h-full">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-2xl">🛡️</span>
                      <span className={`px-2 py-1 rounded text-xs font-bold uppercase ${
                        data.metrics.security.status === 'secure' ? 'bg-green-500/20 text-green-400' :
                        data.metrics.security.status === 'critical' ? 'bg-red-500/20 text-red-400' :
                        'bg-yellow-500/20 text-yellow-400'
                      }`}>
                        {data.metrics.security.status}
                      </span>
                    </div>
                    <h3 className="text-white font-bold mb-2">Sécurité</h3>
                    <div className="text-3xl font-bold text-white mb-1">
                      {data.metrics.security.aikido.total}
                    </div>
                    <p className="text-gray-400 text-sm">issues détectés</p>
                    <div className="flex gap-2 mt-3 text-xs">
                      <span className="text-red-400">{data.metrics.security.aikido.critical} crit</span>
                      <span className="text-orange-400">{data.metrics.security.aikido.high} high</span>
                    </div>
                  </div>
                </div>

                {/* Productivity Card */}
                <div className={`bg-gradient-to-br ${getStatusColor(data.metrics.productivity.status)} p-[1px] rounded-xl`}>
                  <div className="bg-gray-900 rounded-xl p-5 h-full">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-2xl">⚡</span>
                      <span className="px-2 py-1 rounded text-xs font-bold uppercase bg-blue-500/20 text-blue-400">
                        {data.metrics.productivity.status}
                      </span>
                    </div>
                    <h3 className="text-white font-bold mb-2">Productivité</h3>
                    <div className="text-3xl font-bold text-white mb-1">
                      {Math.round(data.metrics.productivity.proactiveRatio * 100)}%
                    </div>
                    <p className="text-gray-400 text-sm">ratio proactif</p>
                    <div className="flex gap-2 mt-3 text-xs">
                      <span className="text-cyan-400">{data.metrics.productivity.tasksCompleted.today} tâches</span>
                    </div>
                  </div>
                </div>

                {/* Bio Card */}
                <div className={`bg-gradient-to-br ${getStatusColor(data.metrics.bio.status)} p-[1px] rounded-xl`}>
                  <div className="bg-gray-900 rounded-xl p-5 h-full">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-2xl">🧬</span>
                      <span className="px-2 py-1 rounded text-xs font-bold uppercase bg-green-500/20 text-green-400">
                        {data.metrics.bio.status}
                      </span>
                    </div>
                    <h3 className="text-white font-bold mb-2">Bio-Optimisation</h3>
                    <div className="text-3xl font-bold text-white mb-1">
                      {data.metrics.bio.energy.current || '—'}
                    </div>
                    <p className="text-gray-400 text-sm">niveau énergie</p>
                    <div className="flex gap-2 mt-3 text-xs">
                      <span className="text-emerald-400">
                        {data.metrics.bio.stack.completed ? '✓ Stack pris' : '○ Stack en attente'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Compliance Card */}
                <div className={`bg-gradient-to-br ${getStatusColor(data.metrics.compliance.status)} p-[1px] rounded-xl`}>
                  <div className="bg-gray-900 rounded-xl p-5 h-full">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-2xl">⚖️</span>
                      <span className="px-2 py-1 rounded text-xs font-bold uppercase bg-green-500/20 text-green-400">
                        {data.metrics.compliance.status}
                      </span>
                    </div>
                    <h3 className="text-white font-bold mb-2">Conformité</h3>
                    <div className="text-3xl font-bold text-white mb-1">
                      {data.metrics.compliance.fiscal.daysRemaining}j
                    </div>
                    <p className="text-gray-400 text-sm">avant deadline TPS/TVQ</p>
                    <div className="flex gap-2 mt-3 text-xs">
                      <span className="text-teal-400">{data.metrics.compliance.contracts.active} contrats actifs</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Security Tab */}
            {activeTab === 'security' && (
              <div className="grid md:grid-cols-2 gap-6">
                <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
                  <h3 className="text-xl font-bold text-white mb-4">🔒 Aikido Security</h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-red-900/30 rounded-lg p-4 text-center">
                      <div className="text-4xl font-bold text-red-400">{data.metrics.security.aikido.critical}</div>
                      <div className="text-gray-400 text-sm">Critical</div>
                    </div>
                    <div className="bg-orange-900/30 rounded-lg p-4 text-center">
                      <div className="text-4xl font-bold text-orange-400">{data.metrics.security.aikido.high}</div>
                      <div className="text-gray-400 text-sm">High</div>
                    </div>
                    <div className="bg-yellow-900/30 rounded-lg p-4 text-center">
                      <div className="text-4xl font-bold text-yellow-400">{data.metrics.security.aikido.medium}</div>
                      <div className="text-gray-400 text-sm">Medium</div>
                    </div>
                    <div className="bg-blue-900/30 rounded-lg p-4 text-center">
                      <div className="text-4xl font-bold text-blue-400">{data.metrics.security.aikido.low}</div>
                      <div className="text-gray-400 text-sm">Low</div>
                    </div>
                  </div>
                  <div className="mt-4 text-center text-gray-500 text-sm">
                    {data.metrics.security.aikido.repoCount} repos scannés
                  </div>
                </div>
                
                <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
                  <h3 className="text-xl font-bold text-white mb-4">🚨 Alertes</h3>
                  <div className="space-y-3">
                    <div className="flex justify-between items-center p-3 bg-gray-900/50 rounded-lg">
                      <span className="text-gray-300">Dernières 24h</span>
                      <span className="text-2xl font-bold text-white">{data.metrics.security.alerts.last24h}</span>
                    </div>
                    <div className="flex justify-between items-center p-3 bg-gray-900/50 rounded-lg">
                      <span className="text-gray-300">Non résolues</span>
                      <span className="text-2xl font-bold text-orange-400">{data.metrics.security.alerts.unresolved}</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Productivity Tab */}
            {activeTab === 'productivity' && (
              <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
                <h3 className="text-xl font-bold text-white mb-6">⚡ Métriques de Productivité</h3>
                <div className="grid md:grid-cols-3 gap-6">
                  <div className="text-center">
                    <div className="text-5xl font-bold text-cyan-400">
                      {Math.round(data.metrics.productivity.proactiveRatio * 100)}%
                    </div>
                    <div className="text-gray-400 mt-2">Ratio Proactif/Réactif</div>
                    <div className="text-gray-500 text-sm">Objectif: 70%</div>
                  </div>
                  <div className="text-center">
                    <div className="text-5xl font-bold text-blue-400">
                      {data.metrics.productivity.focusTime.today}
                    </div>
                    <div className="text-gray-400 mt-2">Minutes Focus</div>
                    <div className="text-gray-500 text-sm">Objectif: {data.metrics.productivity.focusTime.target}</div>
                  </div>
                  <div className="text-center">
                    <div className="text-5xl font-bold text-purple-400">
                      {data.metrics.productivity.commits.today}
                    </div>
                    <div className="text-gray-400 mt-2">Commits Aujourd'hui</div>
                  </div>
                </div>
              </div>
            )}

            {/* Bio Tab */}
            {activeTab === 'bio' && (
              <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
                <h3 className="text-xl font-bold text-white mb-6">🧬 Bio-Optimisation</h3>
                <div className="grid md:grid-cols-2 gap-6">
                  <div>
                    <h4 className="text-gray-400 mb-3">Stack Suppléments</h4>
                    <div className={`p-4 rounded-lg ${data.metrics.bio.stack.completed ? 'bg-green-900/30 border border-green-500/30' : 'bg-gray-900/50 border border-gray-700'}`}>
                      {data.metrics.bio.stack.completed 
                        ? <span className="text-green-400">✓ Stack du jour complété</span>
                        : <span className="text-gray-400">○ Stack en attente</span>
                      }
                    </div>
                  </div>
                  <div>
                    <h4 className="text-gray-400 mb-3">Clarté Mentale</h4>
                    <div className={`p-4 rounded-lg ${data.metrics.bio.mentalClarity.fogReported ? 'bg-yellow-900/30 border border-yellow-500/30' : 'bg-green-900/30 border border-green-500/30'}`}>
                      {data.metrics.bio.mentalClarity.fogReported 
                        ? <span className="text-yellow-400">⚠️ Brouillard mental reporté</span>
                        : <span className="text-green-400">✓ Clarté optimale</span>
                      }
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Compliance Tab */}
            {activeTab === 'compliance' && (
              <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
                <h3 className="text-xl font-bold text-white mb-6">⚖️ Conformité Légale</h3>
                <div className="grid md:grid-cols-2 gap-6">
                  <div className="bg-gray-900/50 rounded-lg p-4">
                    <h4 className="text-teal-400 font-bold mb-3">📋 Loi 25</h4>
                    <p className="text-gray-400">Tâches restantes: {data.metrics.compliance.loi25.tasksRemaining}</p>
                  </div>
                  <div className="bg-gray-900/50 rounded-lg p-4">
                    <h4 className="text-amber-400 font-bold mb-3">💰 Fiscal (TPS/TVQ)</h4>
                    <p className="text-gray-300 text-lg mb-1">{data.metrics.compliance.fiscal.daysRemaining} jours</p>
                    <p className="text-gray-500 text-sm">Deadline: {data.metrics.compliance.fiscal.tpsDeadline}</p>
                  </div>
                </div>
              </div>
            )}

            {/* Quick Actions */}
            <div className="mt-8 flex gap-4 flex-wrap">
              <a 
                href="https://app.aikido.dev" 
                target="_blank" 
                rel="noopener noreferrer"
                className="px-4 py-2 bg-indigo-600/30 hover:bg-indigo-600/50 border border-indigo-500/30 rounded-lg transition-all text-sm"
              >
                🔒 Ouvrir Aikido
              </a>
              <button 
                onClick={() => window.location.href = '/cyber-training'}
                className="px-4 py-2 bg-red-600/30 hover:bg-red-600/50 border border-red-500/30 rounded-lg transition-all text-sm"
              >
                🎯 Cyber Training
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default KPIDashboard;
