import React, { useState } from 'react';

// Import existing dashboards
import KPIDashboard from './KPIDashboard';
import RiskDashboard from './RiskDashboard';
import OsintDashboard from './OsintDashboard';
import SecurityDashboard from './pages/SecurityDashboard';
import DartAI from './DartAI';
import AgentMonitor from './AgentMonitor';
import ModelIntelligenceDashboard from './components/ModelIntelligenceDashboard';
// OllamaTrainingDashboard removed - Cloud Only Mode
import FineTuningDashboard from './FineTuningDashboard';
import CyberTrainingPage from './CyberTrainingPage';
import NetworkStatus from './NetworkStatus';
import ServerConsole from './ServerConsole';
import ProjectDashboard from './ProjectDashboard';
import PaymentDashboard from './PaymentDashboard';

// Placeholder for removed Ollama Training
const CloudOnlyPlaceholder = () => (
    <div className="flex items-center justify-center h-full bg-gray-900">
        <div className="text-center p-8">
            <div className="text-6xl mb-4">☁️</div>
            <h2 className="text-2xl font-bold text-cyan-400 mb-2">CLOUD ONLY MODE</h2>
            <p className="text-gray-500">Local training désactivé - Utilisez les modèles Cloud.</p>
        </div>
    </div>
);

/**
 * UnifiedDashboard - Central hub for all dashboards
 * Organizes existing dashboards into 4 categories
 */
const UnifiedDashboard = () => {
    const [activeCategory, setActiveCategory] = useState('security');
    const [activeSubTab, setActiveSubTab] = useState(0);

    const categories = {
        security: {
            icon: '🛡️',
            label: 'Security',
            color: 'cyan',
            tabs: [
                { name: 'SOC Dashboard', component: <KPIDashboard /> },
                { name: 'Risk Analysis', component: <RiskDashboard /> },
                { name: 'OSINT', component: <OsintDashboard /> },
                { name: 'Nexus33 Scans', component: <SecurityDashboard /> }
            ]
        },
        ai: {
            icon: '🤖',
            label: 'AI & Agents',
            color: 'purple',
            tabs: [
                { name: 'Dart AI', component: <DartAI /> },
                { name: 'Agent Monitor', component: <AgentMonitor standalone={true} /> },
                { name: 'Model Intelligence', component: <ModelIntelligenceDashboard /> }
            ]
        },
        training: {
            icon: '📚',
            label: 'Training',
            color: 'orange',
            tabs: [
                { name: 'Cloud Training', component: <CloudOnlyPlaceholder /> },
                { name: 'Fine-Tuning', component: <FineTuningDashboard /> },
                { name: 'Cyber Training', component: <CyberTrainingPage /> }
            ]
        },
        tools: {
            icon: '🔧',
            label: 'Tools',
            color: 'green',
            tabs: [
                { name: 'Network Status', component: <NetworkStatus /> },
                { name: 'Server Console', component: <ServerConsole standalone={true} /> },
                { name: 'Projects', component: <ProjectDashboard /> },
                { name: 'Payments', component: <PaymentDashboard /> }
            ]
        }
    };

    const currentCategory = categories[activeCategory];

    return (
        <div className="unified-dashboard h-full flex flex-col bg-gray-900">
            {/* Category Tabs */}
            <div className="category-tabs flex justify-center gap-2 p-4 bg-gray-800/50 border-b border-gray-700">
                {Object.entries(categories).map(([key, cat]) => (
                    <button
                        key={key}
                        onClick={() => { setActiveCategory(key); setActiveSubTab(0); }}
                        className={`px-6 py-3 rounded-lg font-mono text-sm transition-all duration-300 ${activeCategory === key
                            ? `bg-${cat.color}-500/20 text-${cat.color}-400 border border-${cat.color}-500/50`
                            : 'bg-gray-700/50 text-gray-400 hover:bg-gray-600/50 border border-transparent'
                            }`}
                    >
                        <span className="mr-2">{cat.icon}</span>
                        {cat.label}
                    </button>
                ))}
            </div>

            {/* Sub-tabs for current category */}
            <div className="sub-tabs flex gap-1 px-4 py-2 bg-gray-800/30 border-b border-gray-700/50">
                {currentCategory.tabs.map((tab, index) => (
                    <button
                        key={index}
                        onClick={() => setActiveSubTab(index)}
                        className={`px-4 py-2 rounded text-xs font-mono transition-all ${activeSubTab === index
                            ? 'bg-gray-700 text-white'
                            : 'text-gray-500 hover:text-gray-300 hover:bg-gray-700/50'
                            }`}
                    >
                        {tab.name}
                    </button>
                ))}
            </div>

            {/* Dashboard Content */}
            <div className="dashboard-content flex-grow overflow-auto">
                {currentCategory.tabs[activeSubTab]?.component}
            </div>

            <style jsx>{`
                .unified-dashboard {
                    font-family: 'Inter', -apple-system, sans-serif;
                }
                
                .category-tabs button {
                    backdrop-filter: blur(10px);
                }
                
                /* Dynamic color classes */
                .bg-cyan-500\/20 { background-color: rgba(6, 182, 212, 0.2); }
                .text-cyan-400 { color: rgb(34, 211, 238); }
                .border-cyan-500\/50 { border-color: rgba(6, 182, 212, 0.5); }
                
                .bg-purple-500\/20 { background-color: rgba(168, 85, 247, 0.2); }
                .text-purple-400 { color: rgb(192, 132, 252); }
                .border-purple-500\/50 { border-color: rgba(168, 85, 247, 0.5); }
                
                .bg-orange-500\/20 { background-color: rgba(249, 115, 22, 0.2); }
                .text-orange-400 { color: rgb(251, 146, 60); }
                .border-orange-500\/50 { border-color: rgba(249, 115, 22, 0.5); }
                
                .bg-green-500\/20 { background-color: rgba(34, 197, 94, 0.2); }
                .text-green-400 { color: rgb(74, 222, 128); }
                .border-green-500\/50 { border-color: rgba(34, 197, 94, 0.5); }
            `}</style>
        </div>
    );
};

export default UnifiedDashboard;
