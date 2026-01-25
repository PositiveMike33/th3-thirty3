import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import { SocketProvider } from './contexts/SocketContext'; // Added Socket
import ProtectedRoute from './components/ProtectedRoute';
import ProjectDashboard from './ProjectDashboard';
import OsintDashboard from './OsintDashboard';

import CyberTrainingPage from './CyberTrainingPage';
import KPIDashboard from './KPIDashboard';

import AgentMonitor from './AgentMonitor';
import ChatInterface from './ChatInterface';
import SettingsPage from './SettingsPage';
import SpaceDashboard from './SpaceDashboard';
import SubscriptionPage from './SubscriptionPage';
import PaymentDashboard from './PaymentDashboard';
import GlobalChat from './GlobalChat';
import DartAI from './DartAI';
import FineTuningDashboard from './FineTuningDashboard';
import CyberKineticSimulator from './CyberKineticSimulator';
import RiskDashboard from './RiskDashboard';
import NetworkStatus from './NetworkStatus';
import ServerConsole from './ServerConsole';
import LoginPage from './LoginPage';
import ToolsPage from './ToolsPage';
import EmailDetailPage from './EmailDetailPage';
import HexStrikeExperts from './components/HexStrikeExperts';
import EliteScenarios from './components/EliteScenarios';
import { API_URL } from './config';
import './index.css';

function App() {
  const [wallpaper, setWallpaper] = React.useState('');

  React.useEffect(() => {
    fetch(`${API_URL}/settings`)
      .then(res => res.json())
      .then(data => {
        if (data.themeMode === 'paint' && data.customWallpaper) {
          setWallpaper(data.customWallpaper);
        }
      })
      .catch(err => console.error("Failed to load wallpaper settings", err));
  }, []);

  return (
    <AuthProvider>
      <SocketProvider>
        <Router>
          <Routes>
            {/* Login Page - Public Route */}
            <Route path="/login" element={<LoginPage />} />

            {/* Protected Routes */}
            <Route path="/*" element={
              <ProtectedRoute>
                <div
                  className="App w-screen h-screen overflow-hidden flex flex-col relative bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-gray-900 via-[#0a0a0a] to-black"
                  style={wallpaper ? { backgroundImage: `url(${wallpaper})`, backgroundSize: 'cover', backgroundPosition: 'center' } : {}}
                >
                  <div className="absolute inset-0 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] z-0 pointer-events-none bg-[length:100%_2px,3px_100%]"></div>

                  {/* Background Logo Overlay for Main Chat - now always present or handled by route */}
                  {!wallpaper && (
                    <div className="absolute inset-0 flex items-center justify-center opacity-10 pointer-events-none z-0">
                      <img src="/logo_security.jpg" alt="Background Logo" className="w-3/4 max-w-2xl object-contain filter grayscale contrast-150" />
                    </div>
                  )}

                  <div className="z-10 w-full h-full flex flex-col">
                    {/* Navigation */}
                    <nav className="p-4 bg-gray-900/80 border-b border-gray-800 text-white flex justify-center gap-8 backdrop-blur-md z-20 items-center">
                      <Link to="/" className="hover:text-cyan-400 transition-colors font-mono text-sm tracking-widest">CHAT</Link>

                      <Link to="/tools" className="hover:text-red-400 transition-colors font-mono text-sm tracking-widest">🛡️ OUTILS</Link>
                      <Link to="/hexstrike" className="hover:text-orange-400 transition-colors font-mono text-sm tracking-widest">🔥 HEXSTRIKE</Link>
                      <Link to="/scenarios" className="hover:text-red-400 transition-colors font-mono text-sm tracking-widest">🎯 SCENARIOS</Link>
                      <Link to="/projects" className="hover:text-cyan-400 transition-colors font-mono text-sm tracking-widest">PROJECTS</Link>
                      <Link to="/simulator" className="hover:text-pink-400 transition-colors font-mono text-sm tracking-widest">🎮 SIMULATOR</Link>
                      <Link to="/space" className="hover:text-blue-400 transition-colors font-mono text-sm tracking-widest"> SPACE</Link>

                      <Link to="/settings" className="hover:text-yellow-400 transition-colors font-mono text-sm tracking-widest"> SETTINGS</Link>
                      {/* Network Status Indicator - RISK-006 */}
                      <NetworkStatus compact={true} />
                    </nav>

                    <div className="flex-grow flex overflow-hidden relative">
                      <div className="flex-grow h-full overflow-y-auto overflow-x-hidden">
                        <Routes>
                          <Route path="/" element={<ChatInterface />} />

                          <Route path="/tools" element={<ToolsPage />} />
                          <Route path="/projects" element={<ProjectDashboard />} />
                          <Route path="/osint" element={<OsintDashboard />} />
                          <Route path="/hexstrike" element={<HexStrikeExperts />} />
                          <Route path="/scenarios" element={<EliteScenarios />} />
                          <Route path="/cyber-training" element={<CyberTrainingPage />} />

                          <Route path="/dashboard" element={<KPIDashboard />} />
                          <Route path="/dart" element={<DartAI />} />
                          <Route path="/finetuning" element={<FineTuningDashboard />} />
                          <Route path="/settings" element={<SettingsPage />} />
                          <Route path="/space" element={<SpaceDashboard />} />
                          <Route path="/simulator" element={<CyberKineticSimulator />} />
                          <Route path="/risks" element={<RiskDashboard />} />
                          <Route path="/subscription" element={<SubscriptionPage />} />
                          <Route path="/payment" element={<PaymentDashboard />} />
                          <Route path="/email/:id" element={<EmailDetailPage />} />
                        </Routes>
                      </div>

                      <AgentMonitor />

                      {/* Global Chat Overlay - Persistent Everywhere */}
                      <GlobalChat />

                      {/* Server Console - RISK-006: Internal Terminal Display */}
                      <ServerConsole />
                    </div>
                  </div>
                </div>
              </ProtectedRoute>
            } />
          </Routes>
        </Router>
      </SocketProvider>
    </AuthProvider>
  );
}

export default App;

