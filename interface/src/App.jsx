import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import ProjectDashboard from './ProjectDashboard';
import OsintDashboard from './OsintDashboard';
import ProfessionalPage from './ProfessionalPage';
import CyberTrainingPage from './CyberTrainingPage';
import AgentMonitor from './AgentMonitor';
import ModelSelector from './components/ModelSelector';
import ChatInterface from './ChatInterface';
import SecurityScreen from './SecurityScreen';
import './index.css';

import GlobalChat from './GlobalChat';

function App() {
  const [wallpaper, setWallpaper] = React.useState('');

  React.useEffect(() => {
    fetch('http://localhost:3000/settings')
      .then(res => res.json())
      .then(data => {
        if (data.themeMode === 'paint' && data.customWallpaper) {
          setWallpaper(data.customWallpaper);
        }
      })
      .catch(err => console.error("Failed to load wallpaper settings", err));
  }, []);

  return (
    <Router>
      <div
        className="App w-screen h-screen overflow-hidden flex justify-center items-center bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-gray-900 via-[#0a0a0a] to-black"
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
          <nav className="p-4 bg-gray-900/80 border-b border-gray-800 text-white flex justify-center gap-8 backdrop-blur-md z-20">
            <Link to="/" className="hover:text-cyan-400 transition-colors font-mono text-sm tracking-widest">CHAT</Link>
            <Link to="/professional" className="hover:text-cyan-400 transition-colors font-mono text-sm tracking-widest">PROFESSIONAL</Link>
            <Link to="/projects" className="hover:text-cyan-400 transition-colors font-mono text-sm tracking-widest">PROJECTS</Link>
            <Link to="/osint" className="hover:text-cyan-400 transition-colors font-mono text-sm tracking-widest">OSINT</Link>
            <Link to="/cyber-training" className="hover:text-red-400 transition-colors font-mono text-sm tracking-widest">🔒 CYBER</Link>
          </nav>

          <div className="flex-grow flex overflow-hidden relative">
            {/* Model Selector - Only show on Chat page or make it global? Keeping it global for now but maybe styled differently */}
            {/* Model Selector - Removed from global view as requested */}
            {/* <div className="absolute top-4 left-4 z-30">
              <ModelSelector />
            </div> */}

            <div className="flex-grow h-full">
              <Routes>
                <Route path="/" element={<ChatInterface />} />
                <Route path="/professional" element={<ProfessionalPage />} />
                <Route path="/projects" element={<ProjectDashboard />} />
                <Route path="/osint" element={<OsintDashboard />} />
                <Route path="/cyber-training" element={<CyberTrainingPage />} />
              </Routes>
            </div>

            <AgentMonitor />

            {/* Global Chat Overlay - Persistent Everywhere */}
            <GlobalChat />
          </div>
        </div>
      </div>
    </Router>
  );
};

export default App;
