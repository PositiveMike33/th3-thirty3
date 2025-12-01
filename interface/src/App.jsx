import React, { useState } from 'react';
import ChatInterface from './ChatInterface';
import SecurityScreen from './SecurityScreen';
import './index.css';

function App() {
  const [isLocked, setIsLocked] = useState(true);

  return (
    <div className="App w-screen h-screen overflow-hidden flex justify-center items-center bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-gray-900 via-[#0a0a0a] to-black">
      <div className="absolute inset-0 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] z-0 pointer-events-none bg-[length:100%_2px,3px_100%]"></div>

      {/* Background Logo Overlay for Main Chat */}
      {!isLocked && (
        <div className="absolute inset-0 flex items-center justify-center opacity-10 pointer-events-none z-0">
          <img src="/logo_security.jpg" alt="Background Logo" className="w-3/4 max-w-2xl object-contain filter grayscale contrast-150" />
        </div>
      )}

      <div className="z-10 w-full h-full">
        {isLocked ? (
          <SecurityScreen onUnlock={() => setIsLocked(false)} />
        ) : (
          <ChatInterface />
        )}
      </div>
    </div>
  );
}

export default App;
