import React from 'react';

const Avatar = ({ isSpeaking }) => {
  return (
    <div className={`relative w-12 h-12 group ${isSpeaking ? 'animate-pulse' : ''}`}>
      <div className={`absolute -inset-1 bg-gradient-to-r from-cyan-600 to-purple-600 rounded-full blur opacity-25 group-hover:opacity-75 transition duration-1000 group-hover:duration-200 ${isSpeaking ? 'opacity-100 duration-75' : ''}`}></div>
      <div className={`relative w-full h-full rounded-full overflow-hidden border-2 ${isSpeaking ? 'border-cyan-400 shadow-[0_0_30px_rgba(34,211,238,0.8)]' : 'border-cyan-900 shadow-[0_0_10px_rgba(8,145,178,0.3)]'} transition-all duration-300`}>
        <img
          src="/agent33.jpg"
          alt="Thirty3"
          className={`w-full h-full object-cover filter contrast-125 brightness-90 grayscale hover:grayscale-0 transition-all duration-500 ${isSpeaking ? 'scale-110 brightness-110 grayscale-0' : ''}`}
        />
        {/* Scanline effect overlay */}
        <div className="absolute inset-0 bg-[url('https://media.giphy.com/media/3o7qE1YN7aQfV9ns1G/giphy.gif')] opacity-10 mix-blend-overlay pointer-events-none"></div>
      </div>
    </div>
  );
};

export default Avatar;
