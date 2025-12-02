import React, { useRef, useState, useEffect } from 'react';
import { Camera, X, Check } from 'lucide-react';

const WebcamInput = ({ onCapture, onClose }) => {
    const videoRef = useRef(null);
    const canvasRef = useRef(null);
    const [stream, setStream] = useState(null);
    const [error, setError] = useState(null);

    useEffect(() => {
        startCamera();
        return () => stopCamera();
    }, []);

    const startCamera = async () => {
        try {
            const mediaStream = await navigator.mediaDevices.getUserMedia({ video: true });
            setStream(mediaStream);
            if (videoRef.current) {
                videoRef.current.srcObject = mediaStream;
            }
        } catch (err) {
            console.error("Error accessing camera:", err);
            setError("Impossible d'accéder à la caméra. Vérifiez les permissions.");
        }
    };

    const stopCamera = () => {
        if (stream) {
            stream.getTracks().forEach(track => track.stop());
            setStream(null);
        }
    };

    const capture = () => {
        if (videoRef.current && canvasRef.current) {
            const video = videoRef.current;
            const canvas = canvasRef.current;
            const context = canvas.getContext('2d');

            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            context.drawImage(video, 0, 0, canvas.width, canvas.height);

            const imageSrc = canvas.toDataURL('image/jpeg');
            onCapture(imageSrc);
            stopCamera();
        }
    };

    return (
        <div className="fixed inset-0 bg-black/90 z-50 flex items-center justify-center p-4 backdrop-blur-sm">
            <div className="bg-[#111] border border-cyan-500/50 rounded-lg p-4 max-w-lg w-full flex flex-col items-center shadow-[0_0_30px_rgba(0,255,255,0.2)]">
                <div className="w-full flex justify-between items-center mb-4 border-b border-cyan-900/50 pb-2">
                    <h3 className="text-cyan-400 font-mono tracking-widest text-sm flex items-center gap-2">
                        <Camera size={16} /> VISION SYSTEM
                    </h3>
                    <button onClick={() => { stopCamera(); onClose(); }} className="text-red-500 hover:text-red-400">
                        <X size={20} />
                    </button>
                </div>

                {error ? (
                    <div className="text-red-400 font-mono text-sm p-8 text-center border border-red-900/50 rounded bg-red-900/10">
                        {error}
                    </div>
                ) : (
                    <div className="relative w-full aspect-video bg-black rounded overflow-hidden border border-cyan-900">
                        <video
                            ref={videoRef}
                            autoPlay
                            playsInline
                            muted
                            className="w-full h-full object-cover transform scale-x-[-1]" // Mirror effect
                        />
                        <canvas ref={canvasRef} className="hidden" />

                        {/* HUD Overlay */}
                        <div className="absolute inset-0 pointer-events-none border border-cyan-500/20 m-4 rounded">
                            <div className="absolute top-0 left-0 w-4 h-4 border-t-2 border-l-2 border-cyan-500"></div>
                            <div className="absolute top-0 right-0 w-4 h-4 border-t-2 border-r-2 border-cyan-500"></div>
                            <div className="absolute bottom-0 left-0 w-4 h-4 border-b-2 border-l-2 border-cyan-500"></div>
                            <div className="absolute bottom-0 right-0 w-4 h-4 border-b-2 border-r-2 border-cyan-500"></div>
                            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-8 h-8 border border-cyan-500/30 rounded-full flex items-center justify-center">
                                <div className="w-1 h-1 bg-cyan-500 rounded-full"></div>
                            </div>
                        </div>
                    </div>
                )}

                <div className="mt-6 w-full flex justify-center">
                    <button
                        onClick={capture}
                        disabled={!!error}
                        className="px-8 py-2 bg-cyan-900/30 border border-cyan-500 text-cyan-400 rounded hover:bg-cyan-500/20 hover:text-cyan-200 transition-all font-mono uppercase tracking-widest flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        <div className="w-3 h-3 bg-red-500 rounded-full animate-pulse"></div>
                        Capturer
                    </button>
                </div>
            </div>
        </div>
    );
};

export default WebcamInput;
