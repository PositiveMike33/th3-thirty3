import React, { useState, useRef } from 'react';
import WWTMapComponent from './components/WWTMapComponent';
import { api } from './services/apiService';
import { Upload, Loader, CheckCircle, AlertTriangle } from 'lucide-react';

const SpaceDashboard = () => {
    const wwtRef = useRef(null);
    const [uploading, setUploading] = useState(false);
    const [status, setStatus] = useState(null); // 'uploading', 'solving', 'solved', 'failed'
    const [message, setMessage] = useState('');

    const handleFileUpload = async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        setUploading(true);
        setStatus('uploading');
        setMessage('Uploading to Astrometry.net...');

        const formData = new FormData();
        formData.append('file', file);

        try {
            const res = await api.uploadAstrometry(formData);
            if (res.success) {
                setMessage('Solving... (This may take a minute)');
                setStatus('solving');
                pollStatus(res.submission_id);
            } else {
                throw new Error(res.error || 'Upload failed');
            }
        } catch (error) {
            console.error(error);
            setStatus('failed');
            setMessage(error.message || 'Error occurred');
            setUploading(false);
        }
    };

    const pollStatus = async (subId) => {
        const interval = setInterval(async () => {
            try {
                const res = await api.getAstrometryStatus(subId);
                console.log("Polling status:", res);
                if (res.status === 'solved') {
                    clearInterval(interval);
                    setStatus('solved');
                    setMessage('Solved! Overlaying on map...');
                    setUploading(false);
                    if (wwtRef.current) {
                        wwtRef.current.addSolvedImage(null, res.calibration);
                    }
                } else if (res.status === 'failed') {
                    clearInterval(interval);
                    setStatus('failed');
                    setMessage('Solving failed. Try a clearer image.');
                    setUploading(false);
                }
                // else keep polling
            } catch (error) {
                console.error(error);
                // Don't stop polling on transient network error, but maybe limit retries?
                // For simplified demo, we just log.
            }
        }, 3000);
    };

    return (
        <div
            className="flex-1 flex flex-col bg-black relative overflow-hidden"
            style={{ height: 'calc(100vh - 64px)', width: '100%' }}
        >
            {/* WWT Component (Full Screen) */}
            <div className="w-full h-full relative z-10">
                <WWTMapComponent ref={wwtRef} />
            </div>

            {/* Upload Control Panel */}
            <div className="absolute top-4 left-4 z-20 bg-gray-900/80 backdrop-blur-md p-4 rounded-lg border border-cyan-500/30 text-white w-80 shadow-2xl">
                <h3 className="text-lg font-bold text-cyan-400 mb-2 flex items-center gap-2">
                    <Upload size={20} /> Astrometry Upload
                </h3>
                <p className="text-xs text-gray-400 mb-4">
                    Upload an astrophoto to identify stars and place it on the map (Plate Solving).
                </p>

                {!uploading && status !== 'solved' && (
                    <label className="flex items-center justify-center w-full h-24 border-2 border-dashed border-gray-600 rounded-lg cursor-pointer hover:border-cyan-500 hover:bg-gray-800/50 transition-colors">
                        <div className="flex flex-col items-center">
                            <Upload className="text-gray-400 mb-1" size={24} />
                            <span className="text-sm text-gray-300">Choose Image</span>
                        </div>
                        <input type="file" className="hidden" onChange={handleFileUpload} accept="image/*" />
                    </label>
                )}

                {/* Status Display */}
                {(status === 'uploading' || status === 'solving') && (
                    <div className="flex flex-col items-center py-4">
                        <Loader className="animate-spin text-cyan-400 mb-2" size={24} />
                        <span className="text-sm animate-pulse">{message}</span>
                    </div>
                )}

                {status === 'solved' && (
                    <div className="text-center py-2">
                        <div className="flex items-center justify-center gap-2 text-green-400 mb-2">
                            <CheckCircle size={20} />
                            <span className="font-bold">Solved!</span>
                        </div>
                        <p className="text-xs text-gray-300 mb-3">Map verified and centered on your image.</p>
                        <button
                            onClick={() => { setStatus(null); setMessage(''); }}
                            className="text-xs underline text-cyan-400 hover:text-cyan-300"
                        >
                            Upload Another
                        </button>
                    </div>
                )}

                {status === 'failed' && (
                    <div className="text-center py-2">
                        <div className="flex items-center justify-center gap-2 text-red-400 mb-2">
                            <AlertTriangle size={20} />
                            <span className="font-bold">Failed</span>
                        </div>
                        <p className="text-xs text-red-300">{message}</p>
                        <button
                            onClick={() => { setStatus(null); setMessage(''); }}
                            className="mt-2 px-3 py-1 bg-red-900/50 rounded text-xs hover:bg-red-800"
                        >
                            Try Again
                        </button>
                    </div>
                )}
            </div>

            {/* Decorative Accents */}
            <div className="absolute top-0 right-0 w-32 h-32 bg-[radial-gradient(circle_at_top_right,rgba(34,211,238,0.1),transparent)] pointer-events-none z-0"></div>
            <div className="absolute bottom-0 left-0 w-32 h-32 bg-[radial-gradient(circle_at_bottom_left,rgba(34,211,238,0.1),transparent)] pointer-events-none z-0"></div>
        </div>
    );
};

export default SpaceDashboard;
