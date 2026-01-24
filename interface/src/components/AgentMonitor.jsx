import React, { useEffect, useRef } from 'react';
import { Activity } from 'lucide-react';

const AgentMonitor = ({ output, analyzing, analysis }) => {
    const scrollRef = useRef(null);

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [output, analysis]);

    return (
        <div className="flex flex-col h-64 bg-black border border-green-900 rounded-lg overflow-hidden font-mono text-xs shadow-[0_0_15px_rgba(0,255,0,0.1)]">
            <div className="bg-gray-900 px-3 py-1 border-b border-green-900 flex justify-between items-center">
                <span className="text-green-500 font-bold tracking-wider">TERMINAL OUTPUT</span>
                <div className="flex gap-1">
                    <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
                    <div className="w-2 h-2 rounded-full bg-green-900"></div>
                </div>
            </div>

            <div ref={scrollRef} className="flex-1 p-3 overflow-y-auto space-y-2 scrollbar-thin scrollbar-thumb-green-900 scrollbar-track-black">
                <pre className="whitespace-pre-wrap leading-relaxed font-mono text-xs">
                    {typeof output === 'string' ? output :
                        output.map((log, i) => (
                            <span key={i} className={
                                log.type === 'STDERR' ? 'text-red-400' :
                                    log.type === 'SYSTEM' ? 'text-blue-400 font-bold' :
                                        'text-green-400/90'
                            }>
                                {log.content}
                            </span>
                        ))
                    }
                </pre>

                {(analyzing || analysis) && (
                    <div className="border-t border-green-900/50 pt-2 mt-2">
                        <div className="flex items-center gap-2 text-cyan-400 mb-1">
                            <Activity size={12} className={analyzing ? "animate-spin" : ""} />
                            <span className="font-bold">ANALYSIS PROTOCOL</span>
                        </div>
                        <div className="text-cyan-300 opacity-90">
                            {analysis || "Processing data stream..."}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default AgentMonitor;
