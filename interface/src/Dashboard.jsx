import React, { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { Wallet, TrendingUp, DollarSign, Activity, Camera, Globe, Wifi } from 'lucide-react';
import PaymentDashboard from './PaymentDashboard';
import IPLocationWidget from './components/IPLocationWidget';
import { API_URL } from './config';

const SYMBOLS = ['BTC/CAD', 'ETH/CAD', 'SOL/CAD'];

const Dashboard = () => {
    const [portfolio, setPortfolio] = useState([]);
    const [tickers, setTickers] = useState({});
    const [news, setNews] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [activeTab, setActiveTab] = useState('portfolio'); // portfolio ou payments

    useEffect(() => {
        const fetchData = async () => {
            try {
                const headers = { 'x-api-key': localStorage.getItem('th3_api_key') || '' };

                // Fetch Portfolio
                const portRes = await fetch(`${API_URL}/finance/portfolio`, { headers });
                const portData = await portRes.json();

                if (portData.error) {
                    setError(portData.error);
                } else {
                    setPortfolio(portData);
                    setError(null);
                }

                // Fetch Tickers
                const newTickers = {};
                for (const sym of SYMBOLS) {
                    const tickRes = await fetch(`${API_URL}/finance/ticker?symbol=${sym}`, { headers });
                    const tickData = await tickRes.json();
                    if (!tickData.error) newTickers[sym] = tickData;
                }
                setTickers(newTickers);

                // Fetch News
                const newsRes = await fetch(`${API_URL}/finance/news`, { headers });
                const newsData = await newsRes.json();
                if (!newsData.error) setNews(newsData);

            } catch (e) {
                console.error("Dashboard fetch error:", e);
                setError("Erreur de connexion au serveur.");
            } finally {
                setLoading(false);
            }
        };

        fetchData();
        const interval = setInterval(fetchData, 30000); // Refresh every 30s
        return () => clearInterval(interval);
    }, []);

    const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8'];

    // Network Panel Component
    const NetworkPanel = () => {
        const [networkStatus, setNetworkStatus] = React.useState({ tor: null, vpn: null, cameras: [] });
        const [loadingNet, setLoadingNet] = React.useState(true);
        
        React.useEffect(() => {
            const fetchNetworkStatus = async () => {
                try {
                    const headers = { 'x-api-key': localStorage.getItem('th3_api_key') || '' };
                    
                    // Fetch TOR status
                    const torRes = await fetch(`${API_URL}/api/tor/status`, { headers });
                    const torData = await torRes.json();
                    
                    // Fetch VPN status
                    const vpnRes = await fetch(`${API_URL}/api/vpn/status`, { headers });
                    const vpnData = await vpnRes.json();
                    
                    // Fetch Cameras
                    const camRes = await fetch(`${API_URL}/api/cameras/status`, { headers });
                    const camData = await camRes.json();
                    
                    setNetworkStatus({
                        tor: torData,
                        vpn: vpnData,
                        cameras: camData.cameras || []
                    });
                } catch (e) {
                    console.error('Network status fetch error:', e);
                } finally {
                    setLoadingNet(false);
                }
            };
            
            fetchNetworkStatus();
        }, []);

        if (loadingNet) return <div className="text-purple-400 p-10">Chargement Network Status...</div>;

        return (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {/* IP Location Widget */}
                <div className="bg-gray-800/50 p-6 rounded-lg border border-purple-900/50 shadow-lg backdrop-blur-sm">
                    <h2 className="text-xl font-bold mb-4 flex items-center gap-2 text-purple-300">
                        <Globe className="w-5 h-5" />
                        Géolocalisation IP
                    </h2>
                    <IPLocationWidget display="LIPFB" width={300} />
                </div>

                {/* TOR Status */}
                <div className="bg-gray-800/50 p-6 rounded-lg border border-purple-900/50 shadow-lg backdrop-blur-sm">
                    <h2 className="text-xl font-bold mb-4 flex items-center gap-2 text-purple-300">
                        🧅 Statut TOR
                    </h2>
                    <div className="space-y-3">
                        <div className="flex items-center justify-between p-3 bg-black/30 rounded">
                            <span>Service Active</span>
                            <span className={networkStatus.tor?.tor?.running ? 'text-green-400' : 'text-red-400'}>
                                {networkStatus.tor?.tor?.running ? '✅ Running' : '❌ Stopped'}
                            </span>
                        </div>
                        <div className="flex items-center justify-between p-3 bg-black/30 rounded">
                            <span>Connexion TOR</span>
                            <span className={networkStatus.tor?.tor?.isTor ? 'text-green-400' : 'text-yellow-400'}>
                                {networkStatus.tor?.tor?.isTor ? '🧅 Connected' : '⚠️ Direct'}
                            </span>
                        </div>
                        {networkStatus.tor?.tor?.exitIP && (
                            <div className="flex items-center justify-between p-3 bg-black/30 rounded">
                                <span>Exit IP</span>
                                <span className="text-cyan-400 font-mono text-sm">{networkStatus.tor.tor.exitIP}</span>
                            </div>
                        )}
                    </div>
                </div>

                {/* VPN Status */}
                <div className="bg-gray-800/50 p-6 rounded-lg border border-purple-900/50 shadow-lg backdrop-blur-sm">
                    <h2 className="text-xl font-bold mb-4 flex items-center gap-2 text-purple-300">
                        <Wifi className="w-5 h-5" />
                        Statut VPN
                    </h2>
                    <div className="space-y-3">
                        <div className="flex items-center justify-between p-3 bg-black/30 rounded">
                            <span>Connected</span>
                            <span className={networkStatus.vpn?.isConnected ? 'text-green-400' : 'text-yellow-400'}>
                                {networkStatus.vpn?.isConnected ? '🔒 VPN Active' : '🔓 Direct'}
                            </span>
                        </div>
                        <div className="flex items-center justify-between p-3 bg-black/30 rounded">
                            <span>Current IP</span>
                            <span className="text-cyan-400 font-mono text-sm">
                                {networkStatus.vpn?.currentIP || 'Unknown'}
                            </span>
                        </div>
                        {networkStatus.vpn?.currentServer && (
                            <div className="flex items-center justify-between p-3 bg-black/30 rounded">
                                <span>Server</span>
                                <span className="text-purple-400">{networkStatus.vpn.currentServer}</span>
                            </div>
                        )}
                    </div>
                </div>

                {/* Cameras Panel */}
                <div className="bg-gray-800/50 p-6 rounded-lg border border-purple-900/50 shadow-lg backdrop-blur-sm md:col-span-2 lg:col-span-3">
                    <h2 className="text-xl font-bold mb-4 flex items-center gap-2 text-purple-300">
                        <Camera className="w-5 h-5" />
                        Caméras EasyLife ({networkStatus.cameras?.length || 0})
                    </h2>
                    {networkStatus.cameras?.length > 0 ? (
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                            {networkStatus.cameras.map(cam => (
                                <div key={cam.id} className="p-4 bg-black/40 rounded-lg border border-gray-700">
                                    <div className="flex items-center justify-between mb-2">
                                        <span className="font-bold text-white">{cam.name}</span>
                                        <span className={cam.status === 'online' ? 'text-green-400' : 'text-red-400'}>
                                            {cam.status === 'online' ? '🟢' : '🔴'} {cam.status}
                                        </span>
                                    </div>
                                    <div className="text-sm text-gray-400">
                                        <div>IP: {cam.ip}</div>
                                        <div>PTZ: {cam.hasPTZ ? '✅' : '❌'}</div>
                                    </div>
                                    <div className="mt-3 flex gap-2">
                                        <button className="px-3 py-1 bg-purple-600 hover:bg-purple-500 rounded text-xs transition-colors">
                                            📸 Snapshot
                                        </button>
                                        {cam.hasPTZ && (
                                            <button className="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-xs transition-colors">
                                                🎮 PTZ
                                            </button>
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div className="text-center py-10 text-gray-500">
                            <Camera className="w-12 h-12 mx-auto mb-3 opacity-30" />
                            <p>Aucune caméra configurée</p>
                            <p className="text-xs mt-2">Utilisez l'API /api/cameras ou /api/tuya pour ajouter vos caméras EasyLife</p>
                        </div>
                    )}
                </div>
            </div>
        );
    };

    if (loading) return <div className="text-cyan-400 p-10">Chargement du QG Financier...</div>;


    return (
        <div className="h-full overflow-y-auto p-6 bg-gray-900 text-cyan-300 font-mono">
            <h1 className="text-3xl font-bold mb-8 border-b border-cyan-800 pb-2 flex items-center gap-3">
                <Activity className="w-8 h-8" />
                CENTRE DE COMMANDEMENT FINANCIER
            </h1>

            {/* Tabs */}
            <div className="flex gap-4 mb-6 flex-wrap">
                <button 
                    onClick={() => setActiveTab('portfolio')}
                    className={`px-6 py-3 rounded-lg font-bold transition-all ${
                        activeTab === 'portfolio' 
                            ? 'bg-cyan-600 text-white' 
                            : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                    }`}
                >
                    📊 Portfolio Kraken
                </button>
                <button 
                    onClick={() => setActiveTab('payments')}
                    className={`px-6 py-3 rounded-lg font-bold transition-all ${
                        activeTab === 'payments' 
                            ? 'bg-cyan-600 text-white' 
                            : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                    }`}
                >
                    💳 Paiements (Stripe/PayPal)
                </button>
                <button 
                    onClick={() => setActiveTab('network')}
                    className={`px-6 py-3 rounded-lg font-bold transition-all ${
                        activeTab === 'network' 
                            ? 'bg-purple-600 text-white' 
                            : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                    }`}
                >
                    🌐 Network & Surveillance
                </button>
            </div>

            {/* Content */}
            {activeTab === 'payments' ? (
                <PaymentDashboard />
            ) : activeTab === 'network' ? (
                <NetworkPanel />
            ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* PORTFOLIO CARD */}
                <div className="bg-gray-800/50 p-6 rounded-lg border border-cyan-900/50 shadow-lg backdrop-blur-sm">
                    <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
                        <Wallet className="w-5 h-5" />
                        Portefeuille Kraken
                    </h2>
                    <div className="h-64">
                        {error ? (
                            <div className="flex flex-col items-center justify-center h-full text-red-400 text-center p-4">
                                <span className="font-bold mb-2">⚠️ Erreur API</span>
                                <span className="text-xs">{error}</span>
                                <span className="text-xs text-gray-500 mt-2">Vérifiez les permissions de la clé API (Query Funds).</span>
                            </div>
                        ) : portfolio.length > 0 ? (
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={portfolio}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={60}
                                        outerRadius={80}
                                        fill="#8884d8"
                                        paddingAngle={5}
                                        dataKey="value"
                                    >
                                        {portfolio.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                        ))}
                                    </Pie>
                                    <Tooltip contentStyle={{ backgroundColor: '#1f2937', borderColor: '#0e7490' }} />
                                    <Legend />
                                </PieChart>
                            </ResponsiveContainer>
                        ) : (
                            <div className="flex items-center justify-center h-full text-gray-500">
                                Aucun actif détecté ou API non connectée.
                            </div>
                        )}
                    </div>
                </div>

                {/* MARKET CARD */}
                <div className="bg-gray-800/50 p-6 rounded-lg border border-cyan-900/50 shadow-lg backdrop-blur-sm">
                    <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
                        <TrendingUp className="w-5 h-5" />
                        Marché Crypto (CAD)
                    </h2>
                    <div className="flex flex-col gap-4 h-64 overflow-y-auto pr-2 custom-scrollbar">
                        {SYMBOLS.map(sym => {
                            const data = tickers[sym];
                            if (!data) return null;
                            const isPositive = parseFloat(data.percentage) >= 0;
                            return (
                                <div key={sym} className="flex items-center justify-between p-3 bg-black/30 rounded border border-gray-700">
                                    <div className="font-bold text-white">{sym}</div>
                                    <div className="text-right">
                                        <div className="text-xl font-bold text-cyan-100">
                                            ${parseFloat(data.last).toLocaleString()}
                                        </div>
                                        <div className={`text-xs ${isPositive ? 'text-green-400' : 'text-red-400'}`}>
                                            {isPositive ? '+' : ''}{data.percentage}%
                                        </div>
                                    </div>
                                </div>
                            );
                        })}
                        {Object.keys(tickers).length === 0 && (
                            <div className="text-gray-500 text-center mt-10">Chargement des cours...</div>
                        )}
                    </div>
                </div>

                {/* NEWS CARD */}
                <div className="bg-gray-800/50 p-6 rounded-lg border border-cyan-900/50 shadow-lg backdrop-blur-sm md:col-span-2">
                    <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
                        <Activity className="w-5 h-5" />
                        Actualités Crypto (CryptoCompare)
                    </h2>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-h-96 overflow-y-auto custom-scrollbar">
                        {news.map(item => (
                            <a
                                key={item.id}
                                href={item.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="flex gap-4 p-3 bg-black/30 rounded border border-gray-700 hover:bg-gray-800 transition-colors group"
                            >
                                <img
                                    src={item.image}
                                    alt={item.title}
                                    className="w-20 h-20 object-cover rounded opacity-80 group-hover:opacity-100 transition-opacity"
                                />
                                <div className="flex flex-col justify-between">
                                    <h3 className="text-sm font-bold text-gray-200 group-hover:text-cyan-300 line-clamp-2">
                                        {item.title}
                                    </h3>
                                    <div className="flex items-center justify-between text-[10px] text-gray-500 mt-2">
                                        <span className="bg-gray-800 px-2 py-0.5 rounded text-cyan-500 uppercase font-bold">
                                            {item.source}
                                        </span>
                                        <span>
                                            {new Date(item.published_on * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                        </span>
                                    </div>
                                </div>
                            </a>
                        ))}
                        {news.length === 0 && (
                            <div className="text-gray-500 text-center col-span-2 py-10">Chargement des actualités...</div>
                        )}
                    </div>
                </div>
            </div>
            )}
        </div>
    );
};

export default Dashboard;
