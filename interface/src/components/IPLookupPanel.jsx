import React, { useState } from 'react';
import { Globe, Search, MapPin, Shield, Server, Clock, Loader, Copy, CheckCircle, AlertTriangle } from 'lucide-react';
import { API_URL } from '../config';

/**
 * IP Lookup Panel Component
 * Integrates IP2Location and WHOIS APIs for OSINT investigations
 * Can be used in OSINT Dashboard and Project Dashboard
 */
const IPLookupPanel = ({ onLocationFound, compact = false }) => {
    const [query, setQuery] = useState('');
    const [lookupType, setLookupType] = useState('ip'); // ip, domain
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);
    const [copied, setCopied] = useState(false);

    const handleLookup = async () => {
        if (!query.trim()) return;
        
        setLoading(true);
        setError(null);
        setResult(null);

        try {
            let data;
            
            if (lookupType === 'ip') {
                // IP Geolocation lookup
                const res = await fetch(`${API_URL}/api/ip2location/lookup?ip=${encodeURIComponent(query)}`);
                data = await res.json();
                
                if (data.success && data.data.coordinates && onLocationFound) {
                    onLocationFound({
                        lat: data.data.coordinates.latitude,
                        lng: data.data.coordinates.longitude,
                        label: `${query} - ${data.data.city}, ${data.data.country?.name}`
                    });
                }
            } else {
                // WHOIS domain lookup
                const res = await fetch(`${API_URL}/api/whois/lookup?domain=${encodeURIComponent(query)}`);
                data = await res.json();
            }

            if (data.success) {
                setResult(data.data);
            } else {
                setError(data.error || 'Lookup failed');
            }
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const renderIPResult = () => {
        if (!result) return null;
        
        return (
            <div className="space-y-3 animate-in fade-in slide-in-from-bottom-2 duration-300">
                {/* Location Header */}
                <div className="flex items-center gap-3 bg-gradient-to-r from-cyan-900/30 to-purple-900/30 p-3 rounded-lg border border-cyan-500/30">
                    <MapPin size={24} className="text-cyan-400" />
                    <div className="flex-1">
                        <div className="text-white font-bold">{result.city}, {result.region}</div>
                        <div className="text-gray-400 text-sm">{result.country?.name} ({result.country?.code})</div>
                    </div>
                    <button 
                        onClick={() => copyToClipboard(JSON.stringify(result, null, 2))}
                        className="p-2 bg-gray-800 hover:bg-gray-700 rounded text-gray-400 hover:text-white transition-colors"
                        title="Copy JSON"
                    >
                        {copied ? <CheckCircle size={16} className="text-green-400" /> : <Copy size={16} />}
                    </button>
                </div>

                {/* Details Grid */}
                <div className={`grid ${compact ? 'grid-cols-1' : 'grid-cols-2'} gap-2`}>
                    <DetailBox icon={<Globe size={14} />} label="IP" value={result.ip} />
                    <DetailBox icon={<MapPin size={14} />} label="Coordinates" value={`${result.coordinates?.latitude}, ${result.coordinates?.longitude}`} />
                    <DetailBox icon={<Clock size={14} />} label="Timezone" value={result.timezone} />
                    <DetailBox icon={<Server size={14} />} label="ISP / ASN" value={`${result.network?.as_name} (${result.network?.asn})`} />
                    <DetailBox icon={<Shield size={14} />} label="Proxy" value={result.security?.is_proxy ? '⚠️ YES' : '✅ No'} highlight={result.security?.is_proxy} />
                    <DetailBox icon={<MapPin size={14} />} label="Zip Code" value={result.zip_code || 'N/A'} />
                </div>

                {/* Map Preview Button */}
                {result.coordinates && (
                    <a
                        href={`https://www.google.com/maps?q=${result.coordinates.latitude},${result.coordinates.longitude}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="block w-full text-center py-2 bg-cyan-900/30 hover:bg-cyan-800/50 text-cyan-300 rounded border border-cyan-700 text-sm transition-colors"
                    >
                        🗺️ Voir sur Google Maps
                    </a>
                )}
            </div>
        );
    };

    const renderWHOISResult = () => {
        if (!result) return null;
        
        // Calculate days until expiration
        const expiresDate = result.dates?.expires ? new Date(result.dates.expires) : null;
        const daysUntilExpiry = expiresDate ? Math.ceil((expiresDate - new Date()) / (1000 * 60 * 60 * 24)) : null;
        const isExpiringSoon = daysUntilExpiry && daysUntilExpiry < 30;

        return (
            <div className="space-y-3 animate-in fade-in slide-in-from-bottom-2 duration-300">
                {/* Domain Header */}
                <div className="flex items-center gap-3 bg-gradient-to-r from-green-900/30 to-emerald-900/30 p-3 rounded-lg border border-green-500/30">
                    <Globe size={24} className="text-green-400" />
                    <div className="flex-1">
                        <div className="text-white font-bold">{result.domain}</div>
                        <div className="text-gray-400 text-sm">Registrar: {result.registrar?.name}</div>
                    </div>
                    <button 
                        onClick={() => copyToClipboard(JSON.stringify(result, null, 2))}
                        className="p-2 bg-gray-800 hover:bg-gray-700 rounded text-gray-400 hover:text-white transition-colors"
                        title="Copy JSON"
                    >
                        {copied ? <CheckCircle size={16} className="text-green-400" /> : <Copy size={16} />}
                    </button>
                </div>

                {/* Dates Grid */}
                <div className={`grid ${compact ? 'grid-cols-1' : 'grid-cols-2'} gap-2`}>
                    <DetailBox 
                        icon={<Clock size={14} />} 
                        label="Created" 
                        value={result.dates?.created ? new Date(result.dates.created).toLocaleDateString() : 'N/A'} 
                    />
                    <DetailBox 
                        icon={<Clock size={14} />} 
                        label="Updated" 
                        value={result.dates?.updated ? new Date(result.dates.updated).toLocaleDateString() : 'N/A'} 
                    />
                    <DetailBox 
                        icon={<AlertTriangle size={14} />} 
                        label="Expires" 
                        value={expiresDate ? expiresDate.toLocaleDateString() : 'N/A'} 
                        highlight={isExpiringSoon}
                    />
                    <DetailBox 
                        icon={<Clock size={14} />} 
                        label="Age" 
                        value={result.dates?.age_days ? `${result.dates.age_days} days` : 'N/A'} 
                    />
                </div>

                {/* Nameservers */}
                {result.nameservers?.length > 0 && (
                    <div className="bg-black/40 rounded-lg p-3 border border-gray-700">
                        <div className="text-xs text-gray-500 mb-2 flex items-center gap-2">
                            <Server size={12} />
                            NAMESERVERS ({result.nameservers.length})
                        </div>
                        <div className="flex flex-wrap gap-1">
                            {result.nameservers.slice(0, 4).map((ns, i) => (
                                <span key={i} className="text-xs bg-gray-800 text-green-300 px-2 py-1 rounded font-mono">
                                    {ns}
                                </span>
                            ))}
                            {result.nameservers.length > 4 && (
                                <span className="text-xs text-gray-500">+{result.nameservers.length - 4} more</span>
                            )}
                        </div>
                    </div>
                )}

                {/* Registrar Link */}
                {result.registrar?.url && (
                    <a
                        href={result.registrar.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="block w-full text-center py-2 bg-green-900/30 hover:bg-green-800/50 text-green-300 rounded border border-green-700 text-sm transition-colors"
                    >
                        🔗 Registrar: {result.registrar.name}
                    </a>
                )}
            </div>
        );
    };

    return (
        <div className={`bg-gray-900/50 border border-cyan-800/50 rounded-lg overflow-hidden ${compact ? 'p-3' : 'p-4'}`}>
            {/* Header */}
            <div className="flex items-center gap-2 mb-3">
                <Globe size={18} className="text-cyan-400" />
                <h3 className="font-bold text-cyan-300 text-sm tracking-wider">IP & DOMAIN LOOKUP</h3>
            </div>

            {/* Type Toggle */}
            <div className="flex gap-2 mb-3">
                <button
                    onClick={() => { setLookupType('ip'); setResult(null); setError(null); }}
                    className={`flex-1 py-1.5 rounded text-xs font-bold transition-all ${
                        lookupType === 'ip'
                            ? 'bg-cyan-900/50 text-cyan-300 border border-cyan-600'
                            : 'bg-gray-800 text-gray-400 border border-gray-700 hover:border-cyan-700'
                    }`}
                >
                    🌐 IP Lookup
                </button>
                <button
                    onClick={() => { setLookupType('domain'); setResult(null); setError(null); }}
                    className={`flex-1 py-1.5 rounded text-xs font-bold transition-all ${
                        lookupType === 'domain'
                            ? 'bg-green-900/50 text-green-300 border border-green-600'
                            : 'bg-gray-800 text-gray-400 border border-gray-700 hover:border-green-700'
                    }`}
                >
                    🔍 WHOIS
                </button>
            </div>

            {/* Search Input */}
            <div className="flex gap-2 mb-3">
                <input
                    type="text"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleLookup()}
                    placeholder={lookupType === 'ip' ? 'Enter IP address...' : 'Enter domain...'}
                    className="flex-1 bg-black border border-gray-700 rounded px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-cyan-500 outline-none"
                />
                <button
                    onClick={handleLookup}
                    disabled={loading || !query.trim()}
                    className="px-4 py-2 bg-cyan-900/50 hover:bg-cyan-800 text-cyan-300 rounded border border-cyan-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                    {loading ? <Loader size={16} className="animate-spin" /> : <Search size={16} />}
                </button>
            </div>

            {/* Error */}
            {error && (
                <div className="bg-red-900/20 border border-red-700 rounded p-3 mb-3 text-red-400 text-sm flex items-center gap-2">
                    <AlertTriangle size={16} />
                    {error}
                </div>
            )}

            {/* Results */}
            {lookupType === 'ip' && renderIPResult()}
            {lookupType === 'domain' && renderWHOISResult()}
        </div>
    );
};

// Helper component for detail boxes
const DetailBox = ({ icon, label, value, highlight = false }) => (
    <div className={`bg-black/40 rounded p-2 border ${highlight ? 'border-red-700 bg-red-900/20' : 'border-gray-700'}`}>
        <div className="flex items-center gap-1 text-gray-500 text-xs mb-1">
            {icon}
            <span>{label}</span>
        </div>
        <div className={`text-sm font-mono truncate ${highlight ? 'text-red-400' : 'text-white'}`}>
            {value || 'N/A'}
        </div>
    </div>
);

export default IPLookupPanel;
