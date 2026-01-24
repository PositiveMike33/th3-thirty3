import React, { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import {
    Search, Globe, User, Mail, Database, Camera,
    FileText, Lock, Phone, Users, MapPin, Building,
    Briefcase, Image, Video, MessageSquare, Code, Wifi,
    ZoomIn, ZoomOut, Maximize2, RotateCcw, ExternalLink,
    ChevronRight, ChevronDown, Eye, Server, Shield, Hash,
    Smartphone, Car, Plane, Ship, CreditCard, Bitcoin,
    Radio, Newspaper, BookOpen, Map, Filter, X
} from 'lucide-react';
import osintData from '../data/osintFramework.json';

// Icon mapping for categories
const categoryIcons = {
    'Username': User,
    'Email Address': Mail,
    'Domain Name': Globe,
    'IP Address': Server,
    'Social Networks': Users,
    'Instant Messaging': MessageSquare,
    'People Search Engines': Search,
    'Dating': Users,
    'Telephone Numbers': Phone,
    'Public Records': FileText,
    'Business Records': Building,
    'Transportation': Car,
    'Geolocation Tools / Maps': MapPin,
    'Search Engines': Search,
    'Forums / Blogs / IRC': MessageSquare,
    'Archives': Database,
    'Language Translation': BookOpen,
    'Metadata': Code,
    'Mobile Emulation': Smartphone,
    'Terrorism': Shield,
    'Dark Web': Lock,
    'Digital Currency': Bitcoin,
    'Classifieds': Newspaper,
    'Encoding / Decoding': Hash,
    'Tools': Code,
    'Malicious File Analysis': Shield,
    'Exploits & Advisories': Shield,
    'Threat Intelligence': Eye,
    'OpSec': Lock,
    'Documentation / Reference': BookOpen,
    'Training': BookOpen,
    'default': Globe
};

// Color mapping for categories
const categoryColors = {
    'Username': '#22c55e',
    'Email Address': '#3b82f6',
    'Domain Name': '#8b5cf6',
    'IP Address': '#f59e0b',
    'Social Networks': '#ec4899',
    'Instant Messaging': '#06b6d4',
    'People Search Engines': '#84cc16',
    'Dating': '#f43f5e',
    'Telephone Numbers': '#eab308',
    'Public Records': '#14b8a6',
    'Business Records': '#6366f1',
    'Transportation': '#a855f7',
    'Geolocation Tools / Maps': '#0ea5e9',
    'Search Engines': '#10b981',
    'Forums / Blogs / IRC': '#f97316',
    'Archives': '#64748b',
    'Language Translation': '#8b5cf6',
    'Metadata': '#ef4444',
    'Dark Web': '#7c3aed',
    'Digital Currency': '#f59e0b',
    'Tools': '#06b6d4',
    'Threat Intelligence': '#dc2626',
    'default': '#6b7280'
};

const OsintMindMap = ({ onToolSelect, activeTarget }) => {
    const containerRef = useRef(null);
    const [dimensions, setDimensions] = useState({ width: 800, height: 500 });
    const [zoom, setZoom] = useState(0.9);
    const [pan, setPan] = useState({ x: 0, y: 0 });
    const [isDragging, setIsDragging] = useState(false);
    const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
    const [selectedCategory, setSelectedCategory] = useState(null);
    const [expandedNodes, setExpandedNodes] = useState({});
    const [searchQuery, setSearchQuery] = useState('');
    const [viewMode, setViewMode] = useState('tree'); // 'tree' or 'list'

    // Parse OSINT Framework data
    const categories = useMemo(() => {
        if (!osintData || !osintData.children) return [];
        return osintData.children.filter(item => item.type === 'folder');
    }, []);

    // Search filter
    const filterTools = useCallback((items, query) => {
        if (!query) return items;
        const lowerQuery = query.toLowerCase();

        const filterRecursive = (item) => {
            if (item.type === 'url') {
                return item.name.toLowerCase().includes(lowerQuery);
            }
            if (item.children) {
                const filteredChildren = item.children
                    .map(child => filterRecursive(child) ? child : null)
                    .filter(Boolean);
                if (filteredChildren.length > 0 || item.name.toLowerCase().includes(lowerQuery)) {
                    return { ...item, children: filteredChildren };
                }
            }
            return null;
        };

        return items.map(filterRecursive).filter(Boolean);
    }, []);

    const filteredCategories = useMemo(() => {
        return filterTools(categories, searchQuery);
    }, [categories, searchQuery, filterTools]);

    useEffect(() => {
        const updateDimensions = () => {
            if (containerRef.current) {
                setDimensions({
                    width: containerRef.current.offsetWidth,
                    height: containerRef.current.offsetHeight
                });
            }
        };
        updateDimensions();
        window.addEventListener('resize', updateDimensions);
        return () => window.removeEventListener('resize', updateDimensions);
    }, []);

    // Zoom controls
    const handleZoomIn = () => setZoom(prev => Math.min(prev + 0.15, 2));
    const handleZoomOut = () => setZoom(prev => Math.max(prev - 0.15, 0.3));
    const handleFitView = () => { setZoom(0.9); setPan({ x: 0, y: 0 }); };
    const handleResetView = () => { setZoom(1); setPan({ x: 0, y: 0 }); };

    // Pan controls
    const handleMouseDown = (e) => {
        if (e.target.closest('.node-interactive') || e.target.closest('.no-drag')) return;
        setIsDragging(true);
        setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    };

    const handleMouseMove = useCallback((e) => {
        if (!isDragging) return;
        setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
    }, [isDragging, dragStart]);

    const handleMouseUp = () => setIsDragging(false);

    const handleWheel = (e) => {
        e.preventDefault();
        const delta = e.deltaY > 0 ? -0.08 : 0.08;
        setZoom(prev => Math.max(0.3, Math.min(2, prev + delta)));
    };

    useEffect(() => {
        if (isDragging) {
            window.addEventListener('mousemove', handleMouseMove);
            window.addEventListener('mouseup', handleMouseUp);
        }
        return () => {
            window.removeEventListener('mousemove', handleMouseMove);
            window.removeEventListener('mouseup', handleMouseUp);
        };
    }, [isDragging, handleMouseMove]);

    // Toggle expanded node
    const toggleNode = (path) => {
        setExpandedNodes(prev => ({ ...prev, [path]: !prev[path] }));
    };

    // Open external link
    const openLink = (url) => {
        window.open(url, '_blank', 'noopener,noreferrer');
    };

    // Render tree node recursively
    const renderNode = (node, path = '', depth = 0) => {
        const nodePath = path ? `${path}/${node.name}` : node.name;
        const isExpanded = expandedNodes[nodePath];
        const hasChildren = node.children && node.children.length > 0;
        const Icon = categoryIcons[node.name] || categoryIcons.default;
        const color = categoryColors[node.name] || categoryColors.default;

        if (node.type === 'url') {
            return (
                <div
                    key={nodePath}
                    className="node-interactive flex items-center gap-2 py-1.5 px-3 hover:bg-white/5 rounded cursor-pointer transition-colors group"
                    style={{ marginLeft: depth * 16 }}
                    onClick={() => openLink(node.url)}
                >
                    <ExternalLink size={12} className="text-gray-500 group-hover:text-cyan-400 flex-shrink-0" />
                    <span className="text-[11px] text-gray-300 group-hover:text-white truncate">
                        {node.name}
                    </span>
                    <span className="text-[9px] text-gray-600 ml-auto opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">
                        Ouvrir ↗
                    </span>
                </div>
            );
        }

        return (
            <div key={nodePath}>
                <div
                    className={`node-interactive flex items-center gap-2 py-2 px-3 cursor-pointer transition-colors rounded ${depth === 0 ? 'hover:bg-white/10' : 'hover:bg-white/5'
                        }`}
                    style={{ marginLeft: depth * 16 }}
                    onClick={() => toggleNode(nodePath)}
                >
                    {hasChildren && (
                        isExpanded ?
                            <ChevronDown size={14} className="text-gray-400 flex-shrink-0" /> :
                            <ChevronRight size={14} className="text-gray-400 flex-shrink-0" />
                    )}
                    {!hasChildren && <div className="w-3.5" />}

                    <div
                        className="w-6 h-6 rounded flex items-center justify-center flex-shrink-0"
                        style={{ backgroundColor: `${color}20`, border: `1px solid ${color}50` }}
                    >
                        <Icon size={12} style={{ color }} />
                    </div>

                    <span className={`${depth === 0 ? 'text-sm font-semibold' : 'text-[11px]'} text-white truncate`}>
                        {node.name}
                    </span>

                    {hasChildren && (
                        <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-gray-800 text-gray-400 ml-auto flex-shrink-0">
                            {node.children.length}
                        </span>
                    )}
                </div>

                {isExpanded && hasChildren && (
                    <div className="border-l border-gray-800/50 ml-6">
                        {node.children.map(child => renderNode(child, nodePath, depth + 1))}
                    </div>
                )}
            </div>
        );
    };

    // Count total tools
    const countTools = (node) => {
        if (node.type === 'url') return 1;
        if (!node.children) return 0;
        return node.children.reduce((sum, child) => sum + countTools(child), 0);
    };
    const totalTools = useMemo(() => categories.reduce((sum, cat) => sum + countTools(cat), 0), [categories]);

    return (
        <div className="flex flex-col gap-3 h-full">
            {/* Controls Bar */}
            <div className="flex items-center justify-between bg-gray-900/80 border border-gray-700 rounded-lg px-3 py-2 flex-wrap gap-2">
                <div className="flex items-center gap-3">
                    <div className="flex items-center gap-2">
                        <Eye size={16} className="text-cyan-500" />
                        <span className="text-xs text-gray-400 uppercase tracking-wider">OSINT Framework</span>
                    </div>
                    <div className="hidden sm:flex items-center gap-2 text-[10px] text-gray-500">
                        <span className="px-2 py-0.5 bg-gray-800 rounded">{categories.length} catégories</span>
                        <span className="px-2 py-0.5 bg-cyan-900/30 text-cyan-400 rounded">{totalTools}+ outils</span>
                    </div>
                </div>

                {/* Search */}
                <div className="flex items-center gap-2 flex-1 max-w-md mx-4">
                    <div className="relative flex-1">
                        <Search size={14} className="absolute left-2 top-1/2 -translate-y-1/2 text-gray-500" />
                        <input
                            type="text"
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            placeholder="Rechercher un outil..."
                            className="no-drag w-full bg-gray-800 border border-gray-700 rounded pl-8 pr-8 py-1.5 text-xs text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
                        />
                        {searchQuery && (
                            <button
                                onClick={() => setSearchQuery('')}
                                className="no-drag absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-white"
                            >
                                <X size={12} />
                            </button>
                        )}
                    </div>
                </div>

                {/* View & Zoom Controls */}
                <div className="flex items-center gap-2">
                    <button
                        onClick={handleFitView}
                        className="no-drag flex items-center gap-1 px-2 py-1 bg-gray-800 hover:bg-gray-700 border border-gray-600 rounded text-xs text-gray-300 transition-colors"
                        title="Voir tout"
                    >
                        <Maximize2 size={12} />
                    </button>
                    <button
                        onClick={handleResetView}
                        className="no-drag p-1.5 bg-gray-800 hover:bg-gray-700 border border-gray-600 rounded text-gray-300 transition-colors"
                        title="Réinitialiser"
                    >
                        <RotateCcw size={12} />
                    </button>
                    <div className="flex items-center bg-gray-800 border border-gray-600 rounded">
                        <button onClick={handleZoomOut} className="no-drag p-1.5 hover:bg-gray-700 text-gray-300 transition-colors border-r border-gray-600">
                            <ZoomOut size={12} />
                        </button>
                        <span className="px-2 text-[10px] text-cyan-400 font-mono min-w-[40px] text-center">
                            {Math.round(zoom * 100)}%
                        </span>
                        <button onClick={handleZoomIn} className="no-drag p-1.5 hover:bg-gray-700 text-gray-300 transition-colors border-l border-gray-600">
                            <ZoomIn size={12} />
                        </button>
                    </div>
                </div>
            </div>

            {/* Main Container */}
            <div
                ref={containerRef}
                className="relative flex-1 min-h-[450px] bg-gradient-to-br from-gray-900 via-gray-950 to-black rounded-xl border border-gray-800 overflow-hidden cursor-grab active:cursor-grabbing"
                onMouseDown={handleMouseDown}
                onWheel={handleWheel}
            >
                {/* Background particles */}
                <div className="absolute inset-0 opacity-20 pointer-events-none">
                    <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_30%,rgba(34,211,238,0.1),transparent_50%)]" />
                    <div className="absolute inset-0 bg-[radial-gradient(circle_at_70%_70%,rgba(139,92,246,0.1),transparent_50%)]" />
                </div>

                {/* Scrollable Tree View */}
                <div
                    className="absolute inset-0 overflow-auto p-4"
                    style={{
                        transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
                        transformOrigin: 'top left'
                    }}
                >
                    {/* Central Header */}
                    <div className="flex items-center gap-3 mb-4 pb-4 border-b border-gray-800">
                        <div className="relative">
                            <div className="absolute inset-0 bg-gradient-to-r from-cyan-500 to-purple-600 rounded-full blur-lg opacity-50" />
                            <div className="relative w-14 h-14 bg-gradient-to-br from-gray-900 to-gray-800 rounded-full border-2 border-cyan-500/50 flex flex-col items-center justify-center">
                                <Eye size={20} className="text-cyan-400" />
                                <span className="text-[7px] font-bold text-white">OSINT</span>
                            </div>
                        </div>
                        <div>
                            <h2 className="text-lg font-bold text-white">OSINT Framework</h2>
                            <p className="text-[10px] text-gray-500">Cliquez sur une catégorie pour l'explorer • Cliquez sur un outil pour l'ouvrir</p>
                        </div>
                        <a
                            href="https://osintframework.com/"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="no-drag ml-auto flex items-center gap-1 px-3 py-1.5 bg-cyan-900/30 border border-cyan-700/50 rounded text-[10px] text-cyan-400 hover:bg-cyan-900/50 transition-colors"
                        >
                            <ExternalLink size={10} />
                            Site Officiel
                        </a>
                    </div>

                    {/* Categories Grid/Tree */}
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                        {filteredCategories.map(category => {
                            const Icon = categoryIcons[category.name] || categoryIcons.default;
                            const color = categoryColors[category.name] || categoryColors.default;
                            const isExpanded = expandedNodes[category.name];
                            const toolCount = countTools(category);

                            return (
                                <div
                                    key={category.name}
                                    className="bg-gray-900/50 border border-gray-800 rounded-lg overflow-hidden"
                                >
                                    {/* Category Header */}
                                    <div
                                        className="node-interactive flex items-center gap-3 p-3 cursor-pointer hover:bg-white/5 transition-colors border-b border-gray-800"
                                        style={{ borderLeftColor: color, borderLeftWidth: 3 }}
                                        onClick={() => toggleNode(category.name)}
                                    >
                                        {isExpanded ?
                                            <ChevronDown size={16} className="text-gray-400" /> :
                                            <ChevronRight size={16} className="text-gray-400" />
                                        }
                                        <div
                                            className="w-8 h-8 rounded-lg flex items-center justify-center"
                                            style={{ backgroundColor: `${color}20` }}
                                        >
                                            <Icon size={16} style={{ color }} />
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <div className="text-sm font-semibold text-white truncate">{category.name}</div>
                                            <div className="text-[9px] text-gray-500">{toolCount} outils</div>
                                        </div>
                                    </div>

                                    {/* Category Content */}
                                    {isExpanded && category.children && (
                                        <div className="max-h-[300px] overflow-y-auto bg-black/20">
                                            {category.children.map(child => renderNode(child, category.name, 0))}
                                        </div>
                                    )}
                                </div>
                            );
                        })}
                    </div>

                    {/* No results */}
                    {filteredCategories.length === 0 && searchQuery && (
                        <div className="text-center py-10 text-gray-500">
                            <Search size={32} className="mx-auto mb-2 opacity-30" />
                            <p className="text-sm">Aucun résultat pour "{searchQuery}"</p>
                        </div>
                    )}
                </div>

                {/* Target indicator */}
                {activeTarget && (
                    <div className="absolute top-3 right-3 bg-cyan-900/50 border border-cyan-700/50 rounded px-2 py-1 z-20">
                        <span className="text-[9px] text-cyan-400">Cible: </span>
                        <span className="text-[10px] text-white font-mono">{activeTarget}</span>
                    </div>
                )}

                {/* Zoom indicator */}
                <div className="absolute bottom-3 right-3 text-[9px] text-gray-600 z-20">
                    Zoom: {Math.round(zoom * 100)}% | Glisser pour déplacer
                </div>
            </div>
        </div>
    );
};

export default OsintMindMap;
