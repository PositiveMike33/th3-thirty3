import React, { useState, useEffect } from 'react';

/**
 * Nexus33 Security - Dashboard Client
 * Tableau de bord pour visualiser les résultats de scans
 */

const SecurityDashboard = () => {
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [selectedScan, setSelectedScan] = useState(null);
    const [newDomain, setNewDomain] = useState('');
    const [scanning, setScanning] = useState(false);

    useEffect(() => {
        loadScans();
    }, []);

    const loadScans = async () => {
        try {
            const response = await fetch('/api/security/history');
            const data = await response.json();
            if (data.success) {
                setScans(data.scans);
            }
        } catch (error) {
            console.error('Error loading scans:', error);
        } finally {
            setLoading(false);
        }
    };

    const startNewScan = async (e) => {
        e.preventDefault();
        if (!newDomain.trim() || scanning) return;

        setScanning(true);
        try {
            const response = await fetch('/api/security/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain: newDomain.trim() })
            });

            const data = await response.json();
            if (data.success) {
                setNewDomain('');
                // Poll for completion
                pollScanStatus(data.scanId);
            }
        } catch (error) {
            console.error('Error starting scan:', error);
        }
    };

    const pollScanStatus = async (scanId) => {
        const checkStatus = async () => {
            try {
                const response = await fetch(`/api/security/scan/${scanId}`);
                const data = await response.json();

                if (data.status === 'completed' || data.status === 'failed') {
                    setScanning(false);
                    loadScans();
                } else {
                    setTimeout(checkStatus, 2000);
                }
            } catch (error) {
                setScanning(false);
            }
        };
        checkStatus();
    };

    const getGradeColor = (grade) => {
        const colors = {
            'A+': '#00c853', 'A': '#4caf50', 'B': '#8bc34a',
            'C': '#ffeb3b', 'D': '#ff9800', 'F': '#f44336'
        };
        return colors[grade] || '#9e9e9e';
    };

    const formatDate = (dateString) => {
        return new Date(dateString).toLocaleDateString('fr-CA', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    };

    if (loading) {
        return <div className="dashboard-loading">Chargement...</div>;
    }

    return (
        <div className="security-dashboard">
            {/* Header */}
            <header className="dashboard-header">
                <h1>🛡️ Nexus33 Security Dashboard</h1>
                <div className="header-actions">
                    <form onSubmit={startNewScan} className="new-scan-form">
                        <input
                            type="text"
                            value={newDomain}
                            onChange={(e) => setNewDomain(e.target.value)}
                            placeholder="Nouveau domaine..."
                            disabled={scanning}
                        />
                        <button type="submit" disabled={scanning || !newDomain.trim()}>
                            {scanning ? '⏳ Scan en cours...' : '🔍 Scanner'}
                        </button>
                    </form>
                </div>
            </header>

            {/* Stats Overview */}
            <section className="stats-overview">
                <div className="stat-card">
                    <span className="stat-value">{scans.length}</span>
                    <span className="stat-label">Scans Total</span>
                </div>
                <div className="stat-card">
                    <span className="stat-value">
                        {scans.filter(s => s.score >= 80).length}
                    </span>
                    <span className="stat-label">Sites Sécurisés</span>
                </div>
                <div className="stat-card">
                    <span className="stat-value">
                        {scans.filter(s => s.score < 60).length}
                    </span>
                    <span className="stat-label">Actions Requises</span>
                </div>
                <div className="stat-card">
                    <span className="stat-value">
                        {scans.length > 0 ? Math.round(scans.reduce((acc, s) => acc + (s.score || 0), 0) / scans.length) : '-'}
                    </span>
                    <span className="stat-label">Score Moyen</span>
                </div>
            </section>

            {/* Main Content */}
            <div className="dashboard-content">
                {/* Scans List */}
                <section className="scans-list">
                    <h2>Historique des Scans</h2>
                    {scans.length === 0 ? (
                        <div className="empty-state">
                            <p>Aucun scan effectué</p>
                            <p>Commencez par scanner votre premier domaine</p>
                        </div>
                    ) : (
                        <div className="scans-table">
                            {scans.map((scan) => (
                                <div
                                    key={scan.id}
                                    className={`scan-row ${selectedScan?.id === scan.id ? 'selected' : ''}`}
                                    onClick={() => setSelectedScan(scan)}
                                >
                                    <div className="scan-domain">
                                        <span className="domain-name">{scan.domain}</span>
                                        <span className="scan-date">{formatDate(scan.completedAt || scan.startedAt)}</span>
                                    </div>
                                    <div
                                        className="scan-grade"
                                        style={{ backgroundColor: getGradeColor(scan.grade) }}
                                    >
                                        {scan.grade || '-'}
                                    </div>
                                    <div className="scan-score">
                                        {scan.score !== undefined ? `${scan.score}/100` : 'En cours...'}
                                    </div>
                                    <div className={`scan-status ${scan.status}`}>
                                        {scan.status === 'completed' ? '✅' : scan.status === 'failed' ? '❌' : '⏳'}
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </section>

                {/* Scan Details */}
                {selectedScan && (
                    <section className="scan-details">
                        <h2>Détails: {selectedScan.domain}</h2>
                        <div className="detail-score">
                            <div
                                className="score-circle"
                                style={{ borderColor: getGradeColor(selectedScan.grade) }}
                            >
                                <span className="grade">{selectedScan.grade}</span>
                                <span className="score">{selectedScan.score}/100</span>
                            </div>
                        </div>

                        <div className="detail-sections">
                            <div className="detail-section">
                                <h3>🔒 SSL/TLS</h3>
                                <div className="section-score">
                                    {selectedScan.results?.ssl?.score || 0}/100
                                </div>
                            </div>
                            <div className="detail-section">
                                <h3>🛡️ Headers</h3>
                                <div className="section-score">
                                    {selectedScan.results?.headers?.score || 0}/100
                                </div>
                            </div>
                            <div className="detail-section">
                                <h3>📧 DNS/Email</h3>
                                <div className="section-score">
                                    {selectedScan.results?.dns?.score || 0}/100
                                </div>
                            </div>
                            <div className="detail-section">
                                <h3>🔍 Ports</h3>
                                <div className="section-score">
                                    {selectedScan.results?.ports?.score || 100}/100
                                </div>
                            </div>
                        </div>

                        <button
                            className="view-report-btn"
                            onClick={() => window.location.href = `/security/report/${selectedScan.id}`}
                        >
                            📄 Voir le Rapport Complet
                        </button>
                    </section>
                )}
            </div>

            <style jsx>{`
                .security-dashboard {
                    font-family: 'Inter', -apple-system, sans-serif;
                    background: #f5f6fa;
                    min-height: 100vh;
                    padding: 20px;
                }
                
                .dashboard-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 30px;
                    flex-wrap: wrap;
                    gap: 20px;
                }
                
                .dashboard-header h1 {
                    margin: 0;
                    color: #2d3436;
                }
                
                .new-scan-form {
                    display: flex;
                    gap: 10px;
                }
                
                .new-scan-form input {
                    padding: 10px 15px;
                    border: 2px solid #dfe6e9;
                    border-radius: 8px;
                    font-size: 1rem;
                    width: 250px;
                }
                
                .new-scan-form button {
                    padding: 10px 20px;
                    background: #667eea;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    cursor: pointer;
                    transition: transform 0.2s;
                }
                
                .new-scan-form button:hover:not(:disabled) {
                    transform: scale(1.02);
                }
                
                .stats-overview {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }
                
                .stat-card {
                    background: white;
                    padding: 25px;
                    border-radius: 12px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.05);
                    text-align: center;
                }
                
                .stat-value {
                    display: block;
                    font-size: 2.5rem;
                    font-weight: bold;
                    color: #667eea;
                }
                
                .stat-label {
                    color: #636e72;
                    font-size: 0.9rem;
                }
                
                .dashboard-content {
                    display: grid;
                    grid-template-columns: 1fr 400px;
                    gap: 30px;
                }
                
                @media (max-width: 1024px) {
                    .dashboard-content {
                        grid-template-columns: 1fr;
                    }
                }
                
                .scans-list, .scan-details {
                    background: white;
                    border-radius: 12px;
                    padding: 25px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.05);
                }
                
                .scans-list h2, .scan-details h2 {
                    margin-top: 0;
                    color: #2d3436;
                    border-bottom: 2px solid #f1f3f4;
                    padding-bottom: 15px;
                }
                
                .scan-row {
                    display: flex;
                    align-items: center;
                    padding: 15px;
                    border-radius: 8px;
                    cursor: pointer;
                    transition: background 0.2s;
                    gap: 15px;
                }
                
                .scan-row:hover {
                    background: #f8f9fa;
                }
                
                .scan-row.selected {
                    background: #e8f0fe;
                }
                
                .scan-domain {
                    flex: 1;
                }
                
                .domain-name {
                    display: block;
                    font-weight: 600;
                    color: #2d3436;
                }
                
                .scan-date {
                    font-size: 0.8rem;
                    color: #636e72;
                }
                
                .scan-grade {
                    width: 40px;
                    height: 40px;
                    border-radius: 8px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: white;
                    font-weight: bold;
                }
                
                .scan-score {
                    width: 70px;
                    text-align: right;
                    font-weight: 600;
                }
                
                .empty-state {
                    text-align: center;
                    padding: 40px;
                    color: #636e72;
                }
                
                .detail-score {
                    display: flex;
                    justify-content: center;
                    margin: 20px 0;
                }
                
                .score-circle {
                    width: 120px;
                    height: 120px;
                    border-radius: 50%;
                    border: 6px solid;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                }
                
                .score-circle .grade {
                    font-size: 2rem;
                    font-weight: bold;
                }
                
                .score-circle .score {
                    font-size: 0.9rem;
                    color: #636e72;
                }
                
                .detail-sections {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 15px;
                    margin: 20px 0;
                }
                
                .detail-section {
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 8px;
                    text-align: center;
                }
                
                .detail-section h3 {
                    margin: 0 0 10px;
                    font-size: 1rem;
                }
                
                .section-score {
                    font-size: 1.5rem;
                    font-weight: bold;
                    color: #667eea;
                }
                
                .view-report-btn {
                    width: 100%;
                    padding: 15px;
                    background: #667eea;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 1rem;
                    cursor: pointer;
                    transition: transform 0.2s;
                }
                
                .view-report-btn:hover {
                    transform: translateY(-2px);
                }
            `}</style>
        </div>
    );
};

export default SecurityDashboard;
