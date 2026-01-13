import React, { useState } from 'react';

/**
 * Nexus33 Security - Landing Page
 * Page marketing pour le SaaS de cybersécurité PME
 */

const SecurityLanding = () => {
    const [domain, setDomain] = useState('');
    const [scanning, setScanning] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);

    const handleQuickScan = async (e) => {
        e.preventDefault();
        if (!domain.trim()) return;

        setScanning(true);
        setError(null);
        setResult(null);

        try {
            const response = await fetch('/api/security/quick-scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain: domain.trim() })
            });

            const data = await response.json();

            if (data.success) {
                setResult(data);
            } else {
                setError(data.error || 'Erreur lors du scan');
            }
        } catch (err) {
            setError('Erreur de connexion au serveur');
        } finally {
            setScanning(false);
        }
    };

    const getGradeColor = (grade) => {
        const colors = {
            'A+': '#00c853', 'A': '#4caf50', 'B': '#8bc34a',
            'C': '#ffeb3b', 'D': '#ff9800', 'F': '#f44336'
        };
        return colors[grade] || '#9e9e9e';
    };

    return (
        <div className="security-landing">
            {/* Hero Section */}
            <section className="hero">
                <div className="hero-content">
                    <h1>🛡️ Nexus33 Security</h1>
                    <h2>Protégez votre entreprise contre les cybermenaces</h2>
                    <p className="subtitle">
                        La première plateforme de cybersécurité au Québec conçue pour les PME.
                        Conforme à la Loi 25. Alimentée par l'IA.
                    </p>

                    {/* Quick Scan Form */}
                    <form className="quick-scan-form" onSubmit={handleQuickScan}>
                        <div className="input-group">
                            <input
                                type="text"
                                value={domain}
                                onChange={(e) => setDomain(e.target.value)}
                                placeholder="Entrez votre domaine (ex: monentreprise.ca)"
                                disabled={scanning}
                            />
                            <button type="submit" disabled={scanning || !domain.trim()}>
                                {scanning ? '⏳ Analyse...' : '🔍 Scan Gratuit'}
                            </button>
                        </div>
                    </form>

                    {error && <div className="error-message">❌ {error}</div>}

                    {result && (
                        <div className="quick-result">
                            <div className="score-badge" style={{ backgroundColor: getGradeColor(result.grade) }}>
                                <span className="grade">{result.grade}</span>
                                <span className="score">{result.quickScore}/100</span>
                            </div>
                            <div className="result-details">
                                <p><strong>SSL/TLS:</strong> {result.ssl.score}/100 ({result.ssl.valid ? '✅ Valide' : '❌ Invalide'})</p>
                                <p><strong>Headers:</strong> {result.headers.score}/100 ({result.headers.present}/{result.headers.present + result.headers.missing} présents)</p>
                            </div>
                            <button className="cta-button" onClick={() => window.location.href = '/pricing'}>
                                🚀 Voir le rapport complet
                            </button>
                        </div>
                    )}
                </div>
            </section>

            {/* Features Section */}
            <section className="features">
                <h2>Pourquoi Nexus33 Security?</h2>
                <div className="features-grid">
                    <div className="feature-card">
                        <span className="feature-icon">🔒</span>
                        <h3>Scan SSL/TLS</h3>
                        <p>Vérification complète de vos certificats et protocoles de sécurité</p>
                    </div>
                    <div className="feature-card">
                        <span className="feature-icon">🛡️</span>
                        <h3>Headers de Sécurité</h3>
                        <p>Analyse des headers HTTP pour prévenir XSS, clickjacking et plus</p>
                    </div>
                    <div className="feature-card">
                        <span className="feature-icon">📧</span>
                        <h3>Sécurité Email</h3>
                        <p>Vérification SPF, DKIM et DMARC pour protéger contre le spoofing</p>
                    </div>
                    <div className="feature-card">
                        <span className="feature-icon">🔍</span>
                        <h3>Scan de Ports</h3>
                        <p>Détection des ports exposés et services vulnérables via Shodan</p>
                    </div>
                    <div className="feature-card">
                        <span className="feature-icon">⚖️</span>
                        <h3>Conformité Loi 25</h3>
                        <p>Rapport automatisé pour démontrer votre conformité</p>
                    </div>
                    <div className="feature-card">
                        <span className="feature-icon">🤖</span>
                        <h3>IA Recommandations</h3>
                        <p>Conseils personnalisés générés par notre IA de sécurité</p>
                    </div>
                </div>
            </section>

            {/* Pricing Section */}
            <section className="pricing" id="pricing">
                <h2>Tarification Simple</h2>
                <div className="pricing-grid">
                    <div className="pricing-card">
                        <h3>Starter</h3>
                        <div className="price">99$<span>/mois</span></div>
                        <ul>
                            <li>✓ 1 domaine surveillé</li>
                            <li>✓ 4 scans par mois</li>
                            <li>✓ Rapport de base</li>
                            <li>✓ Alertes email</li>
                        </ul>
                        <button className="pricing-cta">Commencer</button>
                    </div>
                    <div className="pricing-card recommended">
                        <div className="badge">Recommandé</div>
                        <h3>Pro</h3>
                        <div className="price">199$<span>/mois</span></div>
                        <ul>
                            <li>✓ 5 domaines surveillés</li>
                            <li>✓ Scans illimités</li>
                            <li>✓ Rapport Loi 25</li>
                            <li>✓ Scan Shodan</li>
                            <li>✓ Support prioritaire</li>
                        </ul>
                        <button className="pricing-cta primary">Commencer</button>
                    </div>
                    <div className="pricing-card">
                        <h3>Enterprise</h3>
                        <div className="price">499$<span>/mois</span></div>
                        <ul>
                            <li>✓ Domaines illimités</li>
                            <li>✓ Accès API</li>
                            <li>✓ Account manager</li>
                            <li>✓ Formation équipe</li>
                        </ul>
                        <button className="pricing-cta">Contactez-nous</button>
                    </div>
                </div>
            </section>

            {/* CTA Section */}
            <section className="cta-section">
                <h2>Prêt à sécuriser votre entreprise?</h2>
                <p>Commencez avec un scan gratuit aujourd'hui</p>
                <button className="main-cta" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>
                    🚀 Scanner Mon Site Maintenant
                </button>
            </section>

            <style jsx>{`
                .security-landing {
                    font-family: 'Inter', -apple-system, sans-serif;
                    color: #1a1a2e;
                }
                
                .hero {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 80px 20px;
                    text-align: center;
                }
                
                .hero h1 {
                    font-size: 3rem;
                    margin-bottom: 0.5rem;
                }
                
                .hero h2 {
                    font-size: 1.5rem;
                    font-weight: 400;
                    margin-bottom: 1rem;
                }
                
                .subtitle {
                    font-size: 1.1rem;
                    opacity: 0.9;
                    max-width: 600px;
                    margin: 0 auto 2rem;
                }
                
                .quick-scan-form {
                    max-width: 500px;
                    margin: 0 auto;
                }
                
                .input-group {
                    display: flex;
                    gap: 10px;
                }
                
                .input-group input {
                    flex: 1;
                    padding: 15px 20px;
                    border: none;
                    border-radius: 8px;
                    font-size: 1rem;
                }
                
                .input-group button {
                    padding: 15px 30px;
                    background: #00c853;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 1rem;
                    cursor: pointer;
                    transition: transform 0.2s;
                }
                
                .input-group button:hover:not(:disabled) {
                    transform: scale(1.05);
                }
                
                .input-group button:disabled {
                    opacity: 0.7;
                    cursor: not-allowed;
                }
                
                .quick-result {
                    background: rgba(255,255,255,0.1);
                    border-radius: 12px;
                    padding: 20px;
                    margin-top: 20px;
                    display: flex;
                    align-items: center;
                    gap: 20px;
                    flex-wrap: wrap;
                    justify-content: center;
                }
                
                .score-badge {
                    width: 100px;
                    height: 100px;
                    border-radius: 50%;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    color: white;
                }
                
                .score-badge .grade {
                    font-size: 2rem;
                    font-weight: bold;
                }
                
                .score-badge .score {
                    font-size: 0.9rem;
                }
                
                .error-message {
                    background: rgba(244, 67, 54, 0.2);
                    padding: 10px 20px;
                    border-radius: 8px;
                    margin-top: 10px;
                }
                
                .features {
                    padding: 80px 20px;
                    background: #f8f9fa;
                }
                
                .features h2 {
                    text-align: center;
                    font-size: 2rem;
                    margin-bottom: 40px;
                }
                
                .features-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                    gap: 30px;
                    max-width: 1200px;
                    margin: 0 auto;
                }
                
                .feature-card {
                    background: white;
                    padding: 30px;
                    border-radius: 12px;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    text-align: center;
                }
                
                .feature-icon {
                    font-size: 3rem;
                    display: block;
                    margin-bottom: 15px;
                }
                
                .pricing {
                    padding: 80px 20px;
                }
                
                .pricing h2 {
                    text-align: center;
                    font-size: 2rem;
                    margin-bottom: 40px;
                }
                
                .pricing-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                    gap: 30px;
                    max-width: 1000px;
                    margin: 0 auto;
                }
                
                .pricing-card {
                    background: white;
                    padding: 30px;
                    border-radius: 12px;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    text-align: center;
                    position: relative;
                }
                
                .pricing-card.recommended {
                    border: 3px solid #667eea;
                    transform: scale(1.05);
                }
                
                .pricing-card .badge {
                    position: absolute;
                    top: -12px;
                    left: 50%;
                    transform: translateX(-50%);
                    background: #667eea;
                    color: white;
                    padding: 5px 15px;
                    border-radius: 20px;
                    font-size: 0.8rem;
                }
                
                .price {
                    font-size: 3rem;
                    font-weight: bold;
                    color: #667eea;
                    margin: 20px 0;
                }
                
                .price span {
                    font-size: 1rem;
                    color: #666;
                }
                
                .pricing-card ul {
                    list-style: none;
                    padding: 0;
                    text-align: left;
                    margin: 20px 0;
                }
                
                .pricing-card li {
                    padding: 8px 0;
                    border-bottom: 1px solid #eee;
                }
                
                .pricing-cta {
                    width: 100%;
                    padding: 15px;
                    border: 2px solid #667eea;
                    background: white;
                    color: #667eea;
                    border-radius: 8px;
                    cursor: pointer;
                    font-size: 1rem;
                    transition: all 0.2s;
                }
                
                .pricing-cta.primary {
                    background: #667eea;
                    color: white;
                }
                
                .pricing-cta:hover {
                    transform: translateY(-2px);
                }
                
                .cta-section {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 60px 20px;
                    text-align: center;
                }
                
                .main-cta {
                    padding: 20px 40px;
                    font-size: 1.2rem;
                    background: white;
                    color: #667eea;
                    border: none;
                    border-radius: 8px;
                    cursor: pointer;
                    margin-top: 20px;
                    transition: transform 0.2s;
                }
                
                .main-cta:hover {
                    transform: scale(1.05);
                }
            `}</style>
        </div>
    );
};

export default SecurityLanding;
