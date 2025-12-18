import { useState, useEffect, useCallback } from 'react';
import './PaymentDashboard.css';
import { API_URL } from './config';

function PaymentDashboard() {
  const [stats, setStats] = useState({
    stripe: { balance: 0, pending: 0, subscriptions: 0, loading: true },
    paypal: { balance: 0, pending: 0, subscriptions: 0, loading: true },
    total: { revenue: 0, mrr: 0, customers: 0 }
  });

  const loadPaymentStats = useCallback(async () => {
    try {
      const response = await fetch(`${API_URL}/api/payment/dashboard-stats`);
      const data = await response.json();
      
      if (data.success) {
        setStats(data.stats);
      }
    } catch (error) {
      console.error('Error loading payment stats:', error);
    }
  }, []);

  useEffect(() => {
    let isMounted = true;
    
    const fetchStats = async () => {
      try {
        const response = await fetch(`${API_URL}/api/payment/dashboard-stats`);
        const data = await response.json();
        if (isMounted && data.success) {
          setStats(data.stats);
        }
      } catch (error) {
        console.error('Error loading payment stats:', error);
      }
    };
    
    fetchStats();
    const interval = setInterval(fetchStats, 30000);
    
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const formatCurrency = (amount) => {
    return new Intl.NumberFormat('fr-CA', {
      style: 'currency',
      currency: 'USD'
    }).format(amount / 100);
  };

  return (
    <div className="payment-dashboard">
      <div className="dashboard-header">
        <h1>💰 Dashboard Paiements</h1>
        <button onClick={loadPaymentStats} className="refresh-btn">
          🔄 Rafraîchir
        </button>
      </div>

      {/* Global Stats */}
      <div className="stats-grid">
        <div className="stat-card total">
          <div className="stat-icon">💵</div>
          <div className="stat-info">
            <div className="stat-label">Revenus Totaux</div>
            <div className="stat-value">{formatCurrency(stats.total.revenue)}</div>
          </div>
        </div>

        <div className="stat-card mrr">
          <div className="stat-icon">📈</div>
          <div className="stat-info">
            <div className="stat-label">MRR (Monthly Recurring)</div>
            <div className="stat-value">{formatCurrency(stats.total.mrr)}</div>
          </div>
        </div>

        <div className="stat-card customers">
          <div className="stat-icon">👥</div>
          <div className="stat-info">
            <div className="stat-label">Clients Payants</div>
            <div className="stat-value">{stats.total.customers}</div>
          </div>
        </div>
      </div>

      {/* Stripe Stats */}
      <div className="provider-section">
        <div className="provider-header stripe-header">
          <img src="/icons/stripe.svg" alt="Stripe" className="provider-logo" />
          <h2>Stripe</h2>
        </div>

        {stats.stripe.loading ? (
          <div className="loading">Chargement...</div>
        ) : (
          <div className="provider-stats">
            <div className="provider-stat">
              <span className="label">Balance Disponible</span>
              <span className="value stripe-value">{formatCurrency(stats.stripe.balance)}</span>
            </div>
            <div className="provider-stat">
              <span className="label">En Attente</span>
              <span className="value">{formatCurrency(stats.stripe.pending)}</span>
            </div>
            <div className="provider-stat">
              <span className="label">Abonnements Actifs</span>
              <span className="value">{stats.stripe.subscriptions}</span>
            </div>
          </div>
        )}
      </div>

      {/* PayPal Stats */}
      <div className="provider-section">
        <div className="provider-header paypal-header">
          <img src="/icons/paypal.svg" alt="PayPal" className="provider-logo" />
          <h2>PayPal</h2>
        </div>

        {stats.paypal.loading ? (
          <div className="loading">Chargement...</div>
        ) : (
          <div className="provider-stats">
            <div className="provider-stat">
              <span className="label">Balance Disponible</span>
              <span className="value paypal-value">{formatCurrency(stats.paypal.balance)}</span>
            </div>
            <div className="provider-stat">
              <span className="label">En Attente</span>
              <span className="value">{formatCurrency(stats.paypal.pending)}</span>
            </div>
            <div className="provider-stat">
              <span className="label">Abonnements Actifs</span>
              <span className="value">{stats.paypal.subscriptions}</span>
            </div>
          </div>
        )}
      </div>

      {/* Recent Transactions */}
      <div className="recent-section">
        <h3>Dernières Transactions</h3>
        <div className="transactions-placeholder">
          <p>Connectez vos comptes Stripe et PayPal pour voir les transactions en temps réel</p>
          <button className="connect-btn">Connecter Stripe</button>
          <button className="connect-btn paypal-btn">Connecter PayPal</button>
        </div>
      </div>
    </div>
  );
}

export default PaymentDashboard;
