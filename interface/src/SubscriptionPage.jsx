import { useState, useEffect } from 'react';
import './SubscriptionPage.css';

const API_URL = 'http://localhost:3000';

function SubscriptionPage() {
  const [tiers, setTiers] = useState([]);
  const [currentTier, setCurrentTier] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadSubscriptionData = async () => {
    try {
      // Get current user tier
      const statusRes = await fetch(`${API_URL}/api/subscription/status`);
      const statusData = await statusRes.json();
      setCurrentTier(statusData.subscription.tier);

      // Get all tiers
      const tiersRes = await fetch(`${API_URL}/api/subscription/tiers`);
      const tiersData = await tiersRes.json();
      setTiers(tiersData.tiers);

      setLoading(false);
    } catch (error) {
      console.error('Error loading subscription:', error);
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSubscriptionData();
  }, []);

  const handleUpgrade = async (tierKey, billingCycle) => {
    try {
      const response = await fetch(`${API_URL}/api/payment/create-checkout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tier: tierKey,
          billing_cycle: billingCycle,
          provider: 'stripe'
        })
      });

      const data = await response.json();
      if (data.url) {
        window.location.href = data.url; // Redirect to Stripe
      }
    } catch (error) {
      console.error('Error creating checkout:', error);
    }
  };

  if (loading) {
    return <div className="subscription-loading">Chargement...</div>;
  }

  return (
    <div className="subscription-page">
      <div className="subscription-header">
        <h1>Choisir votre Abonnement</h1>
        <p>Tier actuel: <span className="current-tier">{currentTier?.label}</span></p>
      </div>

      <div className="tiers-grid">
        {tiers.map((tier) => (
          <div key={tier.key} className={`tier-card ${tier.key === currentTier?.key ? 'active' : ''}`}>
            <div className="tier-header">
              <h2>{tier.label}</h2>
              <div className="tier-price">
                {tier.key === 'initiate' && <span className="price">Gratuit</span>}
                {tier.key === 'operator' && <span className="price">19.99$ <small>/mois</small></span>}
                {tier.key === 'enterprise' && <span className="price">99.99$ <small>/mois</small></span>}
                {tier.key === 'architect' && <span className="price">Propriétaire</span>}
              </div>
            </div>

            <div className="tier-features">
              {tier.key === 'initiate' && (
                <ul>
                  <li>✅ 10 chats / jour</li>
                  <li>✅ 5 recherches Google / jour</li>
                  <li>✅ 5 patterns Fabric</li>
                  <li>✅ Modèles locaux (Ollama)</li>
                  <li>❌ OSINT / Hacking</li>
                  <li>❌ Agents</li>
                </ul>
              )}
              {tier.key === 'operator' && (
                <ul>
                  <li>✅ Chat illimité</li>
                  <li>✅ Google Search illimité</li>
                  <li>✅ 232 patterns Fabric</li>
                  <li>✅ Groq, OpenAI (cloud)</li>
                  <li>✅ OSINT complet (basique + avancé)</li>
                  <li>✅ Hacking tools</li>
                  <li>✅ Cyber Training</li>
                  <li>✅ 10 agents spécialisés</li>
                </ul>
              )}
              {tier.key === 'enterprise' && (
                <ul>
                  <li>✅ Tout de Premium +</li>
                  <li>✅ 25 agents spécialisés</li>
                  <li>✅ 10 sièges utilisateurs</li>
                  <li>✅ Support prioritaire</li>
                  <li>✅ SLA garanti</li>
                  <li>✅ Personnalisation</li>
                </ul>
              )}
              {tier.key === 'architect' && (
                <ul>
                  <li>✅ Accès total illimité</li>
                  <li>✅ 37 agents</li>
                  <li>✅ Finance / Kraken</li>
                  <li>✅ Vision / VPO</li>
                  <li>✅ Tor anonymat complet</li>
                  <li>👑 Propriétaire unique</li>
                </ul>
              )}
            </div>

            <div className="tier-actions">
              {tier.key === currentTier?.key ? (
                <button className="btn-current" disabled>Tier Actuel</button>
              ) : tier.key === 'architect' ? (
                <button className="btn-owner" disabled>Propriétaire</button>
              ) : tier.level > currentTier?.level ? (
                <button 
                  className="btn-upgrade"
                  onClick={() => handleUpgrade(tier.key, 'monthly')}
                >
                  Passer à {tier.name}
                </button>
              ) : (
                <button className="btn-disabled" disabled>Inférieur</button>
              )}
            </div>
          </div>
        ))}
      </div>

      <div className="payment-methods">
        <h3>Méthodes de Paiement</h3>
        <div className="payment-logos">
          <img src="/icons/stripe.svg" alt="Stripe" />
          <img src="/icons/paypal.svg" alt="PayPal" />
          <span>Paiements sécurisés</span>
        </div>
      </div>
    </div>
  );
}

export default SubscriptionPage;
