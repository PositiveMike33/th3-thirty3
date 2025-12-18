import React, { useState, useEffect } from 'react';
import { CreditCard, Check, Zap, Shield, Database, Globe, Star, AlertTriangle, Loader2 } from 'lucide-react';
import './SubscriptionPage.css';
import { API_URL } from './config';

function SubscriptionPage() {
  // const [currentTier, setCurrentTier] = useState(null); // Unused for now
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Load subscription data logic
    const loadSubscriptionData = async () => {
      try {
        const statusRes = await fetch(`${API_URL}/api/subscription/status`);
        await statusRes.json();
        // setCurrentTier(statusData.subscription.tier); // Unused

        // Tiers are currently hardcoded in UI, but we could fetch them here if needed
        // const tiersRes = await fetch(`${API_URL}/api/subscription/tiers`);
        // const tiersData = await tiersRes.json();
        // setTiers(tiersData.tiers);

        setLoading(false);
      } catch (error) {
        console.error('Error loading subscription:', error);
        setLoading(false);
      }
    };

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
        window.location.href = data.url;
      }
    } catch (error) {
      console.error('Error creating checkout:', error);
    }
  };

  if (loading) {
    return <div className="min-h-screen bg-black text-cyan-500 flex items-center justify-center font-mono animate-pulse">Initalisation du protocole de paiement...</div>;
  }

  return (
    <div className="min-h-screen bg-black text-white p-4 md:p-8 font-sans">
      
      {/* 🚀 HERO SECTION */}
      <div className="max-w-5xl mx-auto text-center mb-16 pt-8">
        <div className="inline-block px-4 py-1.5 rounded-full bg-cyan-900/30 border border-cyan-500/30 text-cyan-400 text-sm font-bold tracking-widest mb-6">
          <span className="animate-pulse mr-2">●</span>
          INTELLIGENCE ARTIFICIELLE OPÉRATIONNELLE
        </div>
        
        <h1 className="text-5xl md:text-7xl font-extrabold mb-6 tracking-tight bg-gradient-to-r from-white via-gray-200 to-gray-500 bg-clip-text text-transparent">
          N'utilisez pas l'IA.<br/>
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-600">Embauchez-la.</span>
        </h1>
        
        <p className="text-xl text-gray-400 max-w-2xl mx-auto mb-8 font-light leading-relaxed">
          Arrêtez de payer pour des chatbots. Th3 Thirty3 est votre nouvelle **équipe opérationnelle**. 
          Récupérez 10h par semaine. Devenez l'Architecte de votre vie.
        </p>

        <div className="flex justify-center items-center gap-8 text-sm text-gray-500 font-mono">
          <div className="flex items-center gap-2"><Shield size={16} className="text-green-500"/> Paiement Sécurisé</div>
          <div className="flex items-center gap-2"><Zap size={16} className="text-yellow-500"/> Activation Immédiate</div>
          <div className="flex items-center gap-2"><Brain size={16} className="text-purple-500"/> Modèles GPT-4o & Claude</div>
        </div>
      </div>

      {/* 💎 PRICING CARDS */}
      <div className="max-w-7xl mx-auto grid md:grid-cols-3 gap-8 items-start relative z-10">
        
        {/* FREE TIER */}
        <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-8 hover:border-gray-600 transition-all duration-300">
          <div className="text-gray-400 font-bold tracking-widest text-sm mb-2">INITIATE</div>
          <div className="text-3xl font-bold mb-4">Gratuit <span className="text-lg font-normal text-gray-500">/ vie</span></div>
          <p className="text-gray-400 text-sm mb-6 h-10">Pour les curieux qui veulent voir la puissance avant de croire.</p>
          
          <button className="w-full py-3 rounded-lg border border-gray-700 hover:bg-gray-800 text-white font-bold transition-all mb-8">
            Commencer l'Initiation
          </button>

          <div className="space-y-3">
            <div className="flex items-center gap-3 text-sm text-gray-300"><Check size={16} className="text-gray-500"/> 10 Chats / jour</div>
            <div className="flex items-center gap-3 text-sm text-gray-300"><Check size={16} className="text-gray-500"/> Dashboard Personnel (Vue)</div>
            <div className="flex items-center gap-3 text-sm text-gray-300"><Check size={16} className="text-gray-500"/> Modélisation KPI Basique</div>
            <div className="flex items-center gap-3 text-sm text-gray-500"><Shield size={16}/> Pas d'Agents Autonomes</div>
          </div>
        </div>

        {/* OPERATOR TIER - POPULAR */}
        <div className="bg-gradient-to-b from-gray-900 to-black border-2 border-cyan-500 rounded-2xl p-8 transform md:-translate-y-4 shadow-[0_0_50px_rgba(6,182,212,0.15)] relative">
          <div className="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-cyan-500 text-black font-bold px-4 py-1 rounded-full text-xs tracking-wider shadow-lg">
            LE PLUS POPULAIRE
          </div>
          
          <div className="text-cyan-400 font-bold tracking-widest text-sm mb-2 flex items-center gap-2">
            <Award size={16} /> OPERATOR
          </div>
          <div className="text-5xl font-bold mb-4 text-white">19.99$ <span className="text-lg font-normal text-gray-500">/ mois</span></div>
          <p className="text-gray-300 text-sm mb-6 h-10">La boîte à outils ultime pour les freelances, devs et hackers.</p>
          
          <button 
            onClick={() => handleUpgrade('operator', 'monthly')}
            className="w-full py-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-extrabold text-lg transition-all mb-8 shadow-lg shadow-cyan-900/50 hover:shadow-cyan-500/30"
          >
            OBTENIR L'ACCRÉDITATION
          </button>

          <div className="space-y-4">
            <div className="flex items-center gap-3 text-sm font-bold text-white"><Check size={16} className="text-cyan-500"/> Chat Illimité (GPT-4o, Groq)</div>
            <div className="flex items-center gap-3 text-sm text-gray-300"><Check size={16} className="text-cyan-500"/> Cyber Training (CTF + Scénarios)</div>
            <div className="flex items-center gap-3 text-sm text-gray-300"><Check size={16} className="text-cyan-500"/> Fabric Library (232 patterns)</div>
            <div className="flex items-center gap-3 text-sm text-gray-300"><Check size={16} className="text-cyan-500"/> OSINT Tools (Sherlock, Maigret)</div>
            <div className="flex items-center gap-3 text-sm text-gray-300"><Check size={16} className="text-cyan-500"/> 10 Agents Spécialisés</div>
          </div>
        </div>

        {/* ENTERPRISE TIER */}
        <div className="bg-gray-900/50 border border-purple-500/50 rounded-2xl p-8 hover:border-purple-500 transition-all duration-300">
          <div className="text-purple-400 font-bold tracking-widest text-sm mb-2 flex items-center gap-2">
            <Brain size={16} /> ENTERPRISE
          </div>
          <div className="text-3xl font-bold mb-4">99.99$ <span className="text-lg font-normal text-gray-500">/ mois</span></div>
          <p className="text-gray-400 text-sm mb-6 h-10">Votre équipe salariée virtuelle. Pour ceux qui bâtissent des empires.</p>
          
          <button 
            onClick={() => handleUpgrade('enterprise', 'monthly')}
            className="w-full py-3 rounded-lg border border-purple-500/50 hover:bg-purple-900/20 text-purple-300 font-bold transition-all mb-8"
          >
            DÉPLOYER L'INFRASTRUCTURE
          </button>

          <div className="space-y-3">
            <div className="flex items-center gap-3 text-sm text-gray-300"><Star size={16} className="text-purple-500"/> Tout le pack OPERATOR +</div>
            <div className="flex items-center gap-3 text-sm font-bold text-white"><Check size={16} className="text-purple-500"/> AGENTS AUTONOMES (Hire an Expert)</div>
            <div className="flex items-center gap-3 text-sm text-gray-300"><Check size={16} className="text-purple-500"/> Google Workspace (Docs, Sheets)</div>
            <div className="flex items-center gap-3 text-sm text-gray-300"><Users size={16} className="text-purple-500"/> 10 Sièges Utilisateurs</div>
            <div className="flex items-center gap-3 text-sm text-gray-300"><Check size={16} className="text-purple-500"/> Support Prioritaire 24/7</div>
          </div>
        </div>

      </div>

      {/* 💬 SOCIAL PROOF */}
      <div className="max-w-4xl mx-auto mt-20 text-center">
        <div className="grid md:grid-cols-2 gap-8">
          <div className="bg-gray-900/30 p-6 rounded-xl border border-gray-800">
            <div className="text-yellow-500 flex justify-center gap-1 mb-4">
              <Star fill="currentColor" size={16}/><Star fill="currentColor" size={16}/><Star fill="currentColor" size={16}/><Star fill="currentColor" size={16}/><Star fill="currentColor" size={16}/>
            </div>
            <p className="text-gray-300 italic mb-4">"J'ai remplacé 3 abonnements différents (ChatGPT, Notion AI, Security trails) par Th3 Thirty3. C'est no-brainer niveau ROI."</p>
            <div className="font-bold text-white">— Alex, DevSecOps</div>
          </div>
          <div className="bg-gray-900/30 p-6 rounded-xl border border-gray-800">
            <div className="text-yellow-500 flex justify-center gap-1 mb-4">
              <Star fill="currentColor" size={16}/><Star fill="currentColor" size={16}/><Star fill="currentColor" size={16}/><Star fill="currentColor" size={16}/><Star fill="currentColor" size={16}/>
            </div>
            <p className="text-gray-300 italic mb-4">"Mes agents gèrent mes emails pendant que je dors. Je me réveille avec 0 inbox et mes réunions planifiées."</p>
            <div className="font-bold text-white">— Sarah, Entrepreneur</div>
          </div>
        </div>
      </div>

      <div className="text-center mt-12 text-gray-600 text-xs">
        <p>🔒 Paiement 100% Sécurisé via Stripe. Annulation possible à tout moment.</p>
        <p className="mt-2">Th3 Thirty3 © 2024. All rights reserved.</p>
      </div>

    </div>
  );
}

export default SubscriptionPage;
