# Configuration Stripe & PayPal - Guide Complet

## 📋 Les 3 Étapes Essentielles

### Étape 1: Créer un Compte Stripe

1. **Inscription:**
   - Va sur https://dashboard.stripe.com/register
   - Crée ton compte (email, mot de passe)
   - Vérifie ton email

2. **Obtenir les Clés API:**
   - Dans le Dashboard Stripe → **Developers** → **API keys**
   - **Mode Test** (pour tester):
     ```
     STRIPE_PUBLISHABLE_KEY=pk_test_...
     STRIPE_SECRET_KEY=sk_test_...
     ```
   - **Mode Live** (production - plus tard):
     ```
     STRIPE_PUBLISHABLE_KEY=pk_live_...
     STRIPE_SECRET_KEY=sk_live_...
     ```

3. **Configurer les Webhooks:**
   - **Developers** → **Webhooks** → **Add endpoint**
   - URL: `https://ton-domaine.com/api/payment/webhook/stripe`
   - Événements à écouter:
     - `checkout.session.completed`
     - `customer.subscription.deleted`
     - `invoice.payment_failed`
   - Copier le **Signing secret**: `whsec_...`

---

### Étape 2: Créer un Compte PayPal Business

1. **Inscription PayPal Business:**
   - Va sur https://www.paypal.com/business
   - Créer un **compte professionnel**

2. **Obtenir les Clés API:**
   - Va sur https://developer.paypal.com/dashboard
   - **My Apps & Credentials** → **Create App**
   - Nom de l'app: "Th3 Thirty3 Subscriptions"
   - Mode **Sandbox** (test):
     ```
     PAYPAL_CLIENT_ID=AXxxx... (Sandbox)
     PAYPAL_CLIENT_SECRET=EHxxx...
     PAYPAL_MODE=sandbox
     ```
   - Mode **Live** (production):
     ```
     PAYPAL_CLIENT_ID=AYxxx... (Live)
     PAYPAL_CLIENT_SECRET=EJxxx...
     PAYPAL_MODE=live
     ```

3. **Créer des Boutons d'Abonnement:**
   - PayPal.com → **Tools** → **All Tools** → **PayPal Buttons**
   - Créer 2 boutons:
     - **Premium Monthly**: 19.99$ USD/mois
     - **Enterprise Monthly**: 99.99$ USD/mois
   - Copier les codes HTML

---

### Étape 3: Configurer le Fichier `.env`

Éditer `server/.env` et ajouter:

```env
# Stripe Configuration
STRIPE_SECRET_KEY=sk_test_VOTRE_CLE_ICI
STRIPE_PUBLISHABLE_KEY=pk_test_VOTRE_CLE_ICI
STRIPE_WEBHOOK_SECRET=whsec_VOTRE_SECRET_ICI

# PayPal Configuration
PAYPAL_CLIENT_ID=VOTRE_CLIENT_ID_ICI
PAYPAL_CLIENT_SECRET=VOTRE_SECRET_ICI
PAYPAL_MODE=sandbox

# Frontend URL
FRONTEND_URL=http://localhost:5173
```

**⚠️ Important:** Ne JAMAIS commiter le fichier `.env` sur GitHub !

---

## 🚀 Test en Mode Sandbox

### Tester Stripe

1. Utiliser les **cartes de test Stripe**:
   ```
   Carte: 4242 4242 4242 4242
   Expiration: N'importe quelle date future
   CVC: N'importe quel 3 chiffres
   ```

2. API Endpoint:
   ```bash
   POST http://localhost:3000/api/payment/create-checkout
   Headers: x-api-key: sk-TEST-OPERATOR
   Body: {
     "tier": "operator",
     "billing_cycle": "monthly",
     "provider": "stripe"
   }
   ```

3. Le serveur retourne une `url` → Ouvrir dans le navigateur

### Tester PayPal

1. Connexion Sandbox: https://www.sandbox.paypal.com
2. Comptes de test créés automatiquement par PayPal
3. Tester le paiement avec compte sandbox

---

## 📊 Tarification Configurée

| Tier | Mensuel | Annuel (2 mois gratuits) |
|------|---------|--------------------------|
| **Premium** | 19.99$ | 199.90$ |
| **Enterprise** | 99.99$ | 999.90$ |

---

## 🔄 Workflow Complet

1. **Utilisateur clique "Upgrade to Premium"**
2. **Frontend** appelle `/api/payment/create-checkout`
3. **Backend** crée session Stripe
4. **Utilisateur** redirigé vers Stripe Checkout
5. **Paiement** effectué
6. **Stripe** envoie webhook `checkout.session.completed`
7. **Backend** met à jour `users.json` → tier = `operator`
8. **Utilisateur** a accès aux features PREMIUM ✅

---

## 🛡️ Sécurité

- ✅ Webhooks signés (Stripe signature verification)
- ✅ Clés API en variables d'environnement
- ✅ Mode Sandbox pour tests
- ✅ Validation des tiers (pas d'achat tier `architect`)

---

## 📝 Prochaines Étapes

1. Créer les comptes Stripe et PayPal
2. Copier les clés dans `.env`
3. Tester en mode sandbox
4. Créer l'UI frontend (boutons "Upgrade")
5. Passer en mode Live quand prêt

**Tout est prêt côté backend ! 🎉**
