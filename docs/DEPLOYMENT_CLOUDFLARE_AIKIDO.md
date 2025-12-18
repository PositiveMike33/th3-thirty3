# 🚀 Th3 Thirty3 / Nexus33 - Guide de Déploiement Complet

## 📋 Prérequis

### Services Locaux Requis
- [x] Node.js v18+
- [x] Ollama (localhost:11434)
- [x] Backend Express (localhost:3000)
- [x] Frontend Vite (localhost:5173)
- [x] cloudflared CLI installé

### Comptes et API Keys
- [ ] Cloudflare Account avec domaine nexus33.io
- [ ] Aikido Security API Token
- [ ] Google Cloud OAuth credentials
- [ ] Stripe/PayPal keys (optionnel)

---

## 🌐 Configuration Cloudflare (nexus33.io)

### Étape 1: Vérifier le Domaine dans Cloudflare Dashboard

1. Aller sur https://dash.cloudflare.com
2. Sélectionner le domaine **nexus33.io**
3. Aller dans **DNS** → **Records**

### Étape 2: Configurer les DNS Records

Les records CNAME suivants doivent pointer vers le tunnel:

| Type | Name | Content | Proxy |
|------|------|---------|-------|
| CNAME | @ | `d8ae3918-ff1f-484d-85f3-ce9c3169bf52.cfargotunnel.com` | ✅ Proxied |
| CNAME | www | `d8ae3918-ff1f-484d-85f3-ce9c3169bf52.cfargotunnel.com` | ✅ Proxied |
| CNAME | api | `d8ae3918-ff1f-484d-85f3-ce9c3169bf52.cfargotunnel.com` | ✅ Proxied |
| CNAME | ollama | `d8ae3918-ff1f-484d-85f3-ce9c3169bf52.cfargotunnel.com` | ✅ Proxied |
| CNAME | llm | `d8ae3918-ff1f-484d-85f3-ce9c3169bf52.cfargotunnel.com` | ✅ Proxied |

> **Note**: Remplacez l'UUID par votre Tunnel ID si différent.

### Étape 3: Configurer SSL/TLS

1. Aller dans **SSL/TLS** → **Overview**
2. Sélectionner mode: **Full (strict)**
3. Aller dans **Edge Certificates**
4. Activer: Always Use HTTPS ✅
5. Activer: Automatic HTTPS Rewrites ✅

---

## 🔐 Configuration Aikido Security

### Obtenir un API Token

1. Aller sur https://app.aikido.dev
2. Settings → API Tokens → Create New Token
3. Scopes requis:
   - `read:issues` - Voir les vulnérabilités
   - `read:repos` - Liste des repos
   - `read:compliance` - SOC2/ISO27001

### Configurer le Token

Ajouter dans `server/.env`:
```bash
AIKIDO_API_TOKEN=your_token_here
```

### Tester la connexion

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" https://app.aikido.dev/api/public/v1/issues/groups
```

---

## 🚀 Démarrage Rapide

### Option A: Script automatique

```powershell
# Depuis le dossier thethirty3
.\cloudflare\deploy-cloudflare.ps1 -All
```

### Option B: Démarrage manuel

```powershell
# 1. Démarrer le backend
cd server
node index.js

# 2. Démarrer le frontend (nouveau terminal)
cd interface
npm run dev

# 3. Démarrer le tunnel Cloudflare (nouveau terminal)
cloudflared tunnel run nexus33
```

---

## ✅ Checklist de Vérification

### Services Locaux
- [ ] http://localhost:5173 - Frontend accessible
- [ ] http://localhost:3000/api/health - Backend répond
- [ ] http://localhost:11434/api/version - Ollama actif

### Endpoints Publics (après propagation DNS ~5min)
- [ ] https://nexus33.io - Frontend public
- [ ] https://api.nexus33.io/api/health - API publique
- [ ] https://ollama.nexus33.io/api/version - Ollama public

### Sécurité Aikido
- [ ] Token configuré dans .env
- [ ] /api/cyber-training/aikido/summary retourne des données
- [ ] Dashboard Aikido affiche les stats

---

## 🔧 Troubleshooting

### "Le nom distant ne peut pas être résolu"
→ Les DNS ne sont pas encore propagés. Attendre 5-30 minutes.
→ Vérifier que les records CNAME sont créés dans Cloudflare Dashboard.

### "Aikido disabled"
→ Vérifier AIKIDO_API_TOKEN dans .env
→ Token doit avoir > 20 caractères
→ Redémarrer le serveur après modification

### "Connection refused" sur le tunnel
→ Vérifier que tous les services locaux sont démarrés
→ Vérifier les ports dans config.yml

### CORS Errors
→ Ajouter les domaines dans CORS_ORIGINS de .env:
```
CORS_ORIGINS=https://nexus33.io,https://www.nexus33.io,https://api.nexus33.io
```

---

## 📁 Fichiers Importants

| Fichier | Description |
|---------|-------------|
| `cloudflare/config.yml` | Configuration du tunnel |
| `cloudflare/deploy-cloudflare.ps1` | Script de déploiement |
| `server/.env` | Variables d'environnement (sensible!) |
| `docs/ENV_PRODUCTION_TEMPLATE.md` | Template complet |

---

## 🎯 URLs de Production

| Service | URL | Port Local |
|---------|-----|------------|
| Frontend | https://nexus33.io | 5173 |
| API Backend | https://api.nexus33.io | 3000 |
| Ollama LLM | https://ollama.nexus33.io | 11434 |
| AnythingLLM | https://llm.nexus33.io | 3001 |

---

## 📞 Support

- **Documentation Cloudflare**: https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/
- **Documentation Aikido**: https://apidocs.aikido.dev
- **Logs du tunnel**: `cloudflared tunnel run nexus33 --loglevel debug`

---

*Généré automatiquement - Th3 Thirty3 v1.3.0*
