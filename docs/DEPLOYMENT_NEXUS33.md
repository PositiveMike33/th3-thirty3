# 🚀 Guide de déploiement Nexus33.io

## Vue d'ensemble

Ce guide explique comment déployer Th3 Thirty3 sur votre domaine nexus33.io.

## Prérequis

1. **Domaine**: nexus33.io configuré avec accès DNS
2. **Serveur**: VPS ou service cloud (DigitalOcean, AWS, Vercel, etc.)
3. **Certificat SSL**: Let's Encrypt ou autre
4. **Node.js**: v18+ sur le serveur
5. **Docker** (optionnel mais recommandé)

---

## Architecture de déploiement recommandée

```
nexus33.io (Frontend) ──────────► Vite/Static
api.nexus33.io (Backend) ───────► Express.js
ollama.nexus33.io (LLM) ────────► Ollama (si hébergé)
```

---

## Étape 1: Configuration du fichier config.js

Le fichier `interface/src/config.js` gère automatiquement les URLs selon l'environnement.

### Pour activer la production :

**Option A:** Lors du build
```bash
NODE_ENV=production npm run build
```

**Option B:** Forcer manuellement
Dans `interface/src/config.js`, modifier :
```javascript
const FORCE_PRODUCTION = true;  // Changer de false à true
```

---

## Étape 2: Préparer le Backend

### Variables d'environnement (.env)

Créer un fichier `.env` sur le serveur :

```env
# Server
NODE_ENV=production
PORT=3000

# CORS Origins (votre domaine)
CORS_ORIGINS=https://nexus33.io,https://www.nexus33.io

# JWT Secret (GÉNÉRER UN NOUVEAU!)
JWT_SECRET=votre_secret_super_long_et_securise_minimum_32_caracteres

# Database (si MongoDB)
MONGODB_URI=mongodb://localhost:27017/nexus33

# Ollama
OLLAMA_BASE_URL=http://localhost:11434

# AnythingLLM (si utilisé)
ANYTHINGLLM_URL=http://localhost:3001
ANYTHINGLLM_API_KEY=votre_cle

# Google OAuth (si utilisé)
GOOGLE_CLIENT_ID=votre_client_id
GOOGLE_CLIENT_SECRET=votre_secret
GOOGLE_REDIRECT_URI=https://api.nexus33.io/auth/google/callback

# Stripe (si paiements)
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
```

---

## Étape 3: Build du Frontend

```bash
cd interface
npm install

# Build production
npm run build

# Le dossier dist/ contient les fichiers à déployer
```

---

## Étape 4: Configuration DNS

Configurer les enregistrements DNS suivants :

```
Type    Nom                 Valeur              TTL
A       @                   IP_SERVEUR          300
A       www                 IP_SERVEUR          300
A       api                 IP_SERVEUR          300
CNAME   ollama              IP_OU_DOMAINE       300
```

---

## Étape 5: Configuration Nginx

### nginx.conf pour nexus33.io

```nginx
# Frontend - nexus33.io
server {
    listen 80;
    server_name nexus33.io www.nexus33.io;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name nexus33.io www.nexus33.io;
    
    ssl_certificate /etc/letsencrypt/live/nexus33.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/nexus33.io/privkey.pem;
    
    root /var/www/nexus33/dist;
    index index.html;
    
    # Gzip
    gzip on;
    gzip_types text/plain text/css application/json application/javascript;
    
    # SPA routing
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    # Cache assets
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}

# API Backend - api.nexus33.io
server {
    listen 80;
    server_name api.nexus33.io;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.nexus33.io;
    
    ssl_certificate /etc/letsencrypt/live/nexus33.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/nexus33.io/privkey.pem;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

---

## Étape 6: SSL avec Let's Encrypt

```bash
# Installer Certbot
sudo apt install certbot python3-certbot-nginx

# Obtenir certificat
sudo certbot --nginx -d nexus33.io -d www.nexus33.io -d api.nexus33.io

# Renouvellement automatique
sudo certbot renew --dry-run
```

---

## Étape 7: Démarrer les services

### Avec PM2 (recommandé)

```bash
# Installer PM2
npm install -g pm2

# Démarrer le backend
cd /var/www/nexus33/server
pm2 start index.js --name "nexus33-api"

# Sauvegarder config PM2
pm2 save
pm2 startup
```

### Avec Docker (alternative)

Voir le fichier `docker-compose.yml` inclus.

---

## Étape 8: Vérification

1. Tester le frontend: https://nexus33.io
2. Tester l'API: https://api.nexus33.io/health
3. Tester le login
4. Vérifier les logs: `pm2 logs`

---

## Troubleshooting

### CORS Errors
- Vérifier que CORS_ORIGINS inclut votre domaine
- Vérifier que les headers sont corrects dans nginx

### 502 Bad Gateway
- Vérifier que le backend tourne: `pm2 status`
- Vérifier le port dans nginx proxy_pass

### Mixed Content
- Vérifier que toutes les URLs utilisent HTTPS
- Vérifier config.js utilise les bonnes URLs

---

## Fichiers modifiés pour la production

| Fichier | Changement |
|---------|------------|
| `interface/src/config.js` | Configuration centralisée URLs |
| `interface/src/contexts/AuthContext.jsx` | Utilise config.js |
| `interface/src/services/api.js` | Utilise config.js |
| `interface/src/ProjectDashboard.jsx` | Utilise config.js |

---

## Contact Support

En cas de problème, vérifiez les logs :
```bash
pm2 logs nexus33-api
tail -f /var/log/nginx/error.log
```

Bonne chance avec le déploiement ! 🚀
