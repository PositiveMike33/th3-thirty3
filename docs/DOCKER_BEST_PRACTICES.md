# 🐳 DOCKER BEST PRACTICES - Guide de Référence Rapide

> **Fichier créé le:** 2026-01-11  
> **Projet:** th3-thirty3  
> **Objectif:** Référence rapide pour Docker

---

## 📋 TABLE DES MATIÈRES

1. [🔒 Sécurité](#-1-sécurité)
2. [📦 Optimisation des Layers](#-2-optimisation-des-layers)
3. [🚀 Cache Intelligent](#-3-cache-intelligent)
4. [🏷️ Tags et Versioning](#%EF%B8%8F-4-tags-et-versioning)
5. [💾 Volumes](#-5-volumes)
6. [🔧 Variables d'Environnement](#-6-variables-denvironnement)
7. [🩺 Health Checks](#-7-health-checks)
8. [📋 .dockerignore](#-8-dockerignore)
9. [🎯 Multi-Stage Builds](#-9-multi-stage-builds)
10. [⚡ Commandes Utiles](#-10-commandes-utiles)

---

## 🔒 1. SÉCURITÉ

### ⚠️ RÈGLES CRITIQUES

```dockerfile
# ✅ N'utilisez JAMAIS root en production
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# ✅ Utilisez des images officielles/vérifiées
FROM python:3.12-slim     # ✅ Léger et sécurisé
FROM node:20-alpine       # ✅ Minimal
FROM kalilinux/kali-rolling  # ✅ Officiel Kali

# ❌ ÉVITEZ
FROM random-user/unknown-image  # ❌ Non vérifié
```

### 🔍 Scanner les Vulnérabilités

```bash
# Docker Scout (intégré à Docker Desktop)
docker scout quickview <image>
docker scout cves <image>

# Trivy (outil externe)
trivy image <image>
```

---

## 📦 2. OPTIMISATION DES LAYERS

### ❌ MAUVAIS - Multiple layers

```dockerfile
RUN apt-get update
RUN apt-get install -y python3
RUN apt-get install -y curl
RUN apt-get clean
```

### ✅ BON - Un seul layer optimisé

```dockerfile
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
```

> **Pourquoi ?** Chaque instruction `RUN` crée une nouvelle layer. Moins de layers = image plus petite.

---

## 🚀 3. CACHE INTELLIGENT

### Ordre optimal des instructions

```dockerfile
# 1. Image de base (change rarement)
FROM python:3.12-slim

# 2. Dépendances système (change rarement)
RUN apt-get update && apt-get install -y curl

# 3. Dépendances applicatives (change parfois)
COPY requirements.txt .
RUN pip install -r requirements.txt

# 4. Code source (change souvent) - EN DERNIER!
COPY . .
```

> **Astuce:** Si `requirements.txt` n'a pas changé, Docker utilise le cache pour `pip install`.

---

## 🏷️ 4. TAGS ET VERSIONING

### ✅ Bonnes pratiques

```bash
# Versioning sémantique
docker build -t monapp:1.0.0 .
docker build -t monapp:1.0 .
docker build -t monapp:latest .

# Tags descriptifs
docker build -t monapp:1.0.0-gpu .
docker build -t monapp:1.0.0-light .
```

### ❌ À éviter en production

```bash
# Ne vous fiez pas uniquement à :latest
docker pull monapp:latest  # ❌ Peut changer à tout moment!
docker pull monapp:1.0.0   # ✅ Version fixe
```

---

## 💾 5. VOLUMES

### Types de volumes

```yaml
# docker-compose.yml
services:
  app:
    volumes:
      # Bind mount (développement) - Sync avec le host
      - ./src:/app/src
      
      # Named volume (production) - Persistant
      - app_data:/app/data
      
      # Anonymous volume - Temporaire
      - /app/temp

volumes:
  app_data:  # Déclaration du named volume
```

### Commandes utiles

```bash
docker volume ls                    # Lister les volumes
docker volume inspect <volume>      # Détails
docker volume rm <volume>           # Supprimer
docker volume prune                 # Nettoyer les orphelins
```

---

## 🔧 6. VARIABLES D'ENVIRONNEMENT

### ✅ Dans Dockerfile (valeurs par défaut)

```dockerfile
ENV NODE_ENV=production
ENV DEBUG=false
ENV PORT=3000
```

### ✅ Dans docker-compose.yml

```yaml
services:
  app:
    environment:
      - NODE_ENV=production
      - API_URL=http://api:3000
    env_file:
      - .env  # Fichier séparé pour les secrets
```

### ❌ JAMAIS de secrets en dur!

```dockerfile
# ❌ DANGER - Ne faites JAMAIS ça!
ENV API_KEY=sk-proj-xxxxxxxxxxxxx
ENV PASSWORD=mysecretpassword

# ✅ Utilisez des secrets Docker ou des variables d'environnement
```

---

## 🩺 7. HEALTH CHECKS

### Dockerfile

```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1
```

### docker-compose.yml

```yaml
services:
  api:
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
```

---

## 📋 8. .dockerignore

### Fichier `.dockerignore` recommandé

```
# Dépendances
node_modules/
__pycache__/
*.pyc
.venv/
venv/

# Git
.git/
.gitignore

# Logs et fichiers temporaires
*.log
*.tmp
.cache/

# Secrets et config locale
.env
.env.local
*.pem
*.key

# IDE
.vscode/
.idea/
*.swp

# Tests
coverage/
.pytest_cache/

# Build artifacts
dist/
build/
*.egg-info/
```

---

## 🎯 9. MULTI-STAGE BUILDS

### Exemple Node.js (réduction de taille ~80%)

```dockerfile
# Stage 1: Build
FROM node:20 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Stage 2: Production (image finale)
FROM node:20-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
EXPOSE 3000
CMD ["node", "dist/server.js"]
```

### Exemple Python

```dockerfile
# Stage 1: Build avec toutes les dépendances
FROM python:3.12 AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --user -r requirements.txt

# Stage 2: Image légère
FROM python:3.12-slim
WORKDIR /app
COPY --from=builder /root/.local /root/.local
COPY . .
ENV PATH=/root/.local/bin:$PATH
CMD ["python", "app.py"]
```

---

## ⚡ 10. COMMANDES UTILES

### 🧹 Nettoyage

```bash
# Supprimer les conteneurs arrêtés
docker container prune

# Supprimer les images non utilisées
docker image prune

# Supprimer les volumes orphelins
docker volume prune

# TOUT nettoyer (attention!)
docker system prune -a --volumes
```

### 🔍 Debugging

```bash
# Voir les logs en temps réel
docker logs -f <container>

# Shell interactif dans un conteneur
docker exec -it <container> /bin/bash
docker exec -it <container> /bin/sh  # Alpine

# Inspecter un conteneur
docker inspect <container>

# Voir les processus
docker top <container>
```

### 📊 Monitoring

```bash
# Statistiques en temps réel
docker stats

# Espace disque utilisé
docker system df

# Historique d'une image
docker history <image>
```

### 🏗️ Build

```bash
# Build avec cache désactivé
docker build --no-cache -t app:latest .

# Build pour plusieurs plateformes
docker buildx build --platform linux/amd64,linux/arm64 -t app:latest .

# Voir les layers pendant le build
docker build --progress=plain -t app:latest .
```

---

## 🎯 CHECKLIST RAPIDE

Avant de déployer, vérifiez :

- [ ] Pas de secrets en dur dans le Dockerfile
- [ ] Utilisateur non-root configuré
- [ ] Health check défini
- [ ] Image scannée pour vulnérabilités
- [ ] .dockerignore présent
- [ ] Tags de version appropriés
- [ ] Volumes pour données persistantes
- [ ] Layers optimisées (commandes groupées)

---

## 📚 RESSOURCES

- [Documentation officielle Docker](https://docs.docker.com/)
- [Docker Best Practices](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)
- [Docker Scout (Security)](https://docs.docker.com/scout/)
- [Docker Compose](https://docs.docker.com/compose/)

---

> 💡 **Astuce:** Gardez ce fichier ouvert dans VS Code pour référence rapide!
