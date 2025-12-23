# 🐳 Guide Docker - Aide-Mémoire

> Guide de référence rapide pour les commandes Docker essentielles.
> Créé le 2025-12-23

---

## 📋 Table des Matières

1. [Commandes de Base](#commandes-de-base)
2. [Docker Compose](#docker-compose)
3. [Gestion des Images](#gestion-des-images)
4. [Logs et Debugging](#logs-et-debugging)
5. [Projets Spécifiques](#projets-spécifiques)
6. [Ollama avec Docker](#ollama-avec-docker)

---

## Commandes de Base

### Voir les conteneurs

```powershell
# Conteneurs en cours d'exécution
docker ps

# Tous les conteneurs (même arrêtés)
docker ps -a

# Format compact
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### Contrôler les conteneurs

```powershell
# Démarrer un conteneur
docker start <nom_ou_id>

# Arrêter un conteneur
docker stop <nom_ou_id>

# Redémarrer un conteneur
docker restart <nom_ou_id>

# Supprimer un conteneur (doit être arrêté)
docker rm <nom_ou_id>

# Forcer la suppression
docker rm -f <nom_ou_id>
```

### Exécuter des commandes dans un conteneur

```powershell
# Ouvrir un shell interactif
docker exec -it <nom> bash

# Exécuter une commande unique
docker exec <nom> ls -la /app
```

---

## Docker Compose

> ⭐ **Recommandé** pour les projets avec plusieurs services

### Commandes essentielles

```powershell
# Démarrer les services (arrière-plan)
docker compose up -d

# Démarrer ET reconstruire les images
docker compose up -d --build

# Arrêter les services
docker compose down

# Arrêter ET supprimer les volumes
docker compose down -v

# Redémarrer un service spécifique
docker compose restart <service>
```

### Avec un fichier compose spécifique

```powershell
docker compose -f docker-compose.single.yml up -d
docker compose -f docker-compose.dev.yml up -d --build
```

---

## Gestion des Images

```powershell
# Lister les images
docker images

# Supprimer une image
docker rmi <image_id>

# Construire une image
docker build -t mon-image:tag .

# Construire avec un Dockerfile spécifique
docker build -f Dockerfile.single -t mon-image:tag .

# Nettoyer les images inutilisées
docker image prune -a
```

### Docker Buildx (avancé)

```powershell
# Build standard
docker buildx build .

# Build multi-plateforme
docker buildx build --platform linux/amd64,linux/arm64 -t image:tag .

# Build et push vers un registry
docker buildx build --push -t registry.com/image:tag .
```

> ⚠️ **Note**: `docker buildx build` n'est PAS nécessaire si vous utilisez 
> `docker compose up --build` - cette dernière fait déjà le build automatiquement!

---

## Logs et Debugging

```powershell
# Voir les logs
docker logs <nom>

# Dernières 50 lignes
docker logs <nom> --tail 50

# Suivre en temps réel
docker logs -f <nom>

# Suivre avec timestamp
docker logs -f --timestamps <nom>

# Filtrer les logs
docker logs <nom> 2>&1 | Select-String "ERROR"
```

### Inspecter un conteneur

```powershell
# Informations complètes (JSON)
docker inspect <nom>

# Variables d'environnement
docker inspect <nom> --format '{{json .Config.Env}}'

# Adresse IP
docker inspect <nom> --format '{{.NetworkSettings.IPAddress}}'
```

---

## Projets Spécifiques

### 🔵 Open Notebook

```powershell
# Emplacement
cd C:\Users\th3th\.Th3Thirty3\thethirty3\open-notebook

# Démarrer
docker compose -f docker-compose.single.yml up -d

# Reconstruire et démarrer
docker compose -f docker-compose.single.yml up -d --build

# Arrêter
docker compose -f docker-compose.single.yml down

# Logs
docker logs open-notebook-open_notebook_single-1 --tail 50

# URLs d'accès:
# - Frontend: http://localhost:8502
# - API: http://localhost:5055
# - API Docs: http://localhost:5055/docs
```

### 🟣 Th3 Thirty3 Stack

```powershell
# Redis
docker start th3_redis
docker logs th3_redis

# Ollama Proxy
docker start th3_ollama_proxy
docker logs th3_ollama_proxy

# Kali TOR
docker start th3_kali_tor
docker logs th3_kali_tor
```

---

## Ollama avec Docker

### Configuration pour accès depuis Docker

Dans les fichiers `.env` ou `docker.env`, utilisez:

```env
# Depuis un conteneur Docker vers Ollama sur l'hôte Windows
OLLAMA_API_BASE=http://host.docker.internal:11434
OLLAMA_URL=http://host.docker.internal:11434
```

### Vérifier qu'Ollama fonctionne

```powershell
# Lister les modèles
ollama list

# Vérifier le service
Invoke-RestMethod -Uri "http://localhost:11434/api/tags"

# Depuis un conteneur
docker exec <conteneur> curl http://host.docker.internal:11434/api/tags
```

---

## 🧹 Nettoyage

```powershell
# Supprimer les conteneurs arrêtés
docker container prune

# Supprimer les images inutilisées
docker image prune -a

# Supprimer les volumes orphelins
docker volume prune

# Nettoyage complet (attention!)
docker system prune -a --volumes
```

---

## 🆘 Résolution de Problèmes

### Le conteneur ne démarre pas

```powershell
# Vérifier les logs
docker logs <nom> --tail 100

# Vérifier l'état
docker inspect <nom> --format '{{.State.Status}}'
```

### Erreur de port déjà utilisé

```powershell
# Trouver qui utilise le port
netstat -ano | findstr :8502

# Arrêter le processus
taskkill /PID <pid> /F
```

### Problème de connexion réseau

```powershell
# Vérifier le réseau Docker
docker network ls
docker network inspect bridge
```

---

## 📚 Ressources

- [Documentation Docker](https://docs.docker.com/)
- [Docker Compose Reference](https://docs.docker.com/compose/compose-file/)
- [Docker Hub](https://hub.docker.com/)

---

*Guide créé pour le projet Th3 Thirty3 - Dernière mise à jour: 2025-12-23*
