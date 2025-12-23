# 🚀 Installation Guide - Th3 Thirty3

## Prérequis Système

### Logiciels Requis
- **Node.js** v18+ (recommandé: v20 LTS)
- **npm** v9+
- **Git**
- **Docker Desktop** (pour Open Notebook et certains services)
- **Ollama** (pour les modèles locaux)
- **Python 3.10+** (pour les scripts MCP)

### Clés API Requises
Configurer dans `/server/.env` ou via l'interface Settings:
- `GEMINI_API_KEY` - Google AI (Gemini)
- `OPENAI_API_KEY` - OpenAI (optionnel)
- `ANTHROPIC_API_KEY` - Anthropic Claude (optionnel)
- `PERPLEXITY_API_KEY` - Perplexity AI (optionnel)
- `SHODAN_API_KEY` - Shodan (OSINT)
- `GOOGLE_MAPS_API_KEY` - Google Maps Platform

---

## 📥 Installation avec Antigravity

### Étape 1: Cloner le Projet Principal

```bash
# Créer le dossier de travail
mkdir -p ~/.Th3Thirty3
cd ~/.Th3Thirty3

# Cloner le repo principal
git clone https://github.com/PositiveMike33/th3-thirty3.git thethirty3
cd thethirty3
```

### Étape 2: Cloner les Sous-Projets

```bash
# Open Notebook (Knowledge Management)
git clone https://github.com/lfnovo/open-notebook.git open-notebook

# Fabric Patterns (AI Patterns - déjà inclus dans server/fabric)
# Les patterns sont déjà inclus dans le repo principal
```

### Étape 3: Installer les Dépendances Backend

```bash
cd server
npm install
```

### Étape 4: Configurer l'Environnement Backend

```bash
# Copier le fichier d'exemple
cp .env.example .env

# Éditer avec vos clés API
# Obligatoires:
# - GEMINI_API_KEY=votre_clé_gemini
# - GOOGLE_MAPS_API_KEY=votre_clé_google_maps
```

### Étape 5: Installer les Dépendances Frontend

```bash
cd ../interface
npm install
```

### Étape 6: Configuration Google OAuth (pour Gmail, Calendar, Drive, Tasks)

1. Aller sur [Google Cloud Console](https://console.cloud.google.com/)
2. Créer un projet ou sélectionner un existant
3. Activer les APIs: Gmail, Calendar, Drive, Tasks
4. Créer des identifiants OAuth 2.0
5. Télécharger le fichier `credentials.json`
6. Placer dans `/server/credentials.json`

### Étape 7: Démarrer l'Application

```bash
# Terminal 1 - Backend
cd server
npm start

# Terminal 2 - Frontend
cd interface
npm run dev
```

Accéder à: **http://localhost:5173**

---

## 🐳 Services Docker (Optionnels)

### Open Notebook (Knowledge Management AI)

```bash
cd open-notebook
docker compose -f docker-compose.single.yml up -d
```
Accès: **http://localhost:8502**

### TOR Proxy (pour OSINT anonyme)

```bash
docker run -d --name tor-proxy -p 9050:9050 -p 9051:9051 dperson/torproxy
```

---

## 🤖 Installer Ollama et les Modèles

### Windows
Télécharger depuis: https://ollama.ai/download

### Linux/Mac
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

### Modèles Recommandés

```bash
# Modèle principal (recommandé)
ollama pull llama3.1:8b-instruct-q4_K_M

# Modèles spécialisés
ollama pull codestral:latest          # Code
ollama pull mistral:latest            # Général
ollama pull dolphin-mistral:latest    # Uncensored
ollama pull nomic-embed-text:latest   # Embeddings RAG

# Modèles de sécurité (optionnels)
ollama pull deepseek-r1:8b            # Raisonnement
ollama pull qwen2.5-coder:7b          # Code avancé
```

---

## 📋 Repos à Tirer (Récapitulatif)

| Repo | URL | Destination | Description |
|------|-----|-------------|-------------|
| **th3-thirty3** | `github.com/PositiveMike33/th3-thirty3` | `~/.Th3Thirty3/thethirty3` | Projet principal |
| **open-notebook** | `github.com/lfnovo/open-notebook` | `thethirty3/open-notebook` | Knowledge Management AI |

---

## 🔧 Structure des Dossiers

```
~/.Th3Thirty3/thethirty3/
├── interface/              # Frontend React + Vite
│   ├── src/
│   │   ├── App.jsx
│   │   ├── ChatInterface.jsx
│   │   ├── GoogleServicesPage.jsx     # Page Google Services
│   │   ├── OpenNotebookPage.jsx       # Page Open Notebook
│   │   ├── DartAI.jsx                 # Project Management
│   │   └── components/
│   └── package.json
├── server/                 # Backend Node.js
│   ├── index.js
│   ├── llm_service.js
│   ├── google_service.js
│   ├── notebooklm_service.js
│   ├── credentials.json    # Google OAuth (à créer)
│   ├── tokens/             # Tokens Google (auto-généré)
│   ├── data/
│   │   └── notebooklm/     # Contenu NotebookLM
│   │       ├── osint/
│   │       ├── network/
│   │       ├── vuln/
│   │       ├── coding/
│   │       └── custom/
│   └── package.json
├── open-notebook/          # Sous-projet Open Notebook
├── scripts/                # Scripts Python/MCP
├── docs/                   # Documentation
└── README.md
```

---

## ⚡ Script d'Installation Rapide (PowerShell)

```powershell
# Installation complète automatisée
$installPath = "$env:USERPROFILE\.Th3Thirty3"

# Créer le dossier
New-Item -ItemType Directory -Force -Path $installPath
Set-Location $installPath

# Cloner le repo principal
git clone https://github.com/PositiveMike33/th3-thirty3.git thethirty3
Set-Location thethirty3

# Cloner Open Notebook
git clone https://github.com/lfnovo/open-notebook.git open-notebook

# Installer backend
Set-Location server
npm install
Copy-Item .env.example .env
Write-Host "⚠️ EDIT server/.env with your API keys!"

# Installer frontend
Set-Location ../interface
npm install

Write-Host "✅ Installation complete!"
Write-Host "➡️ Start backend: cd server && npm start"
Write-Host "➡️ Start frontend: cd interface && npm run dev"
```

---

## 🐧 Script d'Installation Rapide (Bash/Linux/Mac)

```bash
#!/bin/bash
INSTALL_PATH="$HOME/.Th3Thirty3"

# Créer le dossier
mkdir -p "$INSTALL_PATH"
cd "$INSTALL_PATH"

# Cloner le repo principal
git clone https://github.com/PositiveMike33/th3-thirty3.git thethirty3
cd thethirty3

# Cloner Open Notebook
git clone https://github.com/lfnovo/open-notebook.git open-notebook

# Installer backend
cd server
npm install
cp .env.example .env
echo "⚠️ EDIT server/.env with your API keys!"

# Installer frontend
cd ../interface
npm install

echo "✅ Installation complete!"
echo "➡️ Start backend: cd server && npm start"
echo "➡️ Start frontend: cd interface && npm run dev"
```

---

## 🔑 Comptes Google Configurés

L'application est configurée pour ces comptes Google:
1. `th3thirty3@gmail.com` (principal)
2. `mikegauthierguillet@gmail.com`
3. `mgauthierguillet@gmail.com`

Pour ajouter/modifier les comptes, éditer `server/index.js` ligne ~87.

---

## 🆘 Dépannage

### Le frontend ne se lance pas
```bash
cd interface
rm -rf node_modules package-lock.json
npm install
npm run dev
```

### Le backend ne se connecte pas à Ollama
```bash
# Vérifier qu'Ollama tourne
ollama list

# Redémarrer Ollama si nécessaire
ollama serve
```

### Erreur Google OAuth
1. Vérifier que `credentials.json` est dans `/server/`
2. Supprimer les tokens: `rm -rf server/tokens/*`
3. Se reconnecter via l'interface

### Open Notebook Docker ne démarre pas
```bash
cd open-notebook
docker compose -f docker-compose.single.yml down
docker compose -f docker-compose.single.yml up -d --build
```

---

## 📞 Support

- **GitHub Issues**: https://github.com/PositiveMike33/th3-thirty3/issues
- **Documentation**: `/docs/` dans le repo

---

✨ **Bon développement avec Th3 Thirty3!**
