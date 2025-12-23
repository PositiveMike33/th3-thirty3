# ⚡ Quick Start - Th3 Thirty3

## 🔧 Installation Rapide

### Avec Git (Recommandé)

```bash
# Cloner le projet
mkdir -p ~/.Th3Thirty3
cd ~/.Th3Thirty3
git clone https://github.com/PositiveMike33/th3-thirty3.git thethirty3
cd thethirty3

# Cloner les sous-projets
git clone https://github.com/lfnovo/open-notebook.git open-notebook

# Installer les dépendances
cd server && npm install
cd ../interface && npm install

# Configurer
cp server/.env.example server/.env
# ➡️ Éditer server/.env avec vos clés API
```

### Démarrage

```bash
# Terminal 1 - Backend
cd server && npm start

# Terminal 2 - Frontend  
cd interface && npm run dev
```

**URL**: http://localhost:5173

---

## 📦 Repos Nécessaires

| Repo | Commande | Description |
|------|----------|-------------|
| **th3-thirty3** | `git clone https://github.com/PositiveMike33/th3-thirty3.git` | Projet principal |
| **open-notebook** | `git clone https://github.com/lfnovo/open-notebook.git` | Knowledge AI |

---

## 🤖 Modèles Ollama Recommandés

```bash
ollama pull llama3.1:8b-instruct-q4_K_M
ollama pull nomic-embed-text:latest
ollama pull codestral:latest
```

---

## 🔑 Clés API Requises

Éditer `server/.env`:

```env
GEMINI_API_KEY=votre_clé_gemini
GOOGLE_MAPS_API_KEY=votre_clé_maps
SHODAN_API_KEY=votre_clé_shodan
```

---

📖 **Guide complet**: [INSTALLATION.md](./INSTALLATION.md)
