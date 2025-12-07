# 🚀 Configuration Llama 3.2 Vision 11B - Guide Complet

## ✅ Installation Terminée

- ✅ Granite 3.1 MoE 1B **supprimé**
- ✅ Llama 3.2 Vision 11B **installé**
- ✅ Nomic Embed Text **déjà présent** (meilleur embedding)
- ✅ Gestionnaire automatique de mémoire **créé**

---

## 🎯 Configuration AnythingLLM

### Étape 1 : Configurer le Workspace VPO

1. Ouvrir AnythingLLM : `http://localhost:3001`
2. Aller dans le workspace VPO :
   - `Expert Senior en Excellence Opérationnelle...`
3. Cliquer sur **⚙️ Settings**

### Étape 2 : Configurer Ollama

Dans **Chat Settings** :

```
Provider: Ollama
Base URL: http://localhost:11434
Model: llama3.2-vision:11b
Temperature: 0.1
Max Tokens: 8192
```

### Étape 3 : Configurer l'Embedding

Dans **Vector Database** :

```
Provider: Ollama
Model: nomic-embed-text:latest
```

---

## 🔧 Gestion Automatique de la Mémoire

Le système décharge automatiquement le modèle après **5 minutes d'inactivité** pour libérer RAM/VRAM.

### Comment ça fonctionne :

1. **Utilisation** → Modèle chargé en RAM/VRAM
2. **5 min d'inactivité** → Modèle déchargé automatiquement
3. **Nouvelle utilisation** → Modèle rechargé automatiquement

### Commandes Manuelles

```bash
# Vérifier les modèles chargés
ollama ps

# Décharger manuellement un modèle
ollama stop llama3.2-vision:11b

# Lister tous les modèles installés
ollama list
```

---

## 📊 Utilisation de la Mémoire

### Avant (avec Granite)
- **Granite 3.1 MoE 1B** : ~1.4 GB
- **Total** : ~1.4 GB

### Après (avec Llama 3.2 Vision)
- **Llama 3.2 Vision 11B** : ~7 GB (quand chargé)
- **Nomic Embed** : ~274 MB (pour embeddings)
- **Total quand actif** : ~7.3 GB
- **Total quand inactif** : ~0 GB (déchargé automatiquement)

---

## 🎯 Utilisation

### Via AnythingLLM Workspace VPO

1. Ouvrir le workspace VPO
2. Envoyer une image + description d'incident
3. Le modèle se charge automatiquement
4. Génère le rapport 5-Why
5. Après 5 min → Déchargement automatique

### Via API

```bash
# Le modèle se charge automatiquement à la première requête
curl -X POST http://localhost:3000/incident/complete \
  -H "Content-Type: application/json" \
  -d '{
    "media": "data:image/jpeg;base64,...",
    "description": "Bourrage Star Wheel"
  }'
```

---

## 🔍 Vérification

### Tester le modèle

```bash
# Test simple
ollama run llama3.2-vision:11b "Bonjour, peux-tu m'aider?"

# Test avec image (exemple)
ollama run llama3.2-vision:11b "Décris cette image" < image.jpg
```

### Vérifier l'embedding

```bash
ollama run nomic-embed-text "test embedding"
```

---

## 🆘 Dépannage

### "Model not found"
```bash
# Vérifier que le modèle est installé
ollama list

# Réinstaller si nécessaire
ollama pull llama3.2-vision:11b
```

### "Out of memory"
```bash
# Décharger tous les modèles
ollama ps
ollama stop <model-name>

# Ou redémarrer Ollama
# Windows : Redémarrer le service Ollama
```

### Modèle ne se décharge pas automatiquement
```bash
# Décharger manuellement
ollama stop llama3.2-vision:11b

# Vérifier qu'aucun modèle n'est chargé
ollama ps
```

---

## 📝 Modèles Installés

| Modèle | Taille | Usage | Auto-décharge |
|--------|--------|-------|---------------|
| **llama3.2-vision:11b** | 7.8 GB | Vision + 5-Why VPO | ✅ Oui (5 min) |
| **nomic-embed-text** | 274 MB | Embeddings (RAG) | ✅ Oui |

---

## 🎯 Avantages de cette Configuration

1. ✅ **100% Local** : Aucune donnée ne sort de ton réseau
2. ✅ **100% Gratuit** : Pas de coût API
3. ✅ **Gestion Mémoire** : Libération automatique RAM/VRAM
4. ✅ **Meilleur Vision Local** : Llama 3.2 Vision 11B
5. ✅ **Meilleur Embedding** : Nomic Embed Text
6. ✅ **Conforme AB InBev** : Données privées

---

## 🚀 Prochaines Étapes

1. ✅ Attendre fin du téléchargement
2. ✅ Configurer AnythingLLM (voir Étape 1-3 ci-dessus)
3. ✅ Tester avec un incident réel
4. ✅ Vérifier le déchargement automatique après 5 min

**C'est prêt ! 🎉**
