# ✅ Installation Complète : Llama 3.2 Vision 11B

## 🎉 Résumé

### ✅ Actions Effectuées

1. **Supprimé** : Granite 3.1 MoE 1B (~1.4 GB libérés)
2. **Installé** : Llama 3.2 Vision 11B (7.8 GB)
3. **Conservé** : Nomic Embed Text (274 MB) - Meilleur embedding
4. **Créé** : Gestionnaire automatique de mémoire (`ollama_manager.js`)

### 📊 Modèles Actuels

```
NAME                       SIZE      USAGE
llama3.2-vision:11b        7.8 GB    Vision + 5-Why VPO
nomic-embed-text:latest    274 MB    Embeddings (RAG)
```

---

## 🔧 Configuration AnythingLLM

### Pour le Workspace VPO

1. Ouvrir `http://localhost:3001`
2. Aller dans le workspace VPO
3. **Settings** → **Chat Settings**

```
Provider: Ollama
Base URL: http://localhost:11434
Model: llama3.2-vision:11b
Temperature: 0.1
Max Tokens: 8192
```

4. **Settings** → **Vector Database**

```
Provider: Ollama
Model: nomic-embed-text:latest
```

---

## 🎯 Gestion Automatique de la Mémoire

### Comment ça fonctionne

Le système décharge automatiquement le modèle après **5 minutes d'inactivité** :

```
Utilisation → Modèle chargé (7.8 GB VRAM)
     ↓
5 min inactivité
     ↓
Déchargement auto → RAM/VRAM libérée (0 GB)
     ↓
Nouvelle utilisation → Rechargement auto
```

### Commandes Manuelles

```bash
# Voir les modèles chargés en mémoire
ollama ps

# Décharger manuellement
ollama stop llama3.2-vision:11b

# Vérifier qu'aucun modèle n'est chargé
ollama ps  # Doit être vide
```

---

## 🚀 Utilisation

### Via AnythingLLM

1. Ouvrir workspace VPO
2. Envoyer image + description incident
3. Modèle se charge automatiquement
4. Génère rapport 5-Why
5. Après 5 min → Déchargement auto

### Via API

```bash
curl -X POST http://localhost:3000/incident/complete \
  -H "Content-Type: application/json" \
  -d '{
    "media": "data:image/jpeg;base64,...",
    "description": "Bourrage Star Wheel"
  }'
```

---

## 💡 Avantages

1. ✅ **100% Local** : Données privées (conforme AB InBev)
2. ✅ **100% Gratuit** : Pas de coût API
3. ✅ **Gestion Mémoire** : Libération auto RAM/VRAM
4. ✅ **Meilleur Vision Local** : Llama 3.2 Vision 11B
5. ✅ **Meilleur Embedding** : Nomic Embed Text
6. ✅ **Pas de limite** : Requêtes illimitées

---

## 📝 Prochaines Étapes

1. ✅ Configurer AnythingLLM (voir ci-dessus)
2. ✅ Tester avec un incident réel
3. ✅ Vérifier le déchargement auto après 5 min

**Tout est prêt ! 🎉**

---

## 📚 Documentation

- **Guide complet** : `SETUP_LLAMA_VISION.md`
- **Gestionnaire mémoire** : `ollama_manager.js`
- **Tests** : `test_incident_analysis.js`
