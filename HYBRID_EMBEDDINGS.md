# 🧠 Système d'Embeddings Hybride - Gemini + Nomic

## Vue d'ensemble

Th3 Thirty3 utilise maintenant un **système d'embeddings intelligent** qui combine le meilleur des deux mondes:

- **☁️ Gemini (Cloud)**: Rapide, puissant, pour les requêtes en ligne
- **🏠 nomic-embed-text (Local)**: Gratuit, privé, fonctionne offline

## Architecture

```
┌─────────────────────────────────────────────┐
│        AnythingLLM Wrapper                  │
│  (Détecte les erreurs d'embedding)          │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────┐
│        Embedding Service                    │
│    (Gère le fallback automatique)           │
└──────┬──────────────────────┬───────────────┘
       │                      │
       ▼                      ▼
┌──────────────┐      ┌──────────────┐
│    Gemini    │      │    Ollama    │
│ (text-emb-   │      │   (nomic-    │
│  004)        │      │ embed-text)  │
└──────────────┘      └──────────────┘
```

## Fonctionnement

### Mode AUTO (par défaut)
1. **Tente Gemini en premier** (plus rapide)
2. **Si échec** (pas d'internet, quota dépassé, etc.)
3. **Bascule automatiquement vers nomic-embed-text**

### Modes Spécifiques
bash
# Forcer Gemini
await embeddingService.embed(text, 'gemini');

# Forcer Ollama (local)
await embeddingService.embed(text, 'ollama');

# Auto-fallback (recommandé)
await embeddingService.embed(text, 'auto');
```

## Avantages

### ✅ **Résilience**
- Continue de fonctionner même si Gemini est down
- Pas d'interruption de service

### ✅ **Performance**
- Cache intégré pour les requêtes répétées
- Gemini = ~100ms, nomic = ~200ms (local)

### ✅ **Économies**
- Utilise Gemini quand disponible (gratuit tier)
- Bascule vers local si quota atteint

### ✅ **Confidentialité**
- Données sensibles? Force le mode local
- Aucune donnée n'est envoyée au cloud en mode Ollama

## Recherche Sémantique

Le service inclut une fonction de recherche sémantique puissante:

```javascript
const documents = [
    { text: "SQL injection tutorial", metadata: { topic: "web" } },
    { text: "Machine learning for security", metadata: { topic: "ml" } }
];

const results = await embeddingService.findSimilar(
    "How to prevent web attacks?",
    documents,
    topK: 3,
    provider: 'auto'
);

// Résultat:
// [
//   { text: "SQL injection tutorial", similarity: 0.89, metadata: {...} },
//   ...
// ]
```

## Configuration AnythingLLM

### Option 1: Interface Graphique
1. Ouvrir AnythingLLM Desktop
2. Settings → Embedding Preference
3. **Laisser sur Gemini** (le wrapper gère le fallback automatiquement)

### Option 2: Forcer Local
Si tu veux TOUJOURS utiliser local (confidentialité max):
1. Settings → Embedding Preference
2. Provider: **Ollama**
3. Model: **nomic-embed-text**
4. Base URL: `http://localhost:11434`

## Statistiques

Le service track les performances:

```javascript
const stats = embeddingService.getStats();
console.log(stats);
// {
//   gemini_success: 42,
//   gemini_failures: 3,
//   ollama_success: 3,
//   ollama_failures: 0,
//   cache_size: 15,
//   total_requests: 48,
//   fallback_rate: 0.07  // 7% de fallback vers Ollama
// }
```

## Tests

Exécute le script de test:

```bash
node server/test_hybrid_embeddings.js
```

Ce script teste:
- ✅ Fallback automatique
- ✅ Embeddings par batch
- ✅ Recherche sémantique
- ✅ Performance du cache
- ✅ Statistiques détaillées

## Cas d'Usage

### 🔒 **Données Sensibles**
```javascript
// Force local pour données confidentielles
const embedding = await embeddingService.embed(
    "Informations confidentielles...",
    'ollama'  // ← Force local, jamais cloud
);
```

### ⚡ **Performance Critique**
```javascript
// Gemini est plus rapide
const embedding = await embeddingService.embed(
    "Query publique...",
    'gemini'
);
```

### 🌐 **Offline Mode**
```javascript
// Auto-détecte et bascule automatiquement
const embedding = await embeddingService.embed(
    "Requête quelconque...",
    'auto'  // ← Recommandé: intelligent
);
```

## Maintenance

### Vérifier les modèles installés
```bash
ollama list
```

### Installer nomic-embed-text
```bash
ollama pull nomic-embed-text
```

### Mettre à jour Gemini API
Dans `.env` ou `settings.json`:
```
GEMINI_API_KEY=ton_api_key
```

## Débogage

### Logs détaillés
Les logs montrent quel provider est utilisé:

```
[EMBEDDING] Gemini failed: Connection error, falling back to Ollama...
[FALLBACK] Using local embeddings + RAG
[OFFLINE MODE] No documents available, using plain local LLM
```

### Test de connexion
```bash
# Tester Gemini
node server/test_hybrid_embeddings.js

# Tester Ollama
ollama run nomic-embed-text "test"
```

## Roadmap

- [ ] Support pour d'autres providers (Cohere, Voyage AI)
- [ ] Embeddings multimodaux (texte + images)
- [ ] Compression d'embeddings pour économiser RAM
- [ ] Index vectoriel persistant (ChromaDB, Qdrant)
- [ ] API REST pour exposer le service

## Questions Fréquentes

**Q: Quel est le meilleur provider?**
A: Ça dépend! Gemini est plus rapide, nomic est plus privé. Le mode `auto` choisit intelligemment.

**Q: Les embeddings sont-ils compatibles entre providers?**
A: Non, les dimensions diffèrent. Utilise toujours le même provider pour comparer.

**Q: Combien coûte Gemini?**
A: Le tier gratuit offre 1500 requêtes/jour. Largement suffisant!

**Q: nomic-embed-text est-il aussi bon que Gemini?**
A: Pour la plupart des tâches, oui! Performance similaire, juste un peu plus lent.

---

**🎯 Objectif**: Un système d'embeddings qui ne tombe jamais en panne, s'adapte automatiquement, et respecte ta vie privée.
