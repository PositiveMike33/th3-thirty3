# 🚀 Optimisation des performances de HackerGPT

**Date**: 2026-01-08  
**Problème**: HackerGPT prend du temps pour répondre dans le chat

## 🔍 Analyse du problème

HackerGPT utilise **Google Gemini 2.5 Flash API** comme backend principal pour générer des réponses axées sur la sécurité. Contrairement aux modèles locaux (Ollama), Gemini nécessite des appels API externes qui peuvent être lents selon :

- La latence réseau
- La charge actuelle de l'API Gemini
- La complexité de la requête
- La taille de la réponse générée

## ✅ Solutions implémentées

### 1. **Timeout de 30 secondes**
Ajout d'un timeout automatique sur les appels Gemini pour éviter les attentes infinies :

```javascript
const timeoutPromise = new Promise((_, reject) => 
    setTimeout(() => reject(new Error('Gemini API timeout après 30 secondes')), 30000)
);

const result = await Promise.race([geminiPromise, timeoutPromise]);
```

**Impact** : Si Gemini ne répond pas en 30 secondes, le système bascule automatiquement sur **AnythingLLM (workspace th3-thirty3)**.

### 2. **Feedback visuel utilisateur**
Ajout d'un message temporaire dans le chat pour informer l'utilisateur :

```
⏳ HackerGPT analyse en cours avec Gemini... (Fallback: AnythingLLM th3-thirty3)
```

**Impact** : L'utilisateur sait que sa requête est en traitement et connaît le système de fallback.

### 3. **Logging amélioré**
Messages console plus clairs :
- `[HACKERGPT] ⏳ Contacting Gemini API...` au démarrage
- `[HACKERGPT+GEMINI] ✅ Response generated` en cas de succès
- `[HACKERGPT] 🔄 Switching to AnythingLLM (th3-thirty3)` si Gemini timeout/erreur
- `[HACKERGPT+ANYTHINGLLM] ✅ Response generated` en cas de succès AnythingLLM
- `[HACKERGPT+OLLAMA] ⚠️ Fallback to local Ollama` en dernier recours

### 4. **Cascade de fallback intelligente**
Ordre de priorité :
1. **Gemini 2.5 Flash** (cloud, puissant, rapide)
2. **AnythingLLM th3-thirty3** (workspace avec base de connaissances)
3. **Ollama granite4** (local, dernier recours)

## 📊 Améliorations futures possibles

### Option A : Utiliser Gemini Flash 1.5 (plus rapide)
```javascript
model: 'gemini-1.5-flash' // Plus rapide mais moins récent
```

### Option B : Mettre en cache le système prompt
Gemini permet de mettre en cache les system prompts longs pour accélérer les requêtes répétées.

### Option C : Streaming des réponses
Afficher les tokens au fur et à mesure au lieu d'attendre la réponse complète :

```javascript
const stream = await geminiModel.generateContentStream(prompt);
for await (const chunk of stream) {
    // Envoyer chunk par chunk via WebSocket
}
```

### Option D : Passer en mode local par défaut
Utiliser Ollama + RAG comme backend principal et Gemini seulement pour les questions complexes.

## 🎯 Recommandations

1. **Court terme** : Les changements actuels suffisent - timeout + feedback
2. **Moyen terme** : Implémenter le streaming pour une meilleure UX
3. **Long terme** : Créer un système hybride intelligent qui choisit automatiquement entre local/cloud selon la complexité

## 🧪 Tester les améliorations

1. Redémarrer le serveur pour appliquer les changements
2. Sélectionner "🔓 HackerGPT + Gemini" dans le chat
3. Poser une question de sécurité
4. Observer le message "⏳ HackerGPT analyse en cours avec Gemini..."
5. La réponse devrait arriver en 10-30 secondes max

**Scénarios de fallback** :
- ✅ **Gemini répond** (< 30s) → Réponse de Gemini
- ⚠️ **Gemini timeout** (> 30s) → Bascule vers AnythingLLM th3-thirty3
- 🔴 **AnythingLLM échoue aussi** → Dernier recours : Ollama granite4

## 📝 Fichiers modifiés

- `server/llm_service.js` - Timeout + logging amélioré
- `interface/src/ChatInterface.jsx` - Message de feedback utilisateur
