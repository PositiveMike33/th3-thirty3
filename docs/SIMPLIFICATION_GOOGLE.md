# 🧹 Plan de Simplification - Services Google

## État Actuel

### Services Google (À SUPPRIMER)
- `google_service.js` - 328 lignes, charge googleapis (189 MB)
- `archive_schedulepro.js` - Fichier archivé, utilise Gmail
- Routes `/google/*` dans index.js

### Fonctionnalités remplacées par DartAI
| Google | DartAI Équivalent |
|--------|-------------------|
| Google Tasks | `/api/dart/tasks` |
| Google Calendar | Dart intégration calendrier |
| Gmail | Non nécessaire (email séparé) |
| Google Drive | Non nécessaire |

## Actions Proposées

### Phase 1: Archiver les fichiers Google
```
server/google_service.js → server/archive/google_service.js.bak
server/archive_schedulepro.js → server/archive/
```

### Phase 2: Nettoyer index.js
- Supprimer import GoogleService
- Supprimer routes `/google/*`
- Supprimer `fetchGoogleContext()`

### Phase 3: Supprimer googleapis de package.json
```bash
cd server
npm uninstall googleapis google-auth-library
# Économie: ~189 MB + 10 MB = ~200 MB
```

## Économies Attendues

| Métrique | Avant | Après |
|----------|-------|-------|
| npm dependencies | 23 | 21 |
| node_modules size | ~520 MB | ~320 MB |
| Startup memory | +189 MB | 0 MB |
| Code complexity | Complexe OAuth | Simple |

## Fonctionnalités Préservées

✅ DartAI - Gestion de tâches avancée avec IA
✅ Groq/DeepSeek - LLM rapides
✅ Ollama - LLM local
✅ Shodan/OSINT - Cybersécurité
✅ Cameras - Découverte et gestion
✅ Training - Formation des modèles

---
*Créé: 2024-12-24*
