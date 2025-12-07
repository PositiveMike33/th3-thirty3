# 🏭 Système d'Analyse d'Incidents KeelClip - Documentation

## Vue d'Ensemble

Le système d'analyse d'incidents KeelClip intègre la vision par ordinateur (via **AnythingLLM**) avec l'expertise VPO (AB InBev) pour générer automatiquement des rapports 5-Why conformes aux standards d'audit.

**Architecture :**
- **Workspace Dédié** : `expert-senior-en-excellence-operationnelle-standard-vpowcm-et-specialiste-technique-des-machines-keelclip`
- **Modèle Recommandé** : **Qwen2.5-VL-72B** (via OpenRouter) ⭐
- **Vision Analysis** : Analyse d'images industrielles avec modèle vision multimodal
- **5-Why Generation** : Génération de rapports via le workspace VPO dédié
- **Validation** : Contrôle qualité automatique selon standards VPO

**⚠️ Important** : Ce module utilise **UNIQUEMENT** le workspace VPO spécifique dans AnythingLLM. Assurez-vous que ce workspace existe et est configuré avec un modèle vision.

## 🎯 Fonctionnalités

### 1. Analyse Visuelle Automatique
- **Images** : Analyse de photos d'incidents machine via workspace VPO
- **Modèle** : Qwen2.5-VL-72B (open source, excellent en français technique)
- **Détection** : Identification automatique des composants KeelClip
- **Extraction** : Défauts, localisation, indices visuels, risques sécurité



### 2. Génération de Rapports 5-Why
- **Format VPO** : Tableaux QQOQCCP, 5 Pourquoi, Plan d'Action
- **Vocabulaire Technique** : Termes exacts (Star Wheel, Lug Chain, PLC, etc.)
- **Cause Racine Systémique** : Jamais d'erreur humaine
- **Prêt pour SAP/DMS** : Copier-coller direct

### 3. Validation Automatique
- **Score de Qualité** : 0-100 points
- **Détection d'Erreurs** : Blâme opérateur, sections manquantes
- **Recommandations** : Excellent / Bon / Insuffisant

## 📡 API Endpoints

### POST `/incident/analyze`
Analyse une image/vidéo d'incident.

**Request:**
```json
{
  "media": "data:image/jpeg;base64,/9j/4AAQ...", // ou chemin fichier
  "mediaType": "image", // ou "video"
  "description": "Bourrage au Star Wheel" // optionnel
}
```

**Response:**
```json
{
  "success": true,
  "analysis": {
    "composants_visibles": ["Star Wheel", "Lug Chain"],
    "defaut_principal": "Bourrage de cartons",
    "localisation": "Star Wheel - Zone de transfert",
    "indices_visuels": ["Accumulation", "Désalignement"],
    "risques_securite": ["Risque de coincement"],
    "hypotheses_causes": ["Désalignement", "Usure"]
  },
  "summary": "📸 **Incident Détecté**..."
}
```

### POST `/incident/generate-5why`
Génère un rapport 5-Why à partir d'une analyse.

**Request:**
```json
{
  "analysis": { /* objet d'analyse */ },
  "description": "Contexte additionnel de l'opérateur"
}
```

**Response:**
```json
{
  "success": true,
  "report": "## 1. 📋 DÉFINITION DU PROBLÈME...",
  "validation": {
    "valid": true,
    "score": 95,
    "issues": [],
    "recommendation": "Excellent - Prêt pour audit"
  }
}
```

### POST `/incident/complete`
Workflow complet : Analyse + 5-Why en un seul appel.

**Request:**
```json
{
  "media": "data:image/jpeg;base64,...",
  "mediaType": "image",
  "description": "Bourrage répété pendant shift de nuit"
}
```

**Response:**
```json
{
  "success": true,
  "analysis": { /* ... */ },
  "report": "## 1. 📋 DÉFINITION...",
  "validation": { /* ... */ },
  "summary": "📸 **Incident Détecté**..."
}
```

### POST `/incident/validate`
Valide un rapport 5-Why existant.

**Request:**
```json
{
  "report": "Texte complet du rapport..."
}
```

**Response:**
```json
{
  "success": true,
  "validation": {
    "valid": false,
    "score": 45,
    "issues": ["⛔ INTERDIT : Erreur Humaine détecté"],
    "recommendation": "Insuffisant - Révision majeure requise"
  }
}
```

## 💬 Intégration Chat

Le système s'active **automatiquement** dans le chat quand :

1. **Image envoyée** + **Mots-clés VPO** détectés :
   - `panne`, `incident`, `keelclip`, `5 why`, `ewo`, `rca`
   - `machine`, `emballage`, `maintenance`, `défaut`, `bourrage`

2. **Comportement** :
   - Analyse visuelle automatique
   - Injection du résumé dans le contexte
   - Si "5 why" ou "rapport" mentionné → Génération complète

**Exemple d'utilisation :**
```
Utilisateur: [Envoie photo] "Panne au Star Wheel, besoin du rapport 5-Why"

Thirty3: 
📸 **Incident Détecté**
**Défaut :** Bourrage de cartons au niveau du Star Wheel
**Localisation :** Star Wheel - Zone de transfert
⚠️ **Sécurité :** Risque de coincement lors du redémarrage

[Génère automatiquement le rapport 5-Why complet]

## 1. 📋 DÉFINITION DU PROBLÈME (QQOQCCP)
...
```

## 🔧 Configuration

### Variables d'Environnement
```bash
# AnythingLLM (Requis pour l'analyse visuelle)
ANYTHING_LLM_URL=http://localhost:3001/api/v1
ANYTHING_LLM_KEY=your_anythingllm_api_key

# OpenRouter (Recommandé pour Qwen2.5-VL-72B)
OPENROUTER_API_KEY=sk-or-v1-your-key-here
```

### Configuration AnythingLLM - WORKSPACE VPO

**⚠️ IMPORTANT** : Le système utilise un workspace spécifique. Vous devez le créer exactement comme suit :

#### **Étape 1 : Créer le Workspace VPO**

1. **Ouvrir AnythingLLM** : `http://localhost:3001`

2. **Créer un nouveau workspace** :
   - Nom : `Expert Senior en Excellence Opérationnelle (Standard VPO/WCM) et Spécialiste Technique des machines KeelClip`
   - Le slug sera généré automatiquement : `expert-senior-en-excellence-operationnelle-standard-vpowcm-et-specialiste-technique-des-machines-keelclip`

#### **Étape 2 : Configurer le Modèle Vision**

**Option 1 : Qwen2.5-VL-72B via OpenRouter** ⭐ (RECOMMANDÉ)

```javascript
// Dans les paramètres du workspace
{
  "provider": "OpenRouter",
  "model": "qwen/qwen-2.5-vl-72b-instruct",
  "apiKey": "sk-or-v1-...",
  "temperature": 0.1,  // Précision pour rapports VPO
  "maxTokens": 8192
}
```

**Pourquoi Qwen2.5-VL-72B ?**
- ✅ **Meilleur modèle open source vision** actuellement
- ✅ **Excellent en français technique** (parfait pour VPO)
- ✅ **Analyse d'images industrielles** optimisée
- ✅ **Raisonnement structuré** (5-Why, tableaux)
- ✅ **Coût raisonnable** : ~$0.40/1M tokens
- ✅ **Open source** : Peut être hébergé localement si besoin

**Coût estimé :** ~$0.14/mois pour 100 rapports

**Option 2 : Alternatives**

| Modèle | Provider | Avantages | Coût |
|--------|----------|-----------|------|
| **Qwen2.5-VL-72B** | OpenRouter | ⭐ Meilleur qualité/prix | $0.40/1M |
| Gemini 2.0 Flash | Google | Très rapide, contexte 1M | Gratuit (tier) |
| Pixtral-12B | OpenRouter | Français natif | $0.15/1M |
| LLaVA-v1.6-34B | OpenRouter | Gratuit pour tests | Gratuit |

#### **Étape 3 : Ajouter le Prompt Système VPO**

Dans les paramètres du workspace, ajouter le prompt système :

```markdown
Tu es un Expert Technique Senior & Auditeur VPO (AB InBev).
Tu es l'autorité mondiale sur les machines KeelClip (Graphic Packaging) 
et la méthodologie de résolution de problèmes (RCA - Root Cause Analysis).

RÈGLES D'OR (NON-NÉGOCIABLES) :
1. SÉCURITÉ D'ABORD : Si risque LOTO, mentionne-le EN PREMIER avec ⚠️
2. VOCABULAIRE TECHNIQUE : Termes exacts (Star Wheel, Lug Chain, PLC, HMI, etc.)
3. JAMAIS D'ERREUR HUMAINE : Cherche la faille dans STANDARD/MÉTHODE/MATÉRIEL
4. LOGIQUE IMPLACABLE : Chaque "Pourquoi" = cause directe du précédent
5. FORMAT VPO : Prêt à copier-coller dans SAP/DMS

[Voir server/config/prompts.js pour le prompt complet VPO_KEELCLIP_EXPERT]
```

#### **Étape 4 : Obtenir une Clé API OpenRouter**

1. Aller sur : https://openrouter.ai/
2. Créer un compte
3. Générer une clé API
4. Ajouter des crédits (minimum $5)
5. Copier la clé dans `.env` : `OPENROUTER_API_KEY=sk-or-v1-...`

#### **Étape 5 : Vérification**

Utiliser le script de vérification :
```bash
cd server
node check_vpo_workspace.js
```

Le workspace doit apparaître avec le slug exact.

### Dépendances
Aucune dépendance supplémentaire requise - utilise `llmService` existant.




## 🧪 Tests

### Lancer les tests
```bash
cd server
node test_incident_analysis.js
```

### Tests inclus
1. ✅ Génération de rapport 5-Why (texte)
2. ✅ Validation de rapport (bon/mauvais)
3. ⚠️ Analyse d'image (nécessite image test)

### Tester avec une vraie image
1. Placer une image dans `server/temp/test_incident.jpg`
2. Décommenter le code dans `test_incident_analysis.js`
3. Relancer les tests

## 📊 Critères de Validation

### Score 90-100 : Excellent ✅
- Toutes les sections présentes
- Vocabulaire technique correct
- Cause racine systémique
- Zéro blâme opérateur

### Score 70-89 : Bon ⚠️
- Sections principales présentes
- Quelques termes techniques manquants
- Cause racine acceptable

### Score 0-69 : Insuffisant ❌
- Sections manquantes
- Blâme opérateur détecté
- Pas de cause racine systémique

## 🚀 Exemples d'Utilisation

### Via API (cURL)
```bash
# Analyse complète
curl -X POST http://localhost:3000/incident/complete \
  -H "Content-Type: application/json" \
  -d '{
    "media": "data:image/jpeg;base64,/9j/4AAQ...",
    "mediaType": "image",
    "description": "Bourrage répété au Star Wheel"
  }'
```

### Via Chat
```javascript
// Frontend
const response = await fetch('/chat', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    message: "Panne KeelClip, génère le rapport 5-Why",
    image: "data:image/jpeg;base64,...",
    provider: "cloud",
    model: "gemini-1.5-pro"
  })
});
```

### Via Services (Backend)
```javascript
const VisionService = require('./vision_service');
const KeelClipAnalyzer = require('./keelclip_analyzer');

const visionService = new VisionService();
const analyzer = new KeelClipAnalyzer(llmService);

// Analyser
const analysis = await visionService.analyzeKeelClipIncident(imagePath, 'image');

// Générer 5-Why
const report = await analyzer.generate5Why(analysis, operatorDescription);

// Valider
const validation = analyzer.validate5WhyReport(report);
```

## 🔒 Sécurité

### Règles VPO Strictes
1. ❌ **JAMAIS** de conclusion "Erreur humaine"
2. ❌ **JAMAIS** de blâme opérateur
3. ✅ **TOUJOURS** une cause racine systémique
4. ✅ **TOUJOURS** le vocabulaire technique exact

### Détection Automatique
Le système **refuse** automatiquement les rapports contenant :
- "erreur humaine", "faute opérateur"
- "inattention", "négligence", "oubli"

## 📝 Format de Sortie Standard

```markdown
## 1. 📋 DÉFINITION DU PROBLÈME (QQOQCCP)
| Élément | Description |
|---------|-------------|
| **Quoi** | Bourrage de cartons au Star Wheel |
| **Où** | Star Wheel - Zone de transfert |
| **Quand** | Shift de nuit, après 2h de production |
| **Impact** | ⚫ Arrêt Ligne |

## 2. 🔍 ANALYSE DES 5 POURQUOI (Chaîne Causale)
| # | Pourquoi | Cause |
|---|----------|-------|
| **P1** | Cause directe visible | Accumulation de cartons au Star Wheel |
| **P2** | Cause technique | Désalignement du Star Wheel de 2mm |
| **P3** | Dérive paramètre/usure | Usure excessive des lugs de la Lug Chain |
| **P4** | Absence détection/maintenance | Pas de vérification d'alignement dans le CIL |
| **P5** | **CAUSE RACINE** | CIL incomplet : Vérification d'alignement Star Wheel absente |

## 3. 🛠️ PLAN D'ACTION
| Type | Action | Responsable | Délai |
|------|--------|-------------|-------|
| **Corrective (MAINTENANT)** | Réaligner Star Wheel, remplacer lugs usés | Opérateur + Maintenance | Immédiat |
| **Préventive (SYSTÉMIQUE)** | Ajouter vérification alignement Star Wheel au CIL quotidien | Ingénierie | 1 semaine |
```

## 🎓 Formation

### Pour les Opérateurs
1. Prendre photo/vidéo de l'incident
2. Envoyer via chat avec description
3. Système génère le rapport automatiquement
4. Copier-coller dans SAP/DMS

### Pour les Auditeurs
- Le rapport est conforme VPO par design
- Score de validation visible
- Traçabilité complète (analyse visuelle + raisonnement)

## 🐛 Dépannage

### "LLMService not set"
→ Vérifier que `visionService` est initialisé avec `llmService`
→ Dans `index.js` : `const visionService = new VisionService(llmService);`

### "AnythingLLM URL or Key missing"
→ Vérifier `ANYTHING_LLM_URL` et `ANYTHING_LLM_KEY` dans `.env`
→ Vérifier que AnythingLLM est démarré (`http://localhost:3001`)

### "5-Why generation failed"
→ Vérifier que `llmService` est initialisé
→ Vérifier connexion à AnythingLLM
→ Vérifier que le workspace AnythingLLM existe

### Score de validation faible
→ Vérifier que le rapport contient :
  - Sections QQOQCCP, 5 Pourquoi, Plan d'Action
  - Vocabulaire technique KeelClip
  - Cause racine systémique (Standard/CIL/OPL)

### Image non analysée
→ Vérifier que le modèle configuré dans AnythingLLM supporte les images
→ Modèles recommandés : GPT-4 Vision, Claude 3 Opus/Sonnet
→ Vérifier le format de l'image (JPEG, PNG supportés)


## 📞 Support

Pour toute question ou amélioration :
- Consulter les logs : `[INCIDENT]`, `[VISION]`, `[KEELCLIP]`
- Tester avec `test_incident_analysis.js`
- Vérifier la validation du rapport

---

**Version:** 1.0.0  
**Dernière mise à jour:** 2025-12-05  
**Auteur:** Th3 Thirty3 System
