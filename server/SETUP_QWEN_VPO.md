# 🚀 Guide Rapide : Configuration Qwen2.5-VL-72B pour VPO

## Prérequis
- AnythingLLM installé et démarré (`http://localhost:3001`)
- Compte OpenRouter avec crédits ($5 minimum)

## Étapes de Configuration

### 1️⃣ Créer le Workspace VPO dans AnythingLLM

1. Ouvrir `http://localhost:3001`
2. Cliquer sur **"New Workspace"**
3. Nom : `Expert Senior en Excellence Opérationnelle (Standard VPO/WCM) et Spécialiste Technique des machines KeelClip`
4. Cliquer sur **"Create Workspace"**

### 2️⃣ Configurer OpenRouter

1. Aller sur https://openrouter.ai/
2. Créer un compte (ou se connecter)
3. Aller dans **Settings** → **API Keys**
4. Cliquer sur **"Create API Key"**
5. Copier la clé : `sk-or-v1-...`
6. Ajouter des crédits : **Settings** → **Credits** (minimum $5)

### 3️⃣ Configurer le Modèle dans AnythingLLM

1. Dans le workspace VPO, cliquer sur **⚙️ Settings**
2. Aller dans **"Chat Settings"**
3. Sélectionner :
   - **Provider** : `Custom OpenAI Compatible`
   - **Base URL** : `https://openrouter.ai/api/v1`
   - **API Key** : `sk-or-v1-...` (ta clé OpenRouter)
   - **Model** : `qwen/qwen-2.5-vl-72b-instruct`
   - **Temperature** : `0.1`
   - **Max Tokens** : `8192`

### 4️⃣ Ajouter le Prompt Système VPO

1. Dans **Chat Settings**, section **"System Prompt"**
2. Coller le prompt VPO :

```
Tu es un Expert Technique Senior & Auditeur VPO (AB InBev).
Tu es l'autorité mondiale sur les machines KeelClip (Graphic Packaging) 
et la méthodologie de résolution de problèmes (RCA - Root Cause Analysis).

CONTEXTE :
Michael est opérateur sur ligne d'emballage. Une panne survient. 
Il doit remplir un rapport d'incident (EWO/5 Why) qui sera audité selon les standards VPO.

RÈGLES D'OR (NON-NÉGOCIABLES) :
1. SÉCURITÉ D'ABORD : Si risque LOTO ou sécurité machine, mentionne-le EN PREMIER avec ⚠️
2. VOCABULAIRE TECHNIQUE : Utilise TOUJOURS les termes exacts :
   - Composants : Discharge Selector, Star Wheel, Lug Chain, Hot Melt Glue Gun, 
     Infeed Conveyor, Outfeed Conveyor, Clip Magazine, Applicator Head, Encoder, Proximity Sensor
   - Systèmes : PLC, HMI, Centerline, VFD, Servo Motor
   - Paramètres : Timing, Speed Ratio, Temperature Setpoint, Pressure Setting
3. JAMAIS D'ERREUR HUMAINE : INTERDICTION ABSOLUE de conclure par "Faute de l'opérateur". 
   Tu dois TOUJOURS chercher la faille dans le STANDARD, la MÉTHODE ou le MATÉRIEL.
4. LOGIQUE IMPLACABLE : Chaque "Pourquoi" DOIT être la cause directe du précédent. ZÉRO saut logique.
5. FORMAT VPO : Ta réponse doit être prête à copier-coller dans SAP/DMS.

FORMAT DE SORTIE OBLIGATOIRE :

## 1. 📋 DÉFINITION DU PROBLÈME (QQOQCCP)
| Élément | Description |
|---------|-------------|
| **Quoi** | (Description technique du défaut) |
| **Où** | (Composant précis de la machine) |
| **Quand** | (Moment du cycle ou condition déclenchante) |
| **Impact** | 🔴 Qualité / 🟡 Sécurité / ⚫ Arrêt Ligne |

## 2. 🔍 ANALYSE DES 5 POURQUOI (Chaîne Causale)
| # | Pourquoi | Cause |
|---|----------|-------|
| **P1** | Cause directe visible | ... |
| **P2** | Cause technique | ... |
| **P3** | Dérive paramètre/usure | ... |
| **P4** | Absence détection/maintenance | ... |
| **P5** | **CAUSE RACINE** | (Faille systémique : Standard manquant, CIL incomplet, OPL absente, Formation insuffisante, Centerline non défini) |

## 3. 🛠️ PLAN D'ACTION
| Type | Action | Responsable | Délai |
|------|--------|-------------|-------|
| **Corrective (MAINTENANT)** | Ce qu'il faut faire pour redémarrer | Opérateur | Immédiat |
| **Préventive (SYSTÉMIQUE)** | Modification CIL/Centerline/OPL | Maintenance/Ingénierie | À planifier |
```

3. Cliquer sur **"Save"**

### 5️⃣ Configurer les Variables d'Environnement

Dans ton fichier `.env` :

```bash
# AnythingLLM
ANYTHING_LLM_URL=http://localhost:3001/api/v1
ANYTHING_LLM_KEY=your_anythingllm_api_key

# OpenRouter (pour Qwen2.5-VL-72B)
OPENROUTER_API_KEY=sk-or-v1-your-key-here
```

### 6️⃣ Vérifier la Configuration

```bash
cd server
node check_vpo_workspace.js
```

Tu devrais voir :
```
✅ Found 10 workspace(s):
🎯 9. Expert Senior en Excellence Opérationnelle...
   Slug: expert-senior-en-excellence-operationnelle-standard-vpowcm-et-specialiste-technique-des-machines-keelclip
   ✅ THIS IS THE VPO WORKSPACE
```

### 7️⃣ Tester le Système

```bash
node test_incident_analysis.js
```

Résultat attendu :
```
✅ Score: 100/100
✅ Valid: ✅
✅ Recommendation: Excellent - Prêt pour audit
```

---

## 🎯 Utilisation

### Via Chat
```
"Panne au Star Wheel, génère le rapport 5-Why"
+ [Image de l'incident]
```

### Via API
```bash
curl -X POST http://localhost:3000/incident/complete \
  -H "Content-Type: application/json" \
  -d '{
    "media": "data:image/jpeg;base64,...",
    "description": "Bourrage Star Wheel shift de nuit"
  }'
```

---

## 💰 Coûts

**Qwen2.5-VL-72B via OpenRouter :**
- Input : $0.40 / 1M tokens
- Output : $0.40 / 1M tokens

**Estimation pour 100 rapports/mois :**
- ~350K tokens total
- **Coût : ~$0.14/mois** ✅

---

## 🔒 Sécurité

- ✅ Open source (Qwen2.5 = Alibaba Cloud)
- ✅ Données ne sont pas utilisées pour entraînement
- ✅ Conforme GDPR
- ⚠️ Données transitent par OpenRouter (comme tout service cloud)

**Pour AB InBev :** Vérifie avec ton IT si l'usage d'API cloud est autorisé.

---

## 🆘 Dépannage

### "Workspace not found"
→ Vérifie que le slug est exact : `expert-senior-en-excellence-operationnelle-standard-vpowcm-et-specialiste-technique-des-machines-keelclip`

### "OpenRouter API error"
→ Vérifie que tu as des crédits sur ton compte OpenRouter
→ Vérifie que la clé API est correcte

### "Model not supported"
→ Vérifie que le modèle est bien : `qwen/qwen-2.5-vl-72b-instruct`

---

## ✅ Checklist Finale

- [ ] Workspace VPO créé dans AnythingLLM
- [ ] Compte OpenRouter créé avec crédits ($5+)
- [ ] Modèle configuré : `qwen/qwen-2.5-vl-72b-instruct`
- [ ] Prompt système VPO ajouté
- [ ] Variables `.env` configurées
- [ ] Test réussi : `node test_incident_analysis.js`

**C'est prêt ! 🎉**
