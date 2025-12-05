# 🎯 Configuration Workspace Marketing - AnythingLLM

## Problème Actuel
Le workspace "marketing" (Fabric) est configuré avec `granite3.1-moe:1b` qui a été supprimé. Il faut le reconfigurer avec un modèle fonctionnel.

---

## ✅ Solution : Configurer le Workspace Marketing

### Étape 1 : Ouvrir AnythingLLM

1. Aller sur `http://localhost:3001`
2. Cliquer sur workspace **"Fabric"** (slug: `marketing`)
3. Cliquer sur **⚙️ Settings**

### Étape 2 : Configurer le Modèle

#### Option A : Llama 3.2 Vision 11B (Recommandé - Multimodal)

```
Provider: Ollama
Base URL: http://localhost:11434
Model: llama3.2-vision:11b
Temperature: 0.7  # Plus créatif pour marketing
Max Tokens: 4096
```

**Avantages** :
- ✅ Peut gérer texte + images (logos, mockups)
- ✅ Excellent en génération créative
- ✅ 100% local et gratuit

#### Option B : Qwen2.5-VL-72B (Cloud - Meilleure qualité)

```
Provider: Custom OpenAI Compatible
Base URL: https://openrouter.ai/api/v1
API Key: sk-or-v1-[ta clé]
Model: qwen/qwen-2.5-vl-72b-instruct
Temperature: 0.8
Max Tokens: 4096
```

**Avantages** :
- ✅ Meilleure qualité de texte
- ✅ Plus créatif et varié
- ⚠️ Coût : ~$0.40/1M tokens

#### Option C : LLM Texte Seulement (Plus rapide)

Si pas besoin de vision pour le marketing:

```
Provider: Ollama
Model: qwen2.5:72b  # ou llama3.1:70b
Temperature: 0.8
```

### Étape 3 : Ajouter Prompt Système Marketing

Dans **System Prompt** du workspace :

```
Tu es un expert en marketing B2B et copywriting pour software manufacturier.

STYLE:
- Clear, benefit-driven, concis
- Tone: Professionnel mais accessible
- Évite le jargon marketing vide ("synergize", "disrupt")
- Focus sur ROI, métriques, résultats concrets

PRINCIPES:
1. WIIFM (What's In It For Me) - toujours du POV client
2. Features → Benefits (pas juste lister features)
3. Preuve sociale (stats, testimonials)
4. Call-to-action clair
5. Scannable (bullets, short paragraphs)

PRODUIT: KeelClip VPO Analyzer
- AI génère rapports 5-Why pour incidents machines
- Économise 45 min par rapport (→ 2 min)
- 100% VPO compliance
- Target : AB InBev, manufacturing plants
- Pricing : $299/mois, $4999 perpetual

AUDIENCES:
- Manufacturing Engineers (pain: temps perdu)
- Quality Managers (pain: audits échoués)
- Plant Directors (angle: ROI, savings)
- Investors (angle: market size, growth)
```

### Étape 4 : Sauvegarder

Cliquer sur **Save Settings**

---

## 🧪 Test de Configuration

Retourne dans le terminal et teste :

```bash
# Test 1 : Pitch investor
node test_marketing.js pitch investor

# Test 2 : Post LinkedIn
node test_marketing.js linkedin product_launch

# Test 3 : Email cold outreach
node test_marketing.js email quality_manager

# Test 4 : Landing page héro
node test_marketing.js landing hero
```

---

## 📊 Utilisation du Service Marketing

### Générer du Contenu en Masse

```javascript
const MarketingService = require('./marketing_service');
const marketing = new MarketingService();

// 1. Elevator pitches pour différentes audiences
const pitchInvestor = await marketing.generateElevatorPitch('investor');
const pitchCustomer = await marketing.generateElevatorPitch('quality_manager');

// 2. Série de posts LinkedIn
const post1 = await marketing.generateLinkedInPost('product_launch');
const post2 = await marketing.generateLinkedInPost('case_study');
const post3 = await marketing.generateLinkedInPost('problem_agitate');

// 3. Emails pour outreach
const emailEngineer = await marketing.generateColdEmail('manufacturing_engineer');
const emailManager = await marketing.generateColdEmail('quality_manager');
const emailDirector = await marketing.generateColdEmail('plant_director');

// 4. Landing page complète
const hero = await marketing.generateLandingPageCopy('hero');
const features = await marketing.generateLandingPageCopy('features');
const pricing = await marketing.generateLandingPageCopy('pricing');
const testimonials = await marketing.generateLandingPageCopy('testimonials');

// 5. Autres contenus
const videoScript = await marketing.generateVideoScript('3min');
const faq = await marketing.generateFAQ('product');
const pressRelease = await marketing.generatePressRelease('product_launch');
```

---

## 📁 Sauvegarder le Contenu Généré

Créer un dossier pour stocker tout le contenu :

```bash
mkdir marketing-content
mkdir marketing-content/linkedin
mkdir marketing-content/emails
mkdir marketing-content/landing-page
mkdir marketing-content/misc
```

Puis utiliser le script pour générer et sauvegarder :

```bash
# Générer et sauvegarder
node test_marketing.js pitch investor > marketing-content/misc/elevator-pitch-investor.txt
node test_marketing.js linkedin product_launch > marketing-content/linkedin/post-product-launch.txt
node test_marketing.js email quality_manager > marketing-content/emails/cold-email-quality-manager.txt
node test_marketing.js landing hero > marketing-content/landing-page/hero-section.txt
```

---

## 🎯 Prochaines Étapes

1. ✅ Configurer workspace marketing avec Llama 3.2 Vision ou Qwen2.5-VL
2. ✅ Tester génération de contenu
3. ✅ Générer contenu pour pitch deck (présentation PowerPoint)
4. ✅ Générer contenu pour site web (landing page)
5. ✅ Générer série LinkedIn (12 posts pour 3 mois)
6. ✅ Générer emails outreach (templates pour different personas)

---

## 💡 Tips d'Utilisation

### Pour Meilleure Qualité
- **Température 0.7-0.9** = Plus créatif (marketing)
- **Température 0.1-0.3** = Plus factuel (technique)
- **Regénérer 2-3x** et choisir le meilleur
- **Éditer manuellement** après génération (outil d'aide, pas remplacement)

### Pour Cohérence Brand
- Créer un **brand voice guide** (document de référence)
- L'ajouter comme document dans workspace marketing
- AnythingLLM va l'utiliser comme contexte pour tous les contenus

---

**Une fois configuré, le workspace marketing génère tout ton contenu en quelques secondes !** 🚀
