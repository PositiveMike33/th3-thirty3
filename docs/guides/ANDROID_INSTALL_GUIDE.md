# Installation PWA Android - Guide Complet

## 📱 Installer Th3 Thirty3 sur Android

### Méthode 1: Via Chrome Android (Recommandé)

1. **Ouvrir l'application dans Chrome:**
   - Sur ton téléphone Android, ouvre **Chrome**
   - Va sur: `https://ton-domaine.com` (ou `http://IP-PC:5173` pour test local)

2. **Installer l'application:**
   - Chrome affichera une bannière "Installer l'application"
   - OU clique sur **Menu (⋮)** → **Installer l'application**
   - OU clique sur **Ajouter à l'écran d'accueil**

3. **Icône sur l'écran d'accueil:**
   - L'icône **Th3 Thirty3** apparaît sur ton écran d'accueil
   - Clique dessus pour lancer l'app en plein écran

### Méthode 2: Via Brave Android

1. Ouvre Brave sur Android
2. Va sur l'URL de l'application
3. Menu **⋮** → **Installer Th3 Thirty3**
4. L'app s'installe comme une vraie application

### Méthode 3: Partage WiFi Local (Test)

**Pour tester avant déploiement cloud:**

1. **Sur ton PC:**
   ```bash
   # Dans start.bat, le serveur écoute déjà sur 0.0.0.0:5173
   npm run dev -- --host
   ```

2. **Trouver l'IP de ton PC:**
   ```bash
   ipconfig
   # Cherche "Adresse IPv4" → ex: 192.168.1.100
   ```

3. **Sur Android (même WiFi):**
   - Ouvre Chrome
   - Va sur `http://192.168.1.100:5173`
   - Installe comme méthode 1

---

## 🎨 Icônes Générées

L'application utilise des icônes PWA aux tailles:
- 72x72, 96x96, 128x128, 144x144, 152x152
- **192x192** (icône standard Android)
- **512x512** (icône haute résolution)

### Générer tes Icônes

**Option 1: Utiliser un générateur en ligne**
1. Va sur https://realfavicongenerator.net/
2. Upload ton logo Th3 Thirty3
3. Télécharge le pack d'icônes PWA
4. Place dans `interface/public/icons/`

**Option 2: Créer avec DALL-E/Midjourney**
- Demande une icône cyberpunk avec "33"
- Format carré, fond transparent
- Export en 512x512 PNG

**Option 3: Utiliser le logo existant**
Si tu as déjà un logo, je peux le redimensionner automatiquement.

---

## ✨ Fonctionnalités PWA Activées

### Sur Android
- ✅ **Installation sur écran d'accueil**
- ✅ **Plein écran** (pas de barre Chrome)
- ✅ **Icône personnalisée**
- ✅ **Splash screen** au démarrage
- ✅ **Mode offline** (cache)
- ✅ **Shortcuts** (Chat, OSINT, Training)

### Shortcuts Android

Long press sur l'icône → Accès rapide:
- 💬 **Chat IA**
- 🔍 **OSINT**
- 🎓 **Cyber Training**

---

## 🚀 Déploiement Cloud (Production)

### Hébergements Gratuits PWA-Friendly

**Option 1: Vercel (Recommandé)**
```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
cd interface
vercel --prod
```
→ URL: `https://th3-thirty3.vercel.app`

**Option 2: Netlify**
```bash
npm i -g netlify-cli
netlify deploy --prod --dir=dist
```

**Option 3: GitHub Pages**
- Push vers repo GitHub
- Settings → Pages → Deploy from main

**Option 4: Railway.app**
- Connect GitHub repo
- Deploy automatique
- URL custom gratuite

---

## 🔧 Configuration Vite pour PWA

Le fichier `manifest.json` et `sw.js` sont déjà configurés.

**Pour activer dans l'app:**

Éditer `interface/index.html`:
```html
<head>
  <!-- PWA Manifest -->
  <link rel="manifest" href="/manifest.json">
  
  <!-- Theme color -->
  <meta name="theme-color" content="#6366f1">
  
  <!-- Apple Touch Icon -->
  <link rel="apple-touch-icon" href="/icons/icon-192x192.png">
</head>

<script>
  // Register Service Worker
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js')
      .then(reg => console.log('[PWA] Service Worker registered'))
      .catch(err => console.error('[PWA] SW registration failed:', err));
  }
</script>
```

---

## 📊 Test PWA

### Vérifier que tout fonctionne

**1. Chrome DevTools:**
- F12 → **Application** tab
- Manifest → Voir les icônes
- Service Workers → Voir si actif
- **Lighthouse** → Score PWA

**2. Test Installation:**
- Chrome → Menu → "Peut être installé en tant qu'application"
- Si oui = ✅ PWA configurée correctement

**3. Test Offline:**
- Install l'app
- Active mode avion
- Lance l'app → Devrait fonctionner en cache

---

## 🎯 Prochaines Étapes

1. **Générer icônes** (512x512 PNG de ton logo)
2. **Placer dans** `interface/public/icons/`
3. **Tester localement** via WiFi
4. **Déployer** sur Vercel/Netlify
5. **Installer** sur Android depuis l'URL cloud

**L'app sera installable comme une vraie app Android !** 📱✨
