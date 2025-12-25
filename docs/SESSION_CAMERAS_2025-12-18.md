# Session du 18 Décembre 2025 - Intégration Caméras EasyLife

## 📋 Travail Effectué

### 1. Amélioration de l'Analyse Shodan
- ✅ Ajouté la classification automatique des systèmes (ICS/SCADA, IoT, Database, Web Server)
- ✅ Détection des protocoles industriels (Modbus, BACnet, S7comm, DNP3, EtherNet/IP)
- ✅ Score de risque 0-100 avec niveaux CRITICAL/HIGH/MEDIUM/LOW
- ✅ Références aux cas réels (Oldsmar, Stuxnet, Ukraine Power Grid)
- ✅ Prompts en français pour une analyse plus précise
- ✅ Nouvel endpoint `/api/shodan/analyze/:ip` avec intelligence enrichie

### 2. Intégration Widget IPLocation
- ✅ Composant `IPLocationWidget.jsx` créé
- ✅ API Key configurée: `wosTmWLXYjYuE//UCr/N4nUAp0NrfIFluBFBdzHeG6M=`
- ✅ Affichage: Localisation, ISP, Proxy, Plateforme, Navigateur
- ✅ Intégré dans le Dashboard (onglet "Network & Surveillance")

### 3. Service Caméras EasyLife
- ✅ `camera_service.js` - Contrôle RTSP/ONVIF standard
- ✅ `camera_routes.js` - Routes API REST
- ✅ `tuya_camera_service.js` - Protocole Tuya local
- ✅ `tuya_routes.js` - API Tuya
- ✅ `tuya_cloud_service.js` - Fallback API Cloud
- ✅ `tuya_scanner.py` - Découverte réseau Python

### 4. Dashboard Network Panel
- ✅ Statut TOR (Running, Connected, Exit IP)
- ✅ Statut VPN (Connected, Current IP, Server)
- ✅ Panneau Caméras avec liste et contrôles

### 5. Configuration Tuya
- ✅ Credentials API récupérés et configurés dans `.env`
  - Access ID: `d3kkrderuvnuh99mqxkc`
  - Access Secret: `0c572dcb06dd40dca0bad623469f7d13`
  - Région: `us` (Western America)

---

## 📹 Caméras Enregistrées

| # | Nom | Device ID | MAC | IP | Status |
|---|-----|-----------|-----|-----|--------|
| 1 | EasyLife Camera 1 | `131400200201030` | `98:A8:29:80:0F:68` | `192.168.1.165` | ⏳ En attente Local Key |
| 2 | EasyLife Camera 2 | `131400200165748` | `20:98:ED:92:07:B9` | À découvrir | ⏳ En attente |

---

## ⏳ À Faire (Prochaine Session)

### Obtenir les Local Keys
1. **Ouvre** https://platform.tuya.com et connecte-toi
2. **Va dans** Cloud → Project Management → EasyLifeCamera
3. **Dans l'onglet "Devices"**, clique sur "Link App Account"
4. **Scanne le QR code** avec l'app Ease Life (Moi → Scan)
5. **Autorise** la connexion
6. **Tes caméras** apparaîtront dans "All Devices"
7. **Clique** sur une caméra pour voir son Local Key
8. **Fournis-moi** les Local Keys et je configurerai le contrôle complet

### Une fois les Local Keys obtenus
- Contrôle PTZ (Pan-Tilt-Zoom)
- Capture de snapshots
- Vision nocturne
- Détection de mouvement
- Streaming vidéo

---

## 🔗 APIs Disponibles

### Shodan Enhanced
```
GET /api/shodan/analyze/:ip          - Analyse intelligence enrichie
GET /api/shodan/analyze/:ip?withAI=true  - Avec commentaire AI
POST /api/shodan/analyze/batch       - Analyse multiple IPs
```

### Caméras
```
GET /api/cameras/status              - Statut service caméras
POST /api/cameras/quick-add          - Ajouter une caméra
POST /api/cameras/:id/snapshot       - Capturer snapshot
POST /api/cameras/:id/ptz            - Contrôle PTZ
```

### Tuya
```
GET /api/tuya/status                 - Statut service Tuya
POST /api/tuya/devices               - Ajouter un device Tuya
POST /api/tuya/devices/:id/ptz       - Contrôle PTZ
POST /api/tuya/devices/:id/night-vision  - Vision nocturne
GET /api/tuya/help/local-key         - Instructions Local Key
```

---

## 📁 Fichiers Créés/Modifiés

### Nouveaux Fichiers

- `server/camera_service.js`
- `server/camera_routes.js`
- `server/tuya_camera_service.js`
- `server/tuya_routes.js`
- `server/tuya_cloud_service.js`
- `server/config/easylife_cameras.json`
- `interface/src/components/IPLocationWidget.jsx`
- `tuya_scanner.py`

### Fichiers Modifiés
- `server/shodan_service.js` - Analyse enrichie
- `server/shodan_routes.js` - Nouveaux endpoints
- `server/index.js` - Routes caméras et Tuya
- `server/.env` - Credentials Tuya
- `interface/src/Dashboard.jsx` - Onglet Network & Surveillance

---

## 📅 Session du 20 Décembre 2025 - Scan Réseau & MCP Training

### 🔍 Scan Réseau Effectué

**Commande:** `nmap -sV -O -p 554,80,8080,8000 192.168.1.0/24`

**Résultats du scan (PowerShell alternative):**

| IP | MAC | Ports Ouverts | Type |
|----|-----|---------------|------|
| 192.168.1.1 | E8:2C:6D:D5:DE:81 | 80, 8080 | Router/Gateway |
| 192.168.1.108 | N/A | 80, 8080 | **Caméra potentielle** |
| 192.168.1.165 | A0:D0:5B:B6:8E:E2 | 8080 | **EasyLife Camera 1** |

### ✅ Fichiers MCP Training Créés

#### JSON Training Datasets

- `data/training/camera_discovery_training.json` - 8 scénarios de base
- `data/training/camera_discovery_advanced.json` - 8 scénarios avancés

#### Scripts Python MCP
- `scripts/mcp_camera_scanner.py` - Scanner complet avec intégration MCP
- `scripts/mcp_camera_server.py` - Serveur MCP pour LLM
- `scripts/quick_camera_finder.py` - Script rapide standalone

### 📚 Scénarios d'Entraînement Couverts

| ID | Scénario | Difficulté |
|----|----------|------------|
| cam_001 | Découverte réseau basique | Beginner |
| cam_002 | Découverte flux RTSP | Intermediate |
| cam_003 | Identification fabricant | Intermediate |
| cam_004 | Découverte ONVIF | Advanced |
| cam_005 | Test credentials par défaut | Advanced |
| cam_006 | Analyse de trafic | Expert |
| cam_007 | Évaluation vulnérabilités | Expert |
| cam_008 | Audit complet réseau | Expert |
| adv_001 | Détection caméras cachées | Expert |
| adv_002 | Identification caméras cloud | Advanced |
| adv_003 | Découverte NVR/DVR | Intermediate |
| adv_004 | Extraction firmware | Expert |
| adv_005 | Contrôle PTZ | Intermediate |
| adv_006 | Événements détection mouvement | Advanced |
| adv_007 | Enregistrement multi-streams | Intermediate |
| adv_008 | Bypass segmentation VLAN | Expert |

### 🛠️ Outils MCP Disponibles

```python
scanner = MCPCameraScanner()

# Scan réseau
scanner.mcp_network_scan("192.168.1.0/24")

# Scan ARP
scanner.mcp_arp_scan()

# Scan RTSP
scanner.mcp_rtsp_scan("192.168.1.108")

# Fingerprint HTTP
scanner.mcp_http_fingerprint("192.168.1.108")

# Découverte ONVIF
scanner.mcp_onvif_discover()

# Audit complet
scanner.mcp_full_audit("192.168.1.0/24")
```

### ⏭️ Prochaine Étape

1. Installer nmap en mode Administrateur: `choco install nmap -y`
2. Obtenir les Local Keys Tuya pour 192.168.1.165
3. Tester les endpoints RTSP sur 192.168.1.108

---

## 📅 Session 2025-12-20 - Intégration OSINT & Layout Fix

### 🔧 Corrections Layout Project Dashboard

**Problèmes résolus:**
- Map affichée comme "bande en haut" - corrigé avec hauteur fixe (280px)
- CSS global `iframe { height: auto; }` écrasait la hauteur - exclu les iframes de map
- Container parent avec `overflow-y-auto` causait problèmes de calcul hauteur - remplacé par `overflow-hidden`
- Utilisation de `flex-1` et `min-h-0` pour layouts flex corrects

**Fichiers modifiés:**
- `interface/src/index.css` - Exception iframe pour maps
- `interface/src/App.jsx` - Fix overflow container principal  
- `interface/src/ProjectDashboard.jsx` - Refonte layout complet

### 🌐 APIs OSINT Intégrées

| Service | Route | Clé API |
|---------|-------|---------|
| IP2Location | `/api/ip2location/*` | ✅ Configurée |
| IP2WHOIS | `/api/whois/*` | ✅ Configurée |
| iplocation.net | `/api/iplocation/*` | Gratuite |
| IPGeolocation Astronomy | `/api/astronomy/*` | À configurer |

### 🧩 Nouveaux Composants

**IPLookupPanel** (`interface/src/components/IPLookupPanel.jsx`)
- Lookup IP avec géolocalisation complète
- WHOIS domain avec registrar, dates, nameservers
- Mode compact pour sidebar
- Callback `onLocationFound` pour intégration map

**OSINTAgentChat** (`interface/src/components/OSINTAgentChat.jsx`)
- Chat dédié investigations OSINT
- Connexion AnythingLLM agents
- Auto-détection IP/domaines dans messages
- Quick actions (Mon IP, WHOIS, Géoloc, Username)
- Résultats outils affichés dans chat

### 📊 Structure Finale Project Dashboard

```
┌──────────────────────────────────────────────────────────────┐
│ HEADER - DASHBOARD / AI ASSISTANT Button                      │
├──────────────────────────────────┬───────────────────────────┤
│                                  │ OSINT Agent Chat (flex-1) │
│ Google Maps (280px fixe)         │ ─────────────────────────│
│                                  │ IP Lookup Panel           │
├──────────────────────────────────┤                           │
│                                  │──────────────────────────│
│ Camera Panel (flex-1)            │ Calendar │ Email (mini)  │
│                                  │                           │
└──────────────────────────────────┴───────────────────────────┘
      75% width                          25% width
```

### ✅ Tests Effectués - CONFIRMÉS VISUELLEMENT
- [x] Build production réussi
- [x] Lint errors corrigés
- [x] Layout responsive vérifié
- [x] **Test visuel navigateur - CONFIRMÉ**
  - Map correctement dimensionnée à 280px (plus de bande fine!)
  - Camera panel visible sous la map
  - OSINT Agent Chat intégré dans sidebar
- [x] **IP Lookup testé - FONCTIONNEL**
  - Test avec 8.8.8.8 → Mountain View, California, US
- [x] **OSINT Chat testé - FONCTIONNEL**
  - Quick actions fonctionnelles
  - Messages envoyés correctement

### 🎯 Identifiants de Test
- **Email**: `admin@nexus33.io`
- **Password**: `admin123`

### 📹 Enregistrements
- Layout Dashboard: `projects_layout_clear.png`
- IP Lookup Results: `ip_lookup_results.png`
- OSINT Chat Response: `osint_chat_response.png`
- Video Complète: `full_osint_test.webp`

---

*Session terminée le 20/12/2025 20:20 - ✅ Integration OSINT 100% Complete*

---

## 📅 Session 2025-12-22 - Intégration Scripts Découverte Passive Caméras

### 🔧 Scripts Intégrés

#### 1. Script Python - `cam_discover.py`
**Chemin:** `scripts/cam_discover.py`

```bash
# Usage
python scripts/cam_discover.py 192.168.1.0/24
```

**Fonctionnalités:**
- Scan réseau via nmap ou ping fallback
- Scan ports caméras (80, 554, 8080, 8081, 6668, 37777, 34567)
- Détection ONVIF (python-onvif-zeep)
- Fingerprinting HTTP manufacturier
- Test RTSP endpoints
- Export JSON automatique

#### 2. Script Bash WSL - `find_cams.sh`
**Chemin:** `scripts/find_cams.sh`

```bash
# Usage via WSL
wsl bash /mnt/c/Users/th3th/.Th3Thirty3/thethirty3/scripts/find_cams.sh 192.168.1.0/24
```

**Fonctionnalités:**
- Compatible WSL Ubuntu
- Scan nmap complet
- Identification par headers HTTP
- Génération rapport texte
- Commandes d'intégration curl

#### 3. Service Node.js - `camera_discovery_service.js`
**Chemin:** `server/camera_discovery_service.js`

**Fonctionnalités:**
- Scan PowerShell natif Windows
- Port scanning multi-thread
- Fingerprinting HTTP intégré
- Test RTSP automatique
- Wrappers Python/Bash
- Événements temps réel

### 📡 API Endpoints

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/camera-discovery/status` | GET | Statut service + caméras découvertes |
| `/api/camera-discovery/scan` | POST | Scan réseau complet |
| `/api/camera-discovery/quick-scan` | POST | Scan IP unique `{ ip: "..." }` |
| `/api/camera-discovery/results` | GET | Derniers résultats de scan |
| `/api/camera-discovery/cameras` | GET | Liste caméras découvertes |
| `/api/camera-discovery/network-range` | GET | Range réseau auto-détecté |
| `/api/camera-discovery/python` | POST | Exécuter script Python |
| `/api/camera-discovery/bash` | POST | Exécuter script Bash via WSL |
| `/api/camera-discovery/help` | GET | Documentation API |

### 🖥️ Composant Frontend

**Chemin:** `interface/src/components/CameraDiscoveryPanel.jsx`

**Fonctionnalités:**
- Interface scan réseau
- Quick scan IP unique
- Affichage résultats en temps réel
- Mode compact pour sidebar
- Liens directs interfaces caméras
- Indicateurs Tuya/RTSP/ONVIF

### 📁 Fichiers Créés

| Fichier | Description |
|---------|-------------|
| `scripts/cam_discover.py` | Script Python découverte ONVIF |
| `scripts/find_cams.sh` | Script Bash WSL |
| `server/camera_discovery_service.js` | Service Node.js wrapper |
| `server/camera_discovery_routes.js` | Routes API REST |
| `interface/src/components/CameraDiscoveryPanel.jsx` | UI React |
| `server/data/camera_scans/` | Dossier résultats scans |

### 🔧 Prochaines Étapes

1. **Tester les scripts:**
   ```bash
   # Python (depuis racine projet)
   python scripts/cam_discover.py 192.168.1.0/24
   
   # API
   curl http://localhost:3000/api/camera-discovery/scan -X POST -H "Content-Type: application/json"
   ```

2. **Intégrer dans ProjectDashboard** le composant `CameraDiscoveryPanel`

3. **Obtenir Local Keys Tuya** pour contrôle complet caméras

---

*Session 22/12/2025 - ✅ Scripts Découverte Passive Caméras Intégrés*

---

## 📅 Session 2025-12-22 (Suite) - Diagnostic Caméras EasyLife

### 📹 Caméras Identifiées

| Caméra | Device ID | IP | MAC | Status |
|--------|-----------|-----|-----|--------|
| EasyLife #1 | `131400200201030` | `192.168.1.165` | `98:A8:29:80:0F:68` | ✅ Connectée WiFi |
| EasyLife #2 | `131400200165748` | À découvrir | À découvrir | En attente |

### 🔍 Résultats Diagnostic

**Connexion réseau:**
- ✅ Caméra visible dans table ARP (MAC → IP)
- ❌ Tous ports locaux bloqués (80, 554, 6668, etc.)
- ❌ Ne répond pas aux pings
- 📡 Mode **Cloud-Only** (communication P2P/STUN)

**API Tuya Cloud:**
- ✅ Token obtenu avec succès
- ❌ "Permission Deny" - compte utilisateur non lié
- ⏳ En attente de liaison via QR code Tuya Smart

### 🔐 Credentials Tuya IoT

```
Access ID: d3kkrderuvnuh99mqxkc
Access Secret: 0c572dcb06dd40dca0bad623469f7d13
Region: us (Western America Data Center)
Project: EasyLifeCamera
```

### ⏳ Blocage Actuel

**Problème:** L'app EasyLife n'a pas de scanner QR pour lier le compte au projet Tuya IoT.

**Solution requise:** 
1. Télécharger app "Tuya Smart" ou "Smart Life"
2. Se connecter avec le même compte EasyLife
3. Scanner le QR code depuis la plateforme Tuya

**Status:** Problème de connexion réseau sur les apps Tuya Smart/Smart Life (investigation en cours)

### 📁 Fichiers Intégrés Cette Session

| Fichier | Lignes | Description |
|---------|--------|-------------|
| `scripts/cam_discover.py` | ~480 | Script Python ONVIF + Port Scan |
| `scripts/find_cams.sh` | ~220 | Script Bash WSL |
| `server/camera_discovery_service.js` | ~540 | Service Node.js |
| `server/camera_discovery_routes.js` | ~170 | Routes API REST |
| `interface/src/components/CameraDiscoveryPanel.jsx` | ~340 | Composant React UI |

### 🔧 Prochaines Étapes (Demain)

**Plan: Méthode Émulateur Android pour extraire Local Keys**

1. **Télécharger BlueStacks 5** → https://www.bluestacks.com/download.html
2. **Télécharger Smart Life APK v3.6.1** → https://apkpure.com/smart-life-smart-living/com.tuya.smartlife/versions
3. **Installer et configurer** BlueStacks
4. **Installer Smart Life 3.6.1** dans l'émulateur
5. **Se connecter avec Google** (mikegauthierguillet@gmail.com)
6. **Extraire fichier XML** contenant les Local Keys
7. **Configurer caméras** dans Th3 Thirty3

**Fichiers à avoir prêts:**
- BlueStacks installer (~500 MB)
- Smart Life 3.6.1 APK (~50 MB)

---

*Session terminée 22/12/2025 02:52 - À demain pour finir l'intégration! 🎯*

---

## 📅 Session 2025-12-24 - Tests Fonctionnalités & Guide Local Keys

### 🔍 Tests Effectués

**Script Python Discovery:**
```bash
python scripts\cam_discover.py 192.168.1.0/24
```

**Résultats:**
- ✅ 3 devices trouvés en 10.8s
- `192.168.1.1` → Ports [80, 8080] (Router)
- `192.168.1.108` → Ports [80, 8080] (Caméra potentielle - HTTP 404)
- `192.168.1.166` → Ports [8080] (Web server actif)

**Vérification ARP:**
```bash
arp -a | findstr "192.168.1.16"
```
- `192.168.1.165` → MAC `98-a8-29-80-0f-68` ✅
- `192.168.1.166` → MAC `a0-d0-5b-b6-8e-e2` ✅

**Conclusion:** Camera #1 possède probablement 2 interfaces réseau (WiFi + Ethernet)

### 🛠️ Corrections Apportées

**Problème:** Duplication `cameraDiscoveryRoutes` dans `server/index.js`  
**Solution:** Supprimé déclaration dupliquée, conservé celle avec service init

**Fichiers modifiés:**
- `server/index.js` - Fix duplication routes

### ✅ APIs Testées

| Endpoint | Méthode | Status |
|----------|---------|--------|
| `/api/camera-discovery/status` | GET | ✅ Fonctionnel |
| `/api/tuya/status` | GET | ✅ Fonctionnel |

**Statut Serveur:**
```
🎉 TH3 THIRTY3 - FULLY OPERATIONAL
✅ Camera Discovery: Active
✅ Tuya Service: Active (2 devices, 0 online)
✅ Tor Network: Exit IP 5.255.118.151
```

### 📄 Documentation Créée

**Nouveau fichier:** `tuya_local_keys_guide.md`

**Contenu:**
- ✅ Méthode Recommandée: platform.tuya.com + QR Code (5-10 min)
  1. Se connecter à https://platform.tuya.com
  2. Cloud → Project Management → EasyLifeCamera
  3. Devices → Link App Account → Scanner QR avec Tuya Smart/Smart Life
  4. Récupérer Local Keys dans "All Devices"

- ✅ Méthode Alternative: Émulateur BlueStacks Android
  - Installation Smart Life APK v3.6.1
  - Extraction XML avec Local Keys
  
- ✅ Troubleshooting complet
- ✅ Configuration automatique post-récupération

### 📹 Mise à Jour Caméras

| # | Device ID | IP(s) | MAC(s) | Status |
|---|-----------|-------|--------|--------|
| 1 | `131400200201030` | `192.168.1.165`<br>`192.168.1.166` | `98-a8-29-80-0f-68`<br>`a0-d0-5b-b6-8e-e2` | ⏳ En attente Local Key |
| 2 | `131400200165748` | À découvrir | À découvrir | ⏳ En attente |

### 🎯 Prochaine Étape

**IMMÉDIAT:** Récupérer les Local Keys via https://platform.tuya.com

**Une fois obtenus, fournir:**
```
Camera 1 (131400200201030): [LOCAL_KEY]
Camera 2 (131400200165748): [LOCAL_KEY]
```

**Auto-configuration:**
- Mise à jour config Tuya
- Test connexion locale
- Validation contrôles PTZ
- Intégration Dashboard

### 🚨 Problèmes Identifiés

1. **Browser Automation:** Timeout/connection reset
   - Solution: Guide manuel fourni

2. **ONVIF Disabled:** `python-onvif-zeep` pas installé
   - Solution future: `pip install python-onvif-zeep`

3. **IP 192.168.1.108:** Caméra inconnue détectée
   - À investiguer: Type, credentials, protocoles

---

*Session terminée 24/12/2025 19:25 - APIs testées ✅ | Guide Local Keys créé ✅*
