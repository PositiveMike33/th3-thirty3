# 🛠️ Guide Pratique des Outils de Sécurité Réseau

## Table des Matières
1. [Nmap - Scanner de Ports](#nmap)
2. [Wireshark/TShark - Analyseur de Trafic](#wireshark)
3. [WireGuard - VPN Moderne](#wireguard)
4. [Advanced IP Scanner - Découverte Réseau](#advanced-ip-scanner)
5. [WinSCP - Transfert de Fichiers Sécurisé](#winscp)
6. [NetBird - VPN P2P d'Entreprise](#netbird)
7. [mRemoteNG - Gestionnaire de Connexions](#mremoteng)
8. [Portmaster - Pare-feu Applicatif](#portmaster)

---

## 🔍 Nmap - Scanner de Ports {#nmap}

### Description
Nmap (Network Mapper) est l'outil de référence pour la découverte réseau et l'audit de sécurité.

### Installation
```bash
# WSL Ubuntu
sudo apt install nmap

# Windows (via winget)
winget install Insecure.Nmap
```

### Commandes Essentielles

| Commande | Description |
|----------|-------------|
| `nmap -sn 192.168.1.0/24` | Découverte d'hôtes (ping sweep) |
| `nmap -F <cible>` | Scan rapide (top 100 ports) |
| `nmap -sS <cible>` | Scan SYN furtif |
| `nmap -sV <cible>` | Détection de version des services |
| `nmap -O <cible>` | Détection du système d'exploitation |
| `nmap -A <cible>` | Scan agressif (OS, version, scripts) |
| `nmap --script=vuln <cible>` | Scan de vulnérabilités |
| `nmap -p 554,8080,8000 <cible>` | Scan ports spécifiques (caméras IP) |

### API Intégrée

**Endpoint:** `POST /api/network/nmap/scan`

```json
{
  "target": "192.168.1.1",
  "scanType": "quick|ports|service|os|vuln|full|stealth|camera",
  "ports": "80,443,8080" // optionnel
}
```

**Types de scan:**
- `quick` - Scan rapide (top 100 ports)
- `service` - Détection de services
- `camera` - Ports caméras IP (554, 8080, 8000, etc.)
- `vuln` - Scan de vulnérabilités
- `full` - Scan complet (OS, services, scripts)

---

## 🦈 Wireshark/TShark - Analyseur de Trafic {#wireshark}

### Description
Wireshark capture et analyse le trafic réseau en temps réel. TShark est la version ligne de commande.

### Installation
```bash
# WSL Ubuntu
sudo apt install wireshark tshark

# Windows
winget install WiresharkFoundation.Wireshark
```

### Commandes TShark Essentielles

| Commande | Description |
|----------|-------------|
| `tshark -D` | Lister les interfaces |
| `tshark -i eth0` | Capture sur interface eth0 |
| `tshark -i eth0 -c 100` | Capturer 100 paquets |
| `tshark -i eth0 -f "port 80"` | Filtrer HTTP |
| `tshark -r capture.pcap` | Lire un fichier pcap |
| `tshark -i eth0 -w output.pcap` | Sauvegarder la capture |

### Filtres Wireshark Populaires

| Filtre | Description |
|--------|-------------|
| `http` | Tout le trafic HTTP |
| `ip.addr == 192.168.1.1` | Trafic d'une IP spécifique |
| `tcp.port == 443` | Trafic HTTPS |
| `dns` | Requêtes DNS |
| `tcp.flags.syn == 1` | Paquets SYN (début connexion) |

### API Intégrée

**Status:** `GET /api/network/tshark/status`

**Capture:** `POST /api/network/tshark/capture`
```json
{
  "interface": "eth0",
  "duration": 10,
  "filter": "port 80"
}
```

---

## 🔐 WireGuard - VPN Moderne {#wireguard}

### Description
VPN nouvelle génération utilisant le protocole cryptographique le plus rapide et sécurisé.

### Installation
```powershell
# Windows
winget install WireGuard.WireGuard

# Ubuntu
sudo apt install wireguard
```

### Configuration

1. **Générer les clés:**
```bash
wg genkey | tee privatekey | wg pubkey > publickey
```

2. **Créer le fichier de configuration `/etc/wireguard/wg0.conf`:**
```ini
[Interface]
PrivateKey = <votre_clé_privée>
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
PublicKey = <clé_publique_du_peer>
AllowedIPs = 10.0.0.2/32
Endpoint = peer.example.com:51820
```

3. **Démarrer le tunnel:**
```bash
wg-quick up wg0
```

### Commandes Essentielles

| Commande | Description |
|----------|-------------|
| `wg-quick up wg0` | Démarrer le tunnel |
| `wg-quick down wg0` | Arrêter le tunnel |
| `wg show` | Afficher le statut |
| `wg showconf wg0` | Afficher la configuration |

---

## 📡 Advanced IP Scanner - Découverte Réseau {#advanced-ip-scanner}

### Description
Scanner réseau gratuit pour Windows - découvre tous les appareils sur le réseau local.

### Installation
```powershell
winget install Famatech.AdvancedIPScanner
```

### Fonctionnalités

- **Scan rapide** du réseau local
- **Détection automatique** de l'adresse MAC et fabricant
- **Accès distant** aux partages réseau
- **Wake-on-LAN** pour réveiller les PC
- **Intégration Radmin** pour contrôle à distance

### Utilisation

1. Lancer Advanced IP Scanner
2. Entrer la plage IP (ex: `192.168.1.1-254`)
3. Cliquer sur "Scanner"
4. Double-clic sur un appareil pour voir les détails

### Résultats Typiques

| Colonne | Description |
|---------|-------------|
| Nom | Nom d'hôte/NetBIOS |
| IP | Adresse IP |
| Fabricant | Basé sur MAC |
| MAC | Adresse physique |
| Commentaires | Notes personnelles |

---

## 📁 WinSCP - Transfert de Fichiers Sécurisé {#winscp}

### Description
Client SFTP/SCP/FTP pour Windows avec interface graphique intuitive.

### Installation
```powershell
winget install WinSCP.WinSCP
```

### Protocoles Supportés

| Protocole | Port | Description |
|-----------|------|-------------|
| SFTP | 22 | SSH File Transfer (recommandé) |
| SCP | 22 | Secure Copy |
| FTP | 21 | File Transfer Protocol |
| FTPS | 990 | FTP sur SSL/TLS |
| WebDAV | 80/443 | HTTP-based |

### Utilisation CLI (Scripting)

```powershell
# Connexion et transfert
winscp.com /command `
    "open sftp://user:pass@server/" `
    "put C:\local\file.txt /remote/" `
    "exit"
```

### Fonctionnalités Avancées

- **Synchronisation** de répertoires
- **Éditeur intégré** pour fichiers distants
- **Tunnel SSH** pour connexions sécurisées
- **Scripts automatisés** pour backups
- **Clés SSH** pour authentification sans mot de passe

---

## 🌐 NetBird - VPN P2P d'Entreprise {#netbird}

### Description
VPN mesh peer-to-peer open source pour équipes - alternative à Tailscale.

### Installation
```powershell
# Windows
winget install NetBird.NetBird

# Script d'installation officiel
curl -fsSL https://pkgs.netbird.io/install.sh | sh
```

### Commandes Essentielles

| Commande | Description |
|----------|-------------|
| `netbird up` | Connecter au réseau |
| `netbird down` | Déconnecter |
| `netbird status` | Afficher le statut |
| `netbird login` | S'authentifier |

### Fonctionnalités

- **Zero-config** mesh VPN
- **NAT traversal** automatique
- **SSO** (Google, Azure AD, Okta)
- **Access control** par groupe
- **Auto-discovery** des pairs

### Configuration

1. Créer un compte sur [netbird.io](https://app.netbird.io)
2. Installer le client
3. `netbird login` pour s'authentifier
4. `netbird up` pour rejoindre le réseau

---

## 🔗 mRemoteNG - Gestionnaire de Connexions {#mremoteng}

### Description
Gestionnaire multi-protocole de connexions distantes avec interface à onglets.

### Installation
```powershell
winget install mRemoteNG.mRemoteNG
```

### Protocoles Supportés

| Protocole | Usage |
|-----------|-------|
| RDP | Bureau à distance Windows |
| SSH | Ligne de commande Linux/Unix |
| VNC | Bureau à distance multi-plateforme |
| Telnet | Équipements réseau |
| HTTP/HTTPS | Applications web |
| ICA | Citrix |

### Organisation

```
📁 Connexions
├── 📁 Serveurs Production
│   ├── 🖥️ Web Server (SSH)
│   └── 🖥️ Database (RDP)
├── 📁 Dev/Test
│   ├── 🖥️ Dev VM (RDP)
│   └── 🖥️ Test Server (SSH)
└── 📁 Équipements Réseau
    ├── 🔧 Router (SSH)
    └── 🔧 Switch (Telnet)
```

### Fonctionnalités Clés

- **Onglets multiples** pour plusieurs connexions
- **Héritage** de propriétés (credentials, ports)
- **Import/Export** des configurations
- **Chiffrement** du fichier de connexions
- **Tunnel SSH** intégré

---

## 🛡️ Portmaster - Pare-feu Applicatif {#portmaster}

### Description
Pare-feu applicatif open source avec contrôle granulaire par application.

### Installation
```powershell
winget install Safing.Portmaster
```

### Fonctionnalités

| Fonction | Description |
|----------|-------------|
| **App Firewall** | Bloquer/autoriser par application |
| **Network Monitor** | Visualiser tout le trafic |
| **DNS over TLS** | Chiffrement DNS |
| **SPN** | Safing Privacy Network (optionnel) |
| **Filter Lists** | Bloquer trackers/malware |

### Modes de Fonctionnement

| Mode | Description |
|------|-------------|
| **Permissif** | Tout autorisé par défaut |
| **Demander** | Demande pour chaque application |
| **Restrictif** | Tout bloqué par défaut |

### Utilisation

1. **Lancer** Portmaster (démarre au boot)
2. **Dashboard** via `http://localhost:817/`
3. **Monitor** pour voir le trafic en temps réel
4. **Settings** pour configurer les règles globales
5. **Apps** pour gérer les permissions par application

### Règles Recommandées

```
✅ Firefox - Autoriser tout
✅ VS Code - Autoriser (updates, extensions)
🚫 Office Telemetry - Bloquer
🚫 Windows Telemetry - Bloquer
⚠️ PowerShell - Demander
⚠️ cmd.exe - Demander
```

---

## 📊 Tableau Récapitulatif

| Outil | Type | Port/Protocole | OS |
|-------|------|---------------|-----|
| Nmap | Scanner ports | N/A | Linux/Win |
| Wireshark | Analyseur trafic | N/A | Linux/Win |
| WireGuard | VPN | UDP 51820 | Linux/Win |
| Advanced IP Scanner | Scanner réseau | N/A | Windows |
| WinSCP | Transfert fichiers | 22, 21 | Windows |
| NetBird | VPN mesh | UDP 51820 | Linux/Win |
| mRemoteNG | Connexions distantes | Multiple | Windows |
| Portmaster | Firewall | N/A | Windows |

---

## 🔗 Intégration API Th3 Thirty3

### Endpoints Disponibles

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/network/nmap/status` | GET | Statut Nmap |
| `/api/network/nmap/scan` | POST | Lancer scan Nmap |
| `/api/network/tshark/status` | GET | Statut TShark |
| `/api/network/tshark/capture` | POST | Capturer trafic |
| `/api/network/interfaces` | GET | Lister interfaces |
| `/api/network/discover` | POST | Découverte réseau |

---

*Guide créé le 2025-12-20 - Th3 Thirty3 Platform*
