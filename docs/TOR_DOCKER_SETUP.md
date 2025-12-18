# 🧅 Tor Configuration - Th3 Thirty3

## Vue d'ensemble

Th3 Thirty3 utilise le réseau Tor pour anonymiser les requêtes OSINT et les opérations de cybersécurité.

## Architecture

```
┌─────────────────────────────────────────────┐
│           Th3 Thirty3 Server                │
│                (Node.js)                    │
│                                              │
│  ┌──────────────────────────────────────┐   │
│  │ tor_network_service.js               │   │
│  │  → torFetchViaDocker() ✅            │   │
│  │  → Falls back to SOCKS5 if needed    │   │
│  └──────────────────────────────────────┘   │
│                    │                         │
│                    ▼                         │
│  ┌──────────────────────────────────────┐   │
│  │ Docker: th3_kali_tor                 │   │
│  │  🧅 Tor SOCKS5 (0.0.0.0:9050)        │   │
│  │  🔧 Control Port (9051)              │   │
│  │  🔒 Exit IP: Variable                │   │
│  └──────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

## Méthodes de connexion Tor

### 1. Docker Kali-Tor (Recommandé) ✅

La méthode la plus fiable sur Windows. Le conteneur Docker inclut:
- Kali Linux avec outils OSINT
- Tor pré-configuré
- Redémarrage automatique

**Démarrer le conteneur:**
```bash
cd docker
docker-compose up -d kali-tor
```

**Vérifier le statut:**
```bash
docker exec th3_kali_tor curl -s --socks5 localhost:9050 https://check.torproject.org/api/ip
```

### 2. Tor Standalone (Backup)

Si Docker n'est pas disponible:
```bash
.\start_tor_standalone.bat
```

Ou manuellement:
```powershell
C:\Tor\tor\tor.exe -f C:\Tor\torrc
```

## API Endpoints

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/tor/status` | GET | Statut complet du service Tor |
| `/api/tor/verify` | GET | Vérification rapide IsTor + IP |
| `/api/tor/startup-check` | GET | Check complet au démarrage |
| `/api/tor/ip` | GET | IP de sortie actuelle |
| `/api/tor/new-identity` | POST | Nouveau circuit (nouvelle IP) |
| `/api/tor/start` | POST | Démarrer tor.exe |
| `/api/tor/stop` | POST | Arrêter tor.exe |
| `/api/tor/fetch` | POST | Requête HTTP via Tor |

## Vérification au démarrage

Le serveur Node.js vérifie automatiquement Tor au démarrage:

```
[SYSTEM] Running automatic Tor verification...

==================================================
🧅 TOR STARTUP CHECK - Th3 Thirty3
==================================================

[TOR] Checking port 9050...
[TOR] ✅ Port 9050 is already listening

[TOR] Verifying Tor connection...
[TOR] ✅ Connected via Docker Kali-Tor (Exit IP: 185.220.101.6)

--------------------------------------------------
TOR STATUS SUMMARY:
--------------------------------------------------
  Port 9050:    🟢 ACTIVE
  Tor Verified: 🟢 YES
  Exit IP:      185.220.101.6
--------------------------------------------------

[SYSTEM] ✅ Tor is ACTIVE and VERIFIED
[SYSTEM] 🧅 Exit IP: 185.220.101.6
```

## Configuration Docker

Le fichier `docker/docker-compose.yml` configure:

```yaml
services:
  kali-tor:
    container_name: th3_kali_tor
    restart: unless-stopped
    ports:
      - "9050:9050"  # SOCKS5 proxy
      - "9051:9051"  # Control port
    healthcheck:
      test: ["CMD", "curl", "-s", "--socks5", "localhost:9050", "https://check.torproject.org/api/ip"]
```

## Fichiers clés

| Fichier | Description |
|---------|-------------|
| `server/tor_startup_check.js` | Module de vérification au démarrage |
| `server/tor_network_service.js` | Service principal Tor |
| `server/tor_routes.js` | Routes API Tor |
| `docker/kali-tor/` | Configuration Docker Kali-Tor |
| `start_tor_standalone.bat` | Lanceur tor.exe standalone |

## Dépannage

### Port 9050 non disponible
```powershell
# Vérifier qui utilise le port
netstat -ano | Select-String "9050"

# Arrêter tor.exe existant
Stop-Process -Name "tor" -Force
```

### Docker container ne démarre pas
```bash
docker logs th3_kali_tor
docker restart th3_kali_tor
```

### IsTor: false malgré port actif
Cela indique que quelque chose d'autre que Tor écoute sur le port 9050.
Vérifiez avec:
```powershell
Get-Process -Id (Get-NetTCPConnection -LocalPort 9050).OwningProcess
```

## Sécurité

⚠️ **Important:**
- N'utilisez Tor QUE pour des activités légales
- Le réseau Tor ne garantit PAS l'anonymat complet
- Les sites .onion peuvent être dangereux
- Toujours effacer les traces après les opérations sensibles

---
*Dernière mise à jour: 2025-12-17*
