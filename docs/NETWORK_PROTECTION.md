# Scripts de Protection Reseau - Th3 Thirty3

## Scripts Crees

| Script | Description | Utilisation |
|--------|-------------|-------------|
| `scripts/network_backup.ps1` | Sauvegarde la configuration reseau | Executer une fois pour creer la reference |
| `scripts/verify_network_integrity.ps1` | Verifie que l'IP n'a pas change | Automatique au demarrage |
| `scripts/start_tor_safe.ps1` | Demarre Tor en mode securise | Quand vous avez besoin de Tor |
| `scripts/create_restore_point.ps1` | Cree un point de restauration | Executer en tant qu'Admin |
| `start_safe.bat` | Demarrage securise de l'application | Double-clic pour lancer |

## Scripts a EVITER

> **ATTENTION**: Ces scripts modifient votre configuration reseau systeme.
> Ne les executez PAS sans une bonne raison.

| Script | Risque |
|--------|--------|
| `configure_dns_cloudflare.ps1` | Modifie les DNS de tous les adaptateurs |
| `scripts/setup_proxy.ps1` | Configure un proxy systeme global |
| `install_tor_service.ps1` | Installe Tor comme service Windows |
| `install_tor_service_v2.ps1` | Idem |
| `docker/docker-compose.yml` | Container avec NET_ADMIN (risque reseau) |

## Commandes Utiles

### Verifier l'integrite reseau
```powershell
.\scripts\verify_network_integrity.ps1
```

### Sauvegarder la configuration actuelle
```powershell
.\scripts\network_backup.ps1
```

### Demarrer Tor en mode securise
```powershell
.\scripts\start_tor_safe.ps1
```

### Arreter Tor
```powershell
.\scripts\start_tor_safe.ps1 -Stop
```

### Verifier votre vraie IP
```powershell
(Invoke-WebRequest -Uri "https://api.ipify.org").Content
```

### Verifier IP via Tor
```powershell
curl.exe --socks5 127.0.0.1:9050 https://api.ipify.org
```

## Architecture Securisee

```
  Votre PC (192.168.1.147)
       |
       +-- Wi-Fi (DHCP normal, DNS FAI)
       |
       +-- Applications normales -> Internet direct
       |
       +-- Th3 Thirty3 (optionnel)
             |
             +-- Tor SOCKS5 (127.0.0.1:9050)
                   |
                   +-- Requetes OSINT -> Reseau Tor
```

**Principe**: Tor n'affecte QUE les applications qui l'utilisent explicitement via le proxy SOCKS5.
Votre IP systeme reste 192.168.1.147 en permanence.
