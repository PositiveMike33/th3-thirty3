# 🔧 Réparation WSL - Guide Manuel

Votre installation WSL est endommagée (code d'erreur: `Wsl/Cal`). Voici comment réparer.

## Option 1: Réparation rapide

Ouvrez **PowerShell en Administrateur** et exécutez:

```powershell
# Désinstaller WSL complètement
wsl --unregister Ubuntu 2>$null
dism.exe /online /disable-feature /featurename:Microsoft-Windows-Subsystem-Linux /norestart
dism.exe /online /disable-feature /featurename:VirtualMachinePlatform /norestart

# Redémarrer
Restart-Computer
```

Après redémarrage, exécutez:

```powershell
# Réactiver WSL
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart

# Redémarrer encore
Restart-Computer
```

Puis:

```powershell
# Installer WSL2 et Ubuntu
wsl --set-default-version 2
wsl --install -d Ubuntu
```

---

## Option 2: Utiliser Docker Desktop (plus simple)

Installez **Docker Desktop** qui gère WSL automatiquement:

1. Téléchargez: https://www.docker.com/products/docker-desktop/
2. Installez et cochez "Use WSL 2 based engine"
3. Docker réparera WSL automatiquement

---

## Après réparation

```bash
# Dans Ubuntu WSL
cd /mnt/c/Users/th3th/.gemini/antigravity/scratch/th3-thirty3
docker compose -f docker-compose.gpu.yml up -d
```
