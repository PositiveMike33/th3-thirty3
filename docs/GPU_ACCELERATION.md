# 🚀 Accélération GPU & Deep Learning - Guide Nexus33

Ce document détaille l'architecture et l'utilisation de l'accélération GPU pour Th3 Thirty3 (Nexus33).

## 📑 Table des Matières

1. [Architecture GPU](#1-architecture-gpu)
2. [Prérequis Système](#2-prérequis-système)
3. [Démarrage Rapide](#3-démarrage-rapide)
4. [Docker & GPU Passthrough](#4-docker--gpu-passthrough)
5. [Entraînement de Modèles (TensorFlow)](#5-entraînement-de-modèles-tensorflow)
6. [Inférence LLM (Ollama GPU)](#6-inférence-llm-ollama-gpu)
7. [Monitoring & Debugging](#7-monitoring--debugging)

---

## 1. Architecture GPU

L'accélération GPU est utilisée par deux composants principaux :

| Composant | Technologie | Usage | Port Container |
|-----------|-------------|-------|----------------|
| **TensorFlow Trainer** | TensorFlow 2.x (CUDA 11/12) | Entraînement de modèles classification/cyber | `5000` (API), `6006` (TensorBoard) |
| **Ollama** | Llama.cpp + CUDA | Inférence LLM locale ultra-rapide | `11434` |

---

## 2. Prérequis Système

Pour que le GPU NVIDIA soit accessible via Docker sur Windows 11 :

- **GPU** : NVIDIA GeForce RTX 30/40 series recommandé (VRAM >= 8GB)
- **Driver** : Dernier pilote NVIDIA Game Ready ou Studio
- **WSL2** : Version à jour (`wsl --update`)
- **Docker Desktop** : Version 4.x+ avec support WSL2 activé

---

## 3. Démarrage Rapide

Utilisez le raccourci **`Th3 Thirty3 GPU`** ou la commande suivante :

```bat
NEXUS33-docker.bat --gpu
```

Cela active le profil Docker `docker-compose.gpu.yml` qui monte le GPU dans les conteneurs.

---

## 4. Docker & GPU Passthrough

La configuration technique se trouve dans `docker-compose.gpu.yml`. 
Section critique pour le passthrough :

```yaml
deploy:
  resources:
    reservations:
      devices:
        - driver: nvidia
          count: 1
          capabilities: [gpu]
```

---

## 5. Entraînement de Modèles (TensorFlow)

Le service `tensorflow-trainer` expose une API pour lancer des entraînements.

### Lancer un entraînement manuel :
Via l'interface Nexus33 ou directement :
```bash
curl -X POST http://localhost:5000/train \
  -H "Content-Type: application/json" \
  -d '{"dataset": "security_logs", "epochs": 10}'
```

---

## 6. Inférence LLM (Ollama GPU)

Par défaut, Ollama tourne sur l'hôte pour maximiser les perfs, ou dans un conteneur dédié si configuré.
Vérifiez l'utilisation GPU :
```powershell
nvidia-smi
```
Vous devriez voir un processus `ollama_llama_server.exe` utiliser de la VRAM lors des requêtes.

---

## 7. Monitoring & Debugging

**Vérifier la visibilité du GPU :**
```bash
docker exec -it th3-gpu-trainer python -c "import tensorflow as tf; print(tf.config.list_physical_devices('GPU'))"
```

**Voir les logs TensorBoard :**
Accédez à `http://localhost:6006` pendant/après un entraînement.
