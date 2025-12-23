# 🧬 Cyber Academy Evolution System - Documentation

## Vue d'Ensemble

Le système Cyber Academy Evolution est un framework d'entraînement continu pour les modèles LLM locaux, inspiré de HackerGPT et intégrant le Golden Ratio (φ = 1.618) comme fondation mathématique pour l'apprentissage progressif.

---

## Architecture des Composants

### 📚 Backend (server/)

| Fichier | Rôle |
|---------|------|
| `hackergpt_training_service.js` | Service principal d'entraînement HackerGPT |
| `continuous_evolution_system.js` | Système d'évolution continue avec 10 niveaux |
| `knowledge_integrated_training.js` | Training RAG avec bases de connaissances |
| `evolution_routes.js` | API REST pour le dashboard et team chat |
| `fibonacci_cognitive_optimizer.js` | Optimisation cognitive basée sur φ |

### 🎨 Frontend (interface/src/components/)

| Fichier | Rôle |
|---------|------|
| `AgentEvolutionDashboard.jsx` | Dashboard temps réel des agents |
| `AgentTeamChat.jsx` | Chat d'équipe collaboratif |

---

## Les 3 Agents AI

| Agent | Modèle | Spécialité | Forces |
|-------|--------|------------|--------|
| 🎭 **Sadiq** | sadiq-bd/llama3.2-3b-uncensored | Social Engineering & OSINT | OSINT, Wireless, Red Team |
| 🐬 **Dolphin** | uandinotai/dolphin-uncensored | Pentesting & Kernel | Pentesting, Exploit Dev |
| ⚡ **Nidum** | nidumai/nidum-llama-3.2-3b-uncensored | Exploit Dev & Précision | Exploit Dev, Crypto, Malware |

---

## Système d'Évolution (10 Niveaux)

| Level | Nom | Score Min | Complexité φ |
|-------|-----|-----------|--------------|
| 1 | Script Kiddie | 0% | 1.0 |
| 2 | Junior Pentester | 55% | 1.2 |
| 3 | Security Analyst | 68% | 1.4 |
| 4 | Red Team Operator | 75% | 1.6 |
| 5 | Elite Hacker | 82% | **φ = 1.618** |
| 6 | APT Specialist | 88% | 1.94 |
| 7 | Ghost | 93% | 2.0 |
| 8 | Legendary | 96% | 2.43 |
| 9 | Prodigy | 98% | 2.62 |
| 10 | Transcendent | 99.5% | φ |

### Score Prodige (1-10)
Les modèles au niveau 9-10 reçoivent un Score Prodige basé sur:
- Maîtrise des domaines
- Consistance des performances
- Total XP accumulé
- Momentum d'apprentissage

---

## Knowledge Bases

Le système intègre **20 fichiers** de connaissances:

| Domaine | Sources | Questions |
|---------|---------|-----------|
| OSINT | osint_shodan_training, osint_tools, osint_expert_team, kinetic_osint | 5 |
| Pentesting | pentestgpt_methodology, defense_training | 36 |
| Exploit Dev | pentestgpt + network_defense | 36 |
| Web Security | pentestgpt_methodology | 36 |
| Wireless | wifi_security_training_scenarios | 20 |
| Cryptography | pentestgpt_methodology | 36 |
| Forensics | pentestgpt_methodology | 36 |
| Red Team | pentestgpt + defense_training | 36 |

---

## RAG Context Injection

Le système injecte le contexte des Knowledge Bases dans les examens:
- **Amélioration moyenne**: +16%
- **Contexte max**: 2000 tokens
- **Sources**: Q&A pairs, méthodologies, tools arsenal, fallback strategies

---

## API Endpoints

### Evolution Dashboard
```
GET  /api/evolution/evolution-status    # État des 3 agents
GET  /api/evolution/training-log        # Logs d'entraînement
GET  /api/evolution/knowledge-summary   # Résumé des KBs
POST /api/evolution/train               # Lancer un entraînement
POST /api/evolution/team-chat           # Chat multi-agents
GET  /api/evolution/model-state/:name   # État détaillé d'un agent
```

### HackerGPT
```
GET  /api/hackergpt/status              # État du training
GET  /api/hackergpt/models              # Configurations modèles
POST /api/hackergpt/exam                # Passer un examen
```

---

## Navigation Frontend

| Route | Page | Description |
|-------|------|-------------|
| `/evolution` | Agent Evolution Dashboard | Visualisation temps réel |
| `/team-chat` | Agent Team Chat | Collaboration fraternelle |
| `/training` | Ollama Training Dashboard | Entraînement modèles |
| `/cyber-training` | Cyber Training Page | Formation cybersécurité |

---

## Progression Actuelle

| Agent | Level | XP | Top Expertise |
|-------|-------|-----|---------------|
| 🎭 Sadiq | 1 | 310 | OSINT: 60.8%, Wireless: 60% |
| 🐬 Dolphin | 1 | 187 | Pentesting: 43.2% |
| ⚡ Nidum | 1 | 130 | Exploit Dev: 29.6% |

---

## Scripts d'Entraînement

```bash
# Entraînement complet avec RAG
node run_full_evolution_rag.js

# Test comparatif RAG vs sans RAG
node test_rag_comparison.js

# Test Knowledge Base
node test_kb_training.js

# Evolution continue
node run_evolution.js
```

---

## Prochaines Étapes

1. **Enrichir les Knowledge Bases** - Ajouter plus de Q&A pour les domaines vides
2. **Auto-génération de questions** - Utiliser LLM pour générer des questions
3. **Spaced Repetition** - Implémenter la révision espacée
4. **Competitions** - Faire s'affronter les agents sur des CTF
5. **Visualisation avancée** - Graphiques de progression dans le temps

---

*Système créé le 23 décembre 2025*
*Framework: Th3 Thirty3 Cyber Academy*
*Golden Ratio: φ = 1.618033988749895*
