# ✅ Pattern Fabric KeelClip 5-Why - Installation Complète

## 🎉 Résumé

Le pattern Fabric personnalisé **keelclip_5why** est maintenant installé et fonctionnel !

### ✅ Ce qui a été créé

1. **Pattern Fabric** : `~/.config/fabric/patterns/keelclip_5why/system.md`
2. **Copie locale** : `server/fabric/data/patterns/keelclip_5why/system.md`
3. **Documentation** : `server/fabric/data/patterns/keelclip_5why/README.md`

---

## 🚀 Utilisation

### Commande de Base

```bash
echo "Description de l'incident" | fabric --pattern keelclip_5why
```

### Exemples Testés

```bash
# Exemple 1 : Bourrage Star Wheel
echo "Bourrage de cartons au Star Wheel. Desalignement de 2mm observe. Usure des Lugs visible. 3 occurrences shift de nuit." | fabric --pattern keelclip_5why

# Exemple 2 : Via fichier
fabric --pattern keelclip_5why < incident.txt

# Exemple 3 : Via clipboard (Windows)
Get-Clipboard | fabric --pattern keelclip_5why

# Exemple 4 : Sauvegarder le rapport
echo "Description..." | fabric --pattern keelclip_5why > rapport_5why.md
```

---

## 📊 Sortie Générée

Le pattern génère un rapport VPO complet :

1. ⚠️ **Sécurité LOTO** (si applicable)
2. 📋 **QQOQCCP** (Définition du problème)
3. 🔍 **5 Pourquoi** (Chaîne causale P1→P5)
4. 🛠️ **Plan d'Action** (Corrective + Préventive)

**Format** : Prêt à copier-coller dans SAP/DMS

---

## 🎯 Intégration Système

Le pattern est utilisé par :

1. **Fabric CLI** : `fabric --pattern keelclip_5why`
2. **VisionService** : Analyse d'images → Pattern VPO
3. **KeelClipAnalyzer** : Génération automatique
4. **AnythingLLM** : Workspace VPO

**Cohérence garantie** : Même format VPO partout

---

## 📝 Règles du Pattern

### ✅ Obligatoire

- Vocabulaire technique exact (Star Wheel, Lug Chain, PLC, etc.)
- Cause racine systémique (Standard/CIL/OPL/Formation)
- Format tableaux markdown
- Sécurité LOTO en premier si applicable

### ❌ Interdit

- "Erreur humaine"
- "Faute de l'opérateur"
- "Inattention" / "Négligence"
- Sauts logiques dans la chaîne causale

---

## 🔍 Vérification

```bash
# Lister les patterns disponibles
fabric --list | grep keelclip

# Tester le pattern
echo "Test incident" | fabric --pattern keelclip_5why

# Vérifier l'emplacement
ls ~/.config/fabric/patterns/keelclip_5why/system.md
```

---

## 💡 Conseils d'Utilisation

### Pour une meilleure qualité

1. **Sois précis** : Mentionne les composants exacts
   ```
   ✅ "Bourrage au Star Wheel, désalignement 2mm"
   ❌ "Problème de machine"
   ```

2. **Inclus les mesures** : Valeurs numériques
   ```
   ✅ "Température 180°C au lieu de 190°C"
   ❌ "Température trop basse"
   ```

3. **Contexte opérationnel** : Quand, combien de fois
   ```
   ✅ "3 occurrences durant shift de nuit"
   ❌ "Ça arrive souvent"
   ```

4. **Observations visuelles** : Ce que tu vois
   ```
   ✅ "Usure visible sur les Lugs, traces de colle"
   ❌ "Ça a l'air usé"
   ```

---

## 🔄 Workflow Complet

### Scénario 1 : Incident Simple (Texte)

```bash
# 1. Décrire l'incident
echo "Bourrage Star Wheel, usure Lugs, shift nuit" > incident.txt

# 2. Générer le rapport
fabric --pattern keelclip_5why < incident.txt > rapport.md

# 3. Copier dans SAP
cat rapport.md | clip  # Windows
```

### Scénario 2 : Incident avec Image

```bash
# 1. Analyser l'image (via système VPO)
curl -X POST http://localhost:3000/incident/analyze \
  -d '{"media": "data:image/jpeg;base64,..."}' > analyse.json

# 2. Extraire la description
jq -r '.summary' analyse.json > description.txt

# 3. Générer le rapport 5-Why
fabric --pattern keelclip_5why < description.txt > rapport.md
```

### Scénario 3 : Workflow Automatisé

```bash
# Script complet
#!/bin/bash
INCIDENT="$1"
echo "$INCIDENT" | \
  fabric --pattern keelclip_5why | \
  tee rapport_$(date +%Y%m%d_%H%M%S).md | \
  clip
echo "✅ Rapport généré et copié dans le clipboard"
```

---

## 🆘 Dépannage

### "Pattern not found"

```bash
# Vérifier l'installation
ls ~/.config/fabric/patterns/keelclip_5why/system.md

# Réinstaller si nécessaire
cp server/fabric/data/patterns/keelclip_5why/system.md \
   ~/.config/fabric/patterns/keelclip_5why/system.md
```

### "Output not formatted"

→ Assure-toi que la description contient des détails techniques
→ Mentionne les composants spécifiques (Star Wheel, Lug Chain, etc.)

### "Fabric command not found"

```bash
# Installer Fabric
go install github.com/danielmiessler/fabric@latest

# Ou via pip
pip install fabric-ai
```

---

## 📚 Documentation

- **Guide complet** : `server/fabric/data/patterns/keelclip_5why/README.md`
- **Pattern source** : `~/.config/fabric/patterns/keelclip_5why/system.md`
- **Intégration système** : `INCIDENT_ANALYSIS.md`

---

## ✅ Checklist

- [x] Pattern créé dans `~/.config/fabric/patterns/keelclip_5why/`
- [x] Pattern testé avec succès
- [x] Documentation créée
- [x] Intégration avec système VPO
- [x] Exemples d'utilisation fournis

**Le pattern est prêt à l'emploi ! 🎉**
