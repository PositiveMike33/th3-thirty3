---
description: Protocole de sauvegarde et git commit du projet
---

# Protocole de Sauvegarde Git

// turbo-all

## Étapes

1. Vérifier les modifications en cours
```powershell
git status
```

2. Ajouter tous les fichiers modifiés au staging
```powershell
git add .
```

3. Créer le commit avec un message descriptif
```powershell
git commit -m "feat: Description des modifications"
```

4. Pousser vers GitHub
```powershell
git push
```

## Format du Message de Commit

Utilisez le format conventionnel :
- `feat:` - Nouvelle fonctionnalité
- `fix:` - Correction de bug
- `docs:` - Documentation
- `style:` - Formatage, pas de changement de code
- `refactor:` - Refactorisation du code
- `test:` - Ajout de tests
- `chore:` - Maintenance, dépendances

## Notes
- Le submodule `hexstrike-ai/` doit être commité séparément si modifié
- Les fichiers de logs temporaires (`*.log`, `*_logs.txt`) ne sont généralement pas inclus
