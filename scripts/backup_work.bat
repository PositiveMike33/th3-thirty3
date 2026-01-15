@echo off
echo [BACKUP] Sauvegarde du travail en cours vers GitHub...

cd /d "%~dp0"

:: 1. Ajouter tous les fichiers modifies
git add .

:: 2. Demander un message de commit (optionnel)
set /p commit_msg="Entrez une description (ou appuyez sur Entree pour 'Sauvegarde automatique'): "
if "%commit_msg%"=="" set commit_msg=Sauvegarde automatique fin de session

:: 3. Commit
git commit -m "%commit_msg%"

:: 4. Push vers GitHub
echo [BACKUP] Envoi vers GitHub...
git push origin main

if %errorlevel% equ 0 (
    echo [SUCCESS] Sauvegarde reussie ! Tout est sur GitHub.
) else (
    echo [ERROR] Une erreur est survenue lors de l'envoi.
)

pause
