@echo off
setlocal EnableDelayedExpansion

echo [SETUP] Initialisation du protocole d'installation Th3 Thirty3...
echo [SETUP] Mode: Zero-Friction / DevOps

:: 1. Verification des droits Admin (Necessaire pour Winget)
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERREUR] Ce script necessite les droits Administrateur pour installer les dependances.
    echo Veuillez faire clic-droit -> "Executer en tant qu'administrateur".
    pause
    exit /b
)

:: 2. Installation des dependances systeme via Winget
echo.
echo [1/4] Verification des dependances systeme...

:: Git
where git >nul 2>&1
if %errorLevel% neq 0 (
    echo [INSTALL] Git non trouve. Installation via Winget...
    winget install --id Git.Git -e --source winget --accept-package-agreements --accept-source-agreements
) else (
    echo [OK] Git est deja installe.
)

:: Node.js
where node >nul 2>&1
if %errorLevel% neq 0 (
    echo [INSTALL] Node.js non trouve. Installation via Winget...
    winget install --id OpenJS.NodeJS.LTS -e --source winget --accept-package-agreements --accept-source-agreements
    echo [INFO] Un redemarrage du terminal pourrait etre necessaire.
) else (
    echo [OK] Node.js est deja installe.
)

:: Ollama
where ollama >nul 2>&1
if %errorLevel% neq 0 (
    echo [INSTALL] Ollama non trouve. Installation via Winget...
    winget install --id Ollama.Ollama -e --source winget --accept-package-agreements --accept-source-agreements
) else (
    echo [OK] Ollama est deja installe.
)

:: 3. Installation des dependances du projet
echo.
echo [2/4] Installation des modules Node.js...

cd /d "%~dp0"

if exist "server\package.json" (
    echo [NPM] Installation dependances Server...
    cd server
    call npm install --silent
    cd ..
)

if exist "interface\package.json" (
    echo [NPM] Installation dependances Interface...
    cd interface
    call npm install --silent
    cd ..
)

:: 4. Configuration
echo.
echo [3/4] Configuration de l'environnement...

if not exist "server\.env" (
    if exist "server\.env.example" (
        echo [CONFIG] Creation de .env a partir de l'exemple...
        copy "server\.env.example" "server\.env" >nul
        echo [IMPORTANT] N'oubliez pas d'ajouter vos cles API dans server\.env !
    ) else (
        echo [WARN] Pas de .env.example trouve. Creation d'un .env vide.
        type nul > "server\.env"
    )
) else (
    echo [OK] Fichier .env existant.
)

:: 5. Finalisation
echo.
echo [4/4] Termine !
echo.
echo [INFO] Pour lancer le systeme, executez 'start_th3_thirty3.bat'.
echo.
pause
