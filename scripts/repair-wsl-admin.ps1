# ===========================================
# RÉPARATION WSL - EXÉCUTER EN ADMINISTRATEUR
# ===========================================
# Clic droit sur ce fichier > "Exécuter avec PowerShell en tant qu'Admin"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   RÉPARATION WSL / DOCKER DESKTOP     " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Vérifier admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n[ERREUR] Ce script doit être exécuté en tant qu'Administrateur!" -ForegroundColor Red
    Write-Host "Clic droit > Exécuter avec PowerShell en tant qu'Admin" -ForegroundColor Yellow
    pause
    exit
}

Write-Host "`n[1/5] Arrêt de Docker Desktop..." -ForegroundColor Yellow
Stop-Process -Name "Docker Desktop" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

Write-Host "`n[2/5] Activation de la fonctionnalité WSL..." -ForegroundColor Yellow
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart

Write-Host "`n[3/5] Activation de Virtual Machine Platform..." -ForegroundColor Yellow
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart

Write-Host "`n[4/5] Réparation des composants Windows..." -ForegroundColor Yellow
# Réparer les classes COM manquantes
regsvr32 /s msi.dll 2>$null

Write-Host "`n[5/5] Mise à jour du kernel WSL..." -ForegroundColor Yellow
# Télécharger et installer le kernel WSL2
$wslUpdateUrl = "https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi"
$wslUpdatePath = "$env:TEMP\wsl_update_x64.msi"
Write-Host "   Téléchargement du kernel WSL2..." -ForegroundColor Gray
Invoke-WebRequest -Uri $wslUpdateUrl -OutFile $wslUpdatePath -UseBasicParsing
Write-Host "   Installation..." -ForegroundColor Gray
Start-Process msiexec.exe -ArgumentList "/i", $wslUpdatePath, "/quiet", "/norestart" -Wait

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "   RÉPARATION TERMINÉE!                " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "`nUn REDÉMARRAGE est REQUIS." -ForegroundColor Yellow
Write-Host "Après redémarrage:" -ForegroundColor White
Write-Host "  1. Docker Desktop devrait fonctionner" -ForegroundColor White
Write-Host "  2. Exécutez: wsl --install -d Ubuntu" -ForegroundColor White

$restart = Read-Host "`nRedémarrer maintenant? (O/N)"
if ($restart -eq "O" -or $restart -eq "o") {
    Restart-Computer -Force
}
