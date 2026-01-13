# ===============================================
# Th3 Thirty3 - Create System Restore Point
# EXECUTE AS ADMINISTRATOR
# ===============================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Point de Restauration Système" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Vérifier les privilèges Admin
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[ERREUR] Ce script nécessite des privilèges Administrateur!" -ForegroundColor Red
    Write-Host "Clic droit -> Exécuter en tant qu'Administrateur" -ForegroundColor Yellow
    pause
    exit
}

Write-Host "[1/2] Activation de la protection système..." -ForegroundColor Yellow
try {
    Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
    Write-Host "  [OK] Protection système activée sur C:" -ForegroundColor Green
} catch {
    Write-Host "  [INFO] Protection système déjà active" -ForegroundColor Gray
}

Write-Host ""
Write-Host "[2/2] Création du point de restauration..." -ForegroundColor Yellow
try {
    Checkpoint-Computer -Description "Pre-Th3-Thirty3-Network-Protection" -RestorePointType "MODIFY_SETTINGS"
    Write-Host "  [OK] Point de restauration créé!" -ForegroundColor Green
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  SAUVEGARDE SYSTÈME RÉUSSIE" -ForegroundColor Green
    Write-Host "  Vous pouvez revenir à cet état si" -ForegroundColor Green
    Write-Host "  quelque chose tourne mal." -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
} catch {
    Write-Host "  [ERREUR] $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
pause
