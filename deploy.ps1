# ============================================
# DEPLOY.PS1 - Script de déploiement automatisé
# Th3 Thirty3 Project
# ============================================

Write-Host ""
Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     TH3 THIRTY3 - DEPLOY SCRIPT        ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# 1. Afficher le git status
Write-Host "📋 Git Status:" -ForegroundColor Yellow
Write-Host "----------------------------------------"
git status
Write-Host "----------------------------------------"
Write-Host ""

# 2. Exécuter git add .
Write-Host "📦 Staging all changes..." -ForegroundColor Yellow
git add .
Write-Host "✓ All files staged" -ForegroundColor Green
Write-Host ""

# 3. Demander le message de commit
Write-Host "💬 Enter commit message (or press Enter for default):" -ForegroundColor Yellow
$COMMIT_MSG = Read-Host

# 4. Si message vide, utiliser message par défaut avec date
if ([string]::IsNullOrWhiteSpace($COMMIT_MSG)) {
    $COMMIT_MSG = "Auto-deploy: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host "Using default message: $COMMIT_MSG" -ForegroundColor Cyan
}

# 5. Exécuter le commit
Write-Host ""
Write-Host "📝 Committing changes..." -ForegroundColor Yellow
git commit -m "$COMMIT_MSG"

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Commit failed or nothing to commit" -ForegroundColor Red
    exit 1
}

# 6. Push vers origin main
Write-Host ""
Write-Host "🚀 Pushing to origin main..." -ForegroundColor Yellow
git push origin main

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Push failed!" -ForegroundColor Red
    exit 1
}

# 7. Message de succès en vert
Write-Host ""
Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║   ✅ DEPLOYMENT SUCCESSFUL!            ║" -ForegroundColor Green
Write-Host "║   All changes pushed to origin/main    ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Commit: $COMMIT_MSG" -ForegroundColor Green
Write-Host "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
