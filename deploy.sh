#!/bin/bash

# ============================================
# DEPLOY.SH - Script de déploiement automatisé
# Th3 Thirty3 Project
# ============================================

# Couleurs pour les messages
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     TH3 THIRTY3 - DEPLOY SCRIPT        ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
echo ""

# 1. Afficher le git status
echo -e "${YELLOW}📋 Git Status:${NC}"
echo "----------------------------------------"
git status
echo "----------------------------------------"
echo ""

# 2. Exécuter git add .
echo -e "${YELLOW}📦 Staging all changes...${NC}"
git add .
echo -e "${GREEN}✓ All files staged${NC}"
echo ""

# 3. Demander le message de commit
echo -e "${YELLOW}💬 Enter commit message (or press Enter for default):${NC}"
read -r COMMIT_MSG

# 4. Si message vide, utiliser message par défaut avec date
if [ -z "$COMMIT_MSG" ]; then
    COMMIT_MSG="Auto-deploy: $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${CYAN}Using default message: ${COMMIT_MSG}${NC}"
fi

# 5. Exécuter le commit
echo ""
echo -e "${YELLOW}📝 Committing changes...${NC}"
git commit -m "$COMMIT_MSG"

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Commit failed or nothing to commit${NC}"
    exit 1
fi

# 6. Push vers origin main
echo ""
echo -e "${YELLOW}🚀 Pushing to origin main...${NC}"
git push origin main

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Push failed!${NC}"
    exit 1
fi

# 7. Message de succès en vert
echo ""
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   ✅ DEPLOYMENT SUCCESSFUL!            ║${NC}"
echo -e "${GREEN}║   All changes pushed to origin/main    ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Commit: ${COMMIT_MSG}${NC}"
echo -e "${GREEN}Time: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
