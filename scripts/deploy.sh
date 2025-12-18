#!/bin/bash
# ===========================================
# Nexus33 Deployment Script
# ===========================================
# This script automates the deployment of Nexus33
# to your production server (nexus33.io)
# ===========================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DEPLOY_USER="${DEPLOY_USER:-root}"
DEPLOY_HOST="${DEPLOY_HOST:-nexus33.io}"
DEPLOY_PATH="${DEPLOY_PATH:-/var/www/nexus33}"
BRANCH="${BRANCH:-main}"

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════╗"
echo "║     NEXUS33 DEPLOYMENT SCRIPT                  ║"
echo "╠════════════════════════════════════════════════╣"
echo "║ Host: $DEPLOY_HOST"
echo "║ Path: $DEPLOY_PATH"
echo "║ Branch: $BRANCH"
echo "╚════════════════════════════════════════════════╝"
echo -e "${NC}"

# Function: Print step
step() {
    echo -e "\n${GREEN}▶ $1${NC}"
}

# Function: Print warning
warn() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Function: Print error
error() {
    echo -e "${RED}✖ $1${NC}"
    exit 1
}

# ===========================================
# STEP 1: Pre-flight checks
# ===========================================
step "STEP 1: Pre-flight checks..."

# Check if we're in the right directory
if [ ! -f "package.json" ] && [ ! -d "interface" ]; then
    error "Please run this script from the project root directory"
fi

# Check for required tools
command -v npm >/dev/null 2>&1 || error "npm is required but not installed"
command -v git >/dev/null 2>&1 || error "git is required but not installed"

echo "✓ All pre-flight checks passed"

# ===========================================
# STEP 2: Build Frontend
# ===========================================
step "STEP 2: Building frontend..."

cd interface
npm ci --silent
npm run build

if [ ! -d "dist" ]; then
    error "Frontend build failed - dist folder not found"
fi

echo "✓ Frontend built successfully"
cd ..

# ===========================================
# STEP 3: Prepare deployment package
# ===========================================
step "STEP 3: Preparing deployment package..."

DEPLOY_DIR="deploy_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$DEPLOY_DIR"

# Copy backend
cp -r server "$DEPLOY_DIR/"
rm -rf "$DEPLOY_DIR/server/node_modules"
rm -f "$DEPLOY_DIR/server/.env"

# Copy frontend build
cp -r interface/dist "$DEPLOY_DIR/interface-dist"

# Copy deployment configs
cp docker-compose.prod.yml "$DEPLOY_DIR/" 2>/dev/null || warn "docker-compose.prod.yml not found"
cp docs/DEPLOYMENT_NEXUS33.md "$DEPLOY_DIR/README.md" 2>/dev/null || true

# Create deployment info
cat > "$DEPLOY_DIR/deploy_info.json" << EOF
{
    "deployedAt": "$(date -Iseconds)",
    "branch": "$BRANCH",
    "commit": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')",
    "host": "$DEPLOY_HOST"
}
EOF

# Create archive
ARCHIVE_NAME="nexus33_deploy_$(date +%Y%m%d_%H%M%S).tar.gz"
tar -czf "$ARCHIVE_NAME" -C "$DEPLOY_DIR" .

echo "✓ Deployment package created: $ARCHIVE_NAME"

# Cleanup temp directory
rm -rf "$DEPLOY_DIR"

# ===========================================
# STEP 4: Deploy to server (if accessible)
# ===========================================
step "STEP 4: Deployment..."

if [ "$1" == "--local" ]; then
    echo "Local build only. Skipping remote deployment."
    echo "Archive ready: $ARCHIVE_NAME"
    exit 0
fi

# Check SSH connectivity
if ssh -o ConnectTimeout=5 -o BatchMode=yes "${DEPLOY_USER}@${DEPLOY_HOST}" "echo 1" >/dev/null 2>&1; then
    echo "SSH connection established to ${DEPLOY_HOST}"
    
    # Upload archive
    scp "$ARCHIVE_NAME" "${DEPLOY_USER}@${DEPLOY_HOST}:/tmp/"
    
    # Execute remote deployment
    ssh "${DEPLOY_USER}@${DEPLOY_HOST}" << REMOTE_SCRIPT
        set -e
        
        echo "Creating backup..."
        if [ -d "${DEPLOY_PATH}" ]; then
            sudo cp -r "${DEPLOY_PATH}" "${DEPLOY_PATH}_backup_\$(date +%Y%m%d_%H%M%S)"
        fi
        
        echo "Extracting new version..."
        sudo mkdir -p "${DEPLOY_PATH}"
        sudo tar -xzf "/tmp/${ARCHIVE_NAME}" -C "${DEPLOY_PATH}"
        
        echo "Installing backend dependencies..."
        cd "${DEPLOY_PATH}/server"
        npm ci --production
        
        echo "Setting up frontend..."
        sudo mkdir -p /var/www/nexus33-frontend
        sudo cp -r "${DEPLOY_PATH}/interface-dist/"* /var/www/nexus33-frontend/
        
        echo "Restarting services..."
        sudo pm2 restart nexus33-backend || sudo pm2 start npm --name "nexus33-backend" -- start
        
        echo "Cleanup..."
        rm -f "/tmp/${ARCHIVE_NAME}"
        
        echo "✓ Remote deployment complete!"
REMOTE_SCRIPT

    echo -e "${GREEN}✓ Deployment to ${DEPLOY_HOST} completed successfully!${NC}"
    
else
    warn "Cannot connect to ${DEPLOY_HOST} via SSH"
    echo "Archive is ready for manual deployment: $ARCHIVE_NAME"
    echo ""
    echo "Manual deployment steps:"
    echo "1. Copy $ARCHIVE_NAME to your server"
    echo "2. Extract: tar -xzf $ARCHIVE_NAME -C /var/www/nexus33"
    echo "3. Install deps: cd /var/www/nexus33/server && npm ci --production"
    echo "4. Copy frontend: cp -r interface-dist/* /var/www/nexus33-frontend/"
    echo "5. Restart: pm2 restart nexus33-backend"
fi

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     DEPLOYMENT SUMMARY                         ║${NC}"
echo -e "${BLUE}╠════════════════════════════════════════════════╣${NC}"
echo -e "${BLUE}║ Archive: ${ARCHIVE_NAME}"
echo -e "${BLUE}║ Frontend: Built ✓"
echo -e "${BLUE}║ Backend: Packaged ✓"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"
