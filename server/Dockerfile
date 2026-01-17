# ═══════════════════════════════════════════════════════════════════
# Th3 Thirty3 - Server Dockerfile (OPTIMIZED)
# Slim image with optimized layers
# ═══════════════════════════════════════════════════════════════════

FROM node:20-slim

# Métadonnées
LABEL maintainer="th3-thirty3"
LABEL description="Th3 Thirty3 Backend Server"
LABEL version="2.0"

# Variables d'environnement
ENV NODE_ENV=production
ENV PORT=3000

WORKDIR /app

# ───────────────────────────────────────────────────────────────────
# LAYER 1: Dépendances système (change rarement)
# Tout en une seule layer avec nettoyage
# ───────────────────────────────────────────────────────────────────
RUN apt-get update && \
  apt-get install -y --no-install-recommends \
  wget \
  ca-certificates \
  curl \
  gnupg \
  && install -m 0755 -d /etc/apt/keyrings \
  && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
  && chmod a+r /etc/apt/keyrings/docker.gpg \
  && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(grep -oP '(?<=VERSION_CODENAME=)\w+' /etc/os-release) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
  && apt-get update \
  && apt-get install -y --no-install-recommends docker-ce-cli \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# ───────────────────────────────────────────────────────────────────
# LAYER 2: Dépendances Node.js (change parfois)
# ───────────────────────────────────────────────────────────────────
COPY package*.json ./
RUN npm install --only=production && \
  npm cache clean --force

# ───────────────────────────────────────────────────────────────────
# LAYER 3: Code source (change souvent)
# ───────────────────────────────────────────────────────────────────
COPY . .

# Créer les répertoires nécessaires
RUN mkdir -p /app/data /app/data/lancedb /app/logs

# Sécurité: Running as root to allow Docker socket access
# In production with more strict security contexts, we would use a docker group mapped to host.
# RUN groupadd -r appuser && useradd -r -g appuser appuser && \
#   chown -R appuser:appuser /app
# USER appuser

EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

CMD ["node", "index.js"]
