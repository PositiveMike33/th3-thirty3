# ═══════════════════════════════════════════════════════════════════
# Th3 Thirty3 - Frontend Dockerfile (OPTIMIZED)
# Multi-stage build for minimal production image
# ═══════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────
# STAGE 1: BUILD (temporaire, sera jeté)
# ───────────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# 1. Dépendances d'abord (cache optimal)
COPY package*.json ./
RUN npm ci --only=production=false

# 2. Code source en dernier
COPY . .

# 3. Build
RUN npm run build

# ───────────────────────────────────────────────────────────────────
# STAGE 2: PRODUCTION (image finale minimale)
# ───────────────────────────────────────────────────────────────────
FROM nginx:alpine

# Copier uniquement le build
COPY --from=builder /app/dist /usr/share/nginx/html

# Config nginx pour SPA
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Sécurité: utilisateur non-root
RUN chown -R nginx:nginx /usr/share/nginx/html && \
    chmod -R 755 /usr/share/nginx/html

EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -q --spider http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
