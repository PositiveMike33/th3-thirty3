# =====================================================
# Th3 Thirty3 / Nexus33 - Production Environment Template
# =====================================================
# Copy this file to .env and fill in your values
# This is the COMPLETE configuration for production deployment
#
# IMPORTANT: Fill in your ACTUAL values before deployment!
# =====================================================

# ===========================================
# Server Configuration
# ===========================================
NODE_ENV=production
PORT=3000

# Production URLs (for nexus33.io deployment)
API_BASE_URL=https://api.nexus33.io
FRONTEND_URL=https://nexus33.io

# CORS Origins (production)
CORS_ORIGINS=https://nexus33.io,https://www.nexus33.io,https://api.nexus33.io

# ===========================================
# Database
# ===========================================
MONGODB_URI=mongodb://localhost:27017/nexus33

# ===========================================
# Authentication
# ===========================================
# IMPORTANT: Generate a strong secret for production!
# Use: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
JWT_SECRET=CHANGE_THIS_TO_A_STRONG_SECRET_IN_PRODUCTION

# ===========================================
# Ollama Configuration
# ===========================================
OLLAMA_BASE_URL=http://localhost:11434

# ===========================================
# Google OAuth & APIs
# ===========================================
# Get these from: https://console.developers.google.com
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=https://api.nexus33.io/auth/google/callback

# ===========================================
# Stripe (Payments)
# ===========================================
# Get keys from: https://dashboard.stripe.com/apikeys
STRIPE_SECRET_KEY=sk_live_your_stripe_key
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret
STRIPE_PRICE_ID_STARTER=price_starter
STRIPE_PRICE_ID_PRO=price_pro
STRIPE_PRICE_ID_ENTERPRISE=price_enterprise

# ===========================================
# PayPal (Payments)
# ===========================================
PAYPAL_CLIENT_ID=your-paypal-client-id
PAYPAL_CLIENT_SECRET=your-paypal-client-secret
PAYPAL_MODE=live

# ===========================================
# AIKIDO SECURITY INTEGRATION
# ===========================================
# Get your API token from: https://app.aikido.dev/settings/api-tokens
# Required scopes: read:issues, read:repos, read:compliance
#
# To generate a new token:
# 1. Go to https://app.aikido.dev
# 2. Navigate to Settings -> API Tokens
# 3. Create a new token with appropriate scopes
# 4. Copy the token here
AIKIDO_API_TOKEN=your_aikido_api_token_here

# Legacy OAuth (if using OAuth flow instead of API token)
AIKIDO_CLIENT_ID=your-aikido-client-id
AIKIDO_CLIENT_SECRET=your-aikido-client-secret

# ===========================================
# Shodan (Security Scanning)
# ===========================================
# Get API key from: https://account.shodan.io
SHODAN_API_KEY=your-shodan-api-key

# ===========================================
# Dart AI (Project Management)
# ===========================================
# Get API key from: https://app.itsdart.com/settings/developer
DART_API_KEY=your-dart-api-key

# ===========================================
# AnythingLLM Integration
# ===========================================
ANYTHING_LLM_URL=http://localhost:3001
ANYTHING_LLM_KEY=your-anythingllm-api-key

# ===========================================
# Perplexity AI (Web Search)
# ===========================================
PERPLEXITY_API_KEY=your-perplexity-api-key

# ===========================================
# OpenAI (Optional - Fallback)
# ===========================================
OPENAI_API_KEY=your-openai-key

# ===========================================
# Anthropic (Optional - Fallback)
# ===========================================
ANTHROPIC_API_KEY=your-anthropic-key

# ===========================================
# Email (SMTP for notifications)
# ===========================================
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# ===========================================
# Kraken (Crypto Finance)
# ===========================================
KRAKEN_API_KEY=your-kraken-key
KRAKEN_API_SECRET=your-kraken-secret

# ===========================================
# VPN/TOR (Anonymization)
# ===========================================
TOR_SOCKS_PORT=9050
TOR_CONTROL_PORT=9051
PROTONVPN_USER=your-protonvpn-user
PROTONVPN_PASS=your-protonvpn-pass

# ===========================================
# Obsidian Integration
# ===========================================
OBSIDIAN_VAULT_PATH=C:/path/to/your/obsidian/vault

# ===========================================
# MCP (Model Context Protocol)
# ===========================================
PIECES_MCP_URL=http://localhost:39300/model_context_protocol/2024-11-05/sse

# ===========================================
# CLOUDFLARE TUNNEL (Auto-configured)
# ===========================================
# These are automatically managed by cloudflared
# CLOUDFLARE_TUNNEL_ID is set when you create the tunnel
CLOUDFLARE_TUNNEL_NAME=nexus33
CLOUDFLARE_DOMAIN=nexus33.io
