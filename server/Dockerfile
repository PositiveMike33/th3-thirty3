# Th3 Thirty3 - Server Dockerfile
# Using slim instead of alpine for LanceDB native binary compatibility
FROM node:20-slim

# Install required system dependencies for native modules
RUN apt-get update && apt-get install -y \
  wget \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (including native binaries)
RUN npm ci --only=production

# Copy application code
COPY . .

# Create data directory for persistent storage
RUN mkdir -p /app/data /app/data/lancedb

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

# Start the server
CMD ["node", "index.js"]
