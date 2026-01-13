# Kali Linux + TOR Container for Th3 Thirty3
# Provides anonymous network operations for OSINT and Hacking agents

FROM kalilinux/kali-rolling:latest

LABEL maintainer="Th3 Thirty3"
LABEL description="Kali Linux with TOR for anonymous operations"

# Update and install essential tools
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    # TOR and networking
    tor \
    torsocks \
    proxychains4 \
    net-tools \
    curl \
    wget \
    # Basic hacking tools
    nmap \
    nikto \
    dirb \
    gobuster \
    sqlmap \
    hydra \
    john \
    # Scripting
    python3 \
    python3-pip \
    nodejs \
    npm \
    # Utilities
    jq \
    vim \
    git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Configure TOR
RUN echo "SocksPort 0.0.0.0:9050" >> /etc/tor/torrc && \
    echo "ControlPort 9051" >> /etc/tor/torrc && \
    echo "CookieAuthentication 0" >> /etc/tor/torrc && \
    echo "HashedControlPassword 16:872860B76453A77D60CA2BB8C1A7042072093276A3D701A41A87CEA6FF" >> /etc/tor/torrc

# Configure proxychains to use TOR
RUN sed -i 's/^socks4.*/socks5 127.0.0.1 9050/' /etc/proxychains4.conf

# Create working directory
WORKDIR /opt/th3thirty3

# Copy API server script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose TOR SOCKS port and control port
EXPOSE 9050 9051

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s \
    CMD curl -s --socks5 localhost:9050 https://check.torproject.org/api/ip | grep -q '"IsTor":true' || exit 1

# Start TOR and keep container running
ENTRYPOINT ["/entrypoint.sh"]
