# HackerGPT Kali - Advanced Pentesting Container
# Full Kali Linux with enhanced hacking toolkit for AI-assisted security research

FROM kalilinux/kali-rolling:latest

LABEL maintainer="Th3 Thirty3"
LABEL description="HackerGPT Kali - AI-Powered Pentesting Environment"
LABEL version="1.0.0"

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/Montreal

# Update system and install core tools
RUN apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y

# =============================================================================
# NETWORKING & ANONYMITY
# =============================================================================
RUN apt-get install -y \
    tor \
    torsocks \
    proxychains4 \
    net-tools \
    iproute2 \
    iputils-ping \
    dnsutils \
    whois \
    curl \
    wget \
    netcat-openbsd \
    socat \
    openvpn \
    wireguard-tools

# =============================================================================
# RECONNAISSANCE & OSINT
# =============================================================================
RUN apt-get install -y \
    nmap \
    masscan \
    recon-ng \
    theharvester \
    sublist3r \
    amass \
    dnsrecon \
    dnsenum \
    fierce \
    whatweb

# =============================================================================
# WEB APPLICATION TESTING
# =============================================================================
RUN apt-get install -y \
    nikto \
    dirb \
    dirbuster \
    gobuster \
    ffuf \
    wfuzz \
    sqlmap \
    burpsuite \
    zaproxy \
    wpscan \
    commix

# =============================================================================
# PASSWORD ATTACKS
# =============================================================================
RUN apt-get install -y \
    hydra \
    john \
    hashcat \
    hashid \
    hash-identifier \
    crunch \
    cewl \
    wordlists

# =============================================================================
# EXPLOITATION
# =============================================================================
RUN apt-get install -y \
    metasploit-framework \
    exploitdb \
    searchsploit \
    msfpc

# =============================================================================
# WIRELESS & NETWORK ATTACKS
# =============================================================================
RUN apt-get install -y \
    aircrack-ng \
    wifite \
    bettercap \
    ettercap-common \
    arpwatch \
    macchanger

# =============================================================================
# REVERSE ENGINEERING & FORENSICS
# =============================================================================
RUN apt-get install -y \
    gdb \
    radare2 \
    binwalk \
    foremost \
    volatility3 \
    sleuthkit \
    autopsy \
    exiftool

# =============================================================================
# PROGRAMMING & SCRIPTING
# =============================================================================
RUN apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    nodejs \
    npm \
    ruby \
    ruby-dev \
    golang-go \
    rustc \
    cargo \
    build-essential \
    cmake \
    git \
    vim \
    nano \
    jq \
    tmux \
    screen

# =============================================================================
# SOCIAL ENGINEERING TOOLS
# =============================================================================
RUN apt-get install -y \
    setoolkit

# =============================================================================
# PYTHON SECURITY LIBRARIES
# =============================================================================
RUN pip3 install --break-system-packages \
    requests \
    beautifulsoup4 \
    lxml \
    shodan \
    pwntools \
    scapy \
    paramiko \
    impacket \
    ldap3 \
    dnspython \
    python-nmap \
    censys \
    builtwith \
    python-whois \
    aiodnsbrute

# =============================================================================
# SHERLOCK (OSINT USERNAME HUNTER)
# =============================================================================
RUN git clone https://github.com/sherlock-project/sherlock.git /opt/sherlock && \
    cd /opt/sherlock && pip3 install --break-system-packages -r requirements.txt

# =============================================================================
# ADDITIONAL TOOLS
# =============================================================================
RUN git clone https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r && \
    cd /opt/Sublist3r && pip3 install --break-system-packages -r requirements.txt

RUN git clone https://github.com/laramies/theHarvester.git /opt/theHarvester && \
    cd /opt/theHarvester && pip3 install --break-system-packages -r requirements.txt

# =============================================================================
# CLEANUP
# =============================================================================
RUN apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# =============================================================================
# TOR CONFIGURATION
# =============================================================================
RUN echo "SocksPort 0.0.0.0:9050" >> /etc/tor/torrc && \
    echo "ControlPort 9051" >> /etc/tor/torrc && \
    echo "CookieAuthentication 0" >> /etc/tor/torrc && \
    echo "HashedControlPassword 16:872860B76453A77D60CA2BB8C1A7042072093276A3D701A41A87CEA6FF" >> /etc/tor/torrc

# Configure proxychains to use TOR
RUN sed -i 's/^socks4.*/socks5 127.0.0.1 9050/' /etc/proxychains4.conf

# =============================================================================
# ENVIRONMENT SETUP
# =============================================================================
ENV PATH="/opt/sherlock:/opt/Sublist3r:/opt/theHarvester:${PATH}"

WORKDIR /opt/hackergpt

# Create entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose ports
# 9050: TOR SOCKS5
# 9051: TOR Control
# 4444: Metasploit default listener
# 8080: Web proxy
EXPOSE 9050 9051 4444 8080

# Health check
HEALTHCHECK --interval=60s --timeout=15s --start-period=120s \
    CMD curl -s --socks5 localhost:9050 https://check.torproject.org/api/ip | grep -q '"IsTor":true' || exit 1

ENTRYPOINT ["/entrypoint.sh"]
