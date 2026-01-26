/**
 * HexStrike Expert Agents Service
 * 
 * Agents experts spécialisés pour chaque outil HexStrike (150+)
 * Chaque agent est un expert absolu de son outil avec:
 * - Connaissance complète des paramètres
 * - Techniques d'évasion
 * - Stratégies de défense correspondantes
 * - Intégration avec le container Kali
 */

const fs = require('fs');
const path = require('path');
const LLMService = require('./llm_service');
const hexstrikeBridge = require('./hexstrike_bridge');

class HexStrikeExpertAgentsService {
    constructor() {
        this.dataPath = path.join(__dirname, 'data', 'hexstrike_experts');
        this.llmService = new LLMService();
        this.agents = new Map();
        this.categories = new Map();

        this.ensureDataFolder();
        this.initializeAgents();

        console.log(`[HEXSTRIKE-EXPERTS] ✅ Service initialized with ${this.agents.size} tool experts`);
    }

    ensureDataFolder() {
        if (!fs.existsSync(this.dataPath)) {
            fs.mkdirSync(this.dataPath, { recursive: true });
        }
    }

    /**
     * Configuration complète des agents experts HexStrike par catégorie
     */
    getToolExpertConfigs() {
        return {
            // ==========================================
            // 🔍 RECONNAISSANCE & SCANNING
            // ==========================================
            nmap: {
                name: 'Nmap Master',
                emoji: '🔬',
                category: 'Reconnaissance',
                tool: 'nmap',
                description: 'Expert scanning réseau, ports, services, OS detection',
                commands: ['nmap -sS -sV -O', 'nmap -sC -sV', 'nmap -p- -T4', 'nmap --script vuln'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Nmap dans HexStrike.
MAÎTRISE COMPLÈTE:
- Scan Types: -sS (SYN stealth), -sT (TCP), -sU (UDP), -sN/sF/sX (NULL/FIN/Xmas)
- Detection: -O (OS), -sV (version), -A (aggressive), --script (NSE)
- Timing: -T0 (paranoid) à -T5 (insane), --scan-delay, --max-rate
- Évasion: -f (fragment), -D (decoy), --source-port, --data-length
- Scripts NSE: vuln, exploit, brute, discovery, malware
- Output: -oN, -oX, -oG, -oA pour tous les formats
DÉFENSE: Comment détecter chaque type de scan, règles IDS/IPS`
            },

            masscan: {
                name: 'Masscan Expert',
                emoji: '⚡',
                category: 'Reconnaissance',
                tool: 'masscan',
                description: 'Scanning ultra-rapide Internet-scale',
                commands: ['masscan -p80,443 0.0.0.0/0 --rate 10000', 'masscan --banners'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Masscan dans HexStrike.
MAÎTRISE: Scanning 10M paquets/sec, async, banners
OPTIONS: --rate, --excludefile, --wait, --adapter-ip
OUTPUT: -oL, -oX, -oG, -oJ
BANNERS: --banners pour capture de bannières
DÉFENSE: Rate limiting, traffic shaping, blackholing`
            },

            rustscan: {
                name: 'RustScan Expert',
                emoji: '🦀',
                category: 'Reconnaissance',
                tool: 'rustscan',
                description: 'Port scanning ultra-rapide avec intégration Nmap',
                commands: ['rustscan -a target', 'rustscan -a target -- -sC -sV'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de RustScan dans HexStrike.
MAÎTRISE: Scan 65535 ports en <3 secondes, pipeline vers Nmap
OPTIONS: --ulimit, -b (batch), --timeout, --tries
NMAP INTEGRATION: -- suivi des options nmap
DÉFENSE: Détection par volume de connexions SYN`
            },

            // ==========================================
            // 🌐 SUBDOMAIN & DNS ENUMERATION
            // ==========================================
            amass: {
                name: 'Amass Expert',
                emoji: '🕸️',
                category: 'DNS & Subdomain',
                tool: 'amass',
                description: 'Enumération subdomains passive et active',
                commands: ['amass enum -d domain.com', 'amass intel -whois -d domain.com'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Amass dans HexStrike.
MODES: enum (enumération), intel (intelligence), viz (visualisation)
SOURCES: ASN, BGP, DNS, Reverse DNS, WHOIS, APIs
PASSIVE: Totalement silencieux, APIs publiques
ACTIVE: Brute force, zone transfers, permutations
CONFIG: config.ini pour API keys (Shodan, VirusTotal, etc.)
DÉFENSE: Monitoring DNS queries, rate limiting APIs`
            },

            subfinder: {
                name: 'Subfinder Expert',
                emoji: '🔎',
                category: 'DNS & Subdomain',
                tool: 'subfinder',
                description: 'Découverte de subdomains passive',
                commands: ['subfinder -d domain.com -all', 'subfinder -dL domains.txt'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Subfinder dans HexStrike.
MAÎTRISE: Découverte passive, APIs multiples, JSON output
OPTIONS: -all (all sources), -recursive, -nW (no wildcard)
SOURCES: CertSpotter, DNSdumpster, Shodan, VirusTotal, etc.
CONFIG: ~/.config/subfinder/provider-config.yaml
DÉFENSE: Certificate transparency monitoring`
            },

            // ==========================================
            // 🌍 WEB RECONNAISSANCE
            // ==========================================
            httpx: {
                name: 'HTTPX Expert',
                emoji: '📡',
                category: 'Web Reconnaissance',
                tool: 'httpx',
                description: 'HTTP probing et tech detection',
                commands: ['httpx -l urls.txt -tech-detect', 'httpx -sc -title -td'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de HTTPX dans HexStrike.
PROBING: Validation HTTP/HTTPS, status codes, redirects
DETECTION: -tech-detect, -title, -server, -content-length
OUTPUT: -json, -csv, -o pour fichiers
MATCHING: -mc (match code), -ml (match length), -ms (match string)
DÉFENSE: WAF detection, fingerprinting protection`
            },

            katana: {
                name: 'Katana Expert',
                emoji: '🗡️',
                category: 'Web Reconnaissance',
                tool: 'katana',
                description: 'Web crawling nouvelle génération',
                commands: ['katana -u url -jc -d 3', 'katana -u url -f form-fields'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Katana dans HexStrike.
CRAWLING: JavaScript crawling, headless browser, form extraction
DEPTH: -d (depth), -delay, -concurrency
EXTRACTION: -jc (JS crawl), -f (fields), -ef (extension filter)
HEADLESS: Chrome/Chromium pour JS rendering
DÉFENSE: Bot detection, rate limiting, CAPTCHA`
            },

            gau: {
                name: 'GAU Expert',
                emoji: '📚',
                category: 'Web Reconnaissance',
                tool: 'gau',
                description: 'URLs historiques depuis archives',
                commands: ['gau domain.com', 'gau --subs domain.com'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de GAU (GetAllUrls) dans HexStrike.
SOURCES: Wayback Machine, Common Crawl, URLScan, AlienVault OTX
OPTIONS: --subs, --providers, --blacklist
FILTRAGE: Extensions, patterns, deduplication
DÉFENSE: Robots.txt noarchive, monitoring archives`
            },

            waybackurls: {
                name: 'Wayback Expert',
                emoji: '⏰',
                category: 'Web Reconnaissance',
                tool: 'waybackurls',
                description: 'URLs depuis Internet Archive',
                commands: ['waybackurls domain.com', 'echo domain.com | waybackurls'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Waybackurls dans HexStrike.
SOURCE: Wayback Machine API
USAGE: stdin/stdout, pipe-friendly
DEDUP: Résultats uniques automatiques
HISTORIQUE: Découverte d'anciens endpoints, fichiers supprimés
DÉFENSE: robots.txt noarchive directive`
            },

            // ==========================================
            // 📂 DIRECTORY & FILE DISCOVERY
            // ==========================================
            gobuster: {
                name: 'Gobuster Expert',
                emoji: '🔨',
                category: 'Web Discovery',
                tool: 'gobuster',
                description: 'Brute force directories et fichiers',
                commands: ['gobuster dir -u url -w wordlist', 'gobuster dns -d domain -w wordlist'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Gobuster dans HexStrike.
MODES: dir, dns, vhost, fuzz, s3, gcs, tftp
OPTIONS: -w (wordlist), -x (extensions), -t (threads)
WORDLISTS: SecLists, dirb, dirbuster
FILTERING: -b (blacklist status), -s (whitelist status)
DÉFENSE: Rate limiting, WAF rules, directory protection`
            },

            feroxbuster: {
                name: 'Feroxbuster Expert',
                emoji: '🦾',
                category: 'Web Discovery',
                tool: 'feroxbuster',
                description: 'Directory brute force récursif',
                commands: ['feroxbuster -u url -w wordlist', 'feroxbuster -u url --smart'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Feroxbuster dans HexStrike.
RÉCURSIF: Exploration automatique des sous-répertoires
OPTIONS: -w, -x, -t, --depth, --smart
SMART: Détection automatique d'extensions valides
RESUME: --resume-from pour reprendre scans
DÉFENSE: Anti brute-force, progressive delays`
            },

            ffuf: {
                name: 'FFUF Expert',
                emoji: '🎯',
                category: 'Web Discovery',
                tool: 'ffuf',
                description: 'Fast web fuzzer',
                commands: ['ffuf -u url/FUZZ -w wordlist', 'ffuf -u url -X POST -d "param=FUZZ"'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de FFUF dans HexStrike.
FUZZING: FUZZ keyword, multiple positions
METHODS: GET, POST, PUT, headers, cookies
FILTERING: -fc, -fs, -fw, -fl, -fr (regex)
MATCHING: -mc, -ms, -mw, -ml, -mr
RECURSION: -recursion, -recursion-depth
DÉFENSE: WAF evasion, request throttling`
            },

            dirsearch: {
                name: 'Dirsearch Expert',
                emoji: '🔍',
                category: 'Web Discovery',
                tool: 'dirsearch',
                description: 'Directory brute forcer classique',
                commands: ['dirsearch -u url -e php,html,js', 'dirsearch -l urls.txt'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Dirsearch dans HexStrike.
EXTENSIONS: -e pour extensions spécifiques
THREADS: -t pour parallélisation
WORDLISTS: Intégrée + custom
RECURSIVE: -r pour récursion
DÉFENSE: Rate limiting, 403 bypass techniques`
            },

            // ==========================================
            // 🎯 PARAMETER DISCOVERY
            // ==========================================
            arjun: {
                name: 'Arjun Expert',
                emoji: '🏹',
                category: 'Parameter Discovery',
                tool: 'arjun',
                description: 'Découverte de paramètres HTTP',
                commands: ['arjun -u url', 'arjun -u url -m POST'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Arjun dans HexStrike.
DISCOVERY: GET, POST, JSON, XML parameters
TECHNIQUES: Heuristic, brute force, passive
OPTIONS: -m (method), -w (wordlist), -t (threads)
STABLE: --stable pour éviter rate limiting
DÉFENSE: Parameter whitelisting, input validation`
            },

            paramspider: {
                name: 'ParamSpider Expert',
                emoji: '🕷️',
                category: 'Parameter Discovery',
                tool: 'paramspider',
                description: 'Mining de paramètres depuis archives',
                commands: ['paramspider -d domain.com', 'paramspider -d domain.com --level high'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de ParamSpider dans HexStrike.
MINING: Wayback Machine, Common Crawl
LEVELS: basic, medium, high pour profondeur
OUTPUT: Paramètres uniques par endpoint
DÉFENSE: Archive sanitization, parameter hardening`
            },

            x8: {
                name: 'X8 Expert',
                emoji: '❌',
                category: 'Parameter Discovery',
                tool: 'x8',
                description: 'Hidden parameter discovery',
                commands: ['x8 -u url -w wordlist', 'x8 -u url --json'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de X8 dans HexStrike.
HIDDEN: Paramètres cachés, non documentés
TECHNIQUES: Response comparison, timing
WORDLIST: SecLists, custom params
DÉFENSE: Parameter hardening, logging`
            },

            // ==========================================
            // 🔓 VULNERABILITY SCANNING
            // ==========================================
            nuclei: {
                name: 'Nuclei Expert',
                emoji: '☢️',
                category: 'Vulnerability Scanning',
                tool: 'nuclei',
                description: 'Scanning de vulnérabilités basé templates',
                commands: ['nuclei -u url -t cves/', 'nuclei -l urls.txt -severity critical,high'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Nuclei dans HexStrike.
TEMPLATES: CVEs, misconfigs, exposures, takeovers
SEVERITY: info, low, medium, high, critical
TAGS: rce, sqli, xss, ssrf, lfi, xxe, etc.
CUSTOM: Écriture de templates YAML
UPDATE: nuclei -ut pour mise à jour templates
DÉFENSE: Pattern detection, response monitoring`
            },

            nikto: {
                name: 'Nikto Expert',
                emoji: '🔧',
                category: 'Vulnerability Scanning',
                tool: 'nikto',
                description: 'Web server scanner classique',
                commands: ['nikto -h url', 'nikto -h url -Tuning x'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Nikto dans HexStrike.
TESTS: 6700+ vulnerability checks
TUNING: -Tuning pour types de tests
SSL: -ssl, -port pour HTTPS
PLUGINS: Extensible via plugins Perl
DÉFENSE: WAF, server hardening`
            },

            jaeles: {
                name: 'Jaeles Expert',
                emoji: '⚔️',
                category: 'Vulnerability Scanning',
                tool: 'jaeles',
                description: 'Scanner de vulnérabilités automatisé',
                commands: ['jaeles scan -u url -s signatures/', 'jaeles server'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Jaeles dans HexStrike.
SIGNATURES: YAML-based, fuzzing, passive
MODES: scan, server (API mode)
PARALLEL: Multi-threading efficace
CUSTOM: Écriture de signatures custom
DÉFENSE: Signature detection, behavioral analysis`
            },

            dalfox: {
                name: 'Dalfox Expert',
                emoji: '🦊',
                category: 'Vulnerability Scanning',
                tool: 'dalfox',
                description: 'Scanner XSS spécialisé',
                commands: ['dalfox url url', 'dalfox file urls.txt'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Dalfox dans HexStrike.
XSS: Reflected, DOM-based, Stored detection
MINING: --mining-dom, --mining-dict
BLIND: --blind pour blind XSS
VERIFICATION: PoC generation automatique
DÉFENSE: CSP, X-XSS-Protection, sanitization`
            },

            // ==========================================
            // 💉 EXPLOITATION
            // ==========================================
            sqlmap: {
                name: 'SQLMap Expert',
                emoji: '💾',
                category: 'Exploitation',
                tool: 'sqlmap',
                description: 'Injection SQL automatisée',
                commands: ['sqlmap -u url --dbs', 'sqlmap -r request.txt --level 5 --risk 3'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de SQLMap dans HexStrike.
TECHNIQUES: UNION, blind, error-based, stacked, time-based
ENUMERATION: --dbs, --tables, --columns, --dump
SHELLS: --os-shell, --os-cmd, --sql-shell
TAMPER: space2comment, between, randomcase, charencode
WAF BYPASS: --tamper, --random-agent, --delay
DÉFENSE: Prepared statements, WAF, input validation`
            },

            metasploit: {
                name: 'Metasploit Expert',
                emoji: '💉',
                category: 'Exploitation',
                tool: 'msfconsole',
                description: 'Framework d\'exploitation complet',
                commands: ['msfconsole', 'use exploit/', 'set PAYLOAD', 'exploit'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Metasploit dans HexStrike.
MODULES: exploit/, auxiliary/, post/, payload/, encoder/
METERPRETER: getsystem, hashdump, migrate, portfwd
PAYLOADS: reverse_tcp, bind_tcp, meterpreter, shell
ENCODING: msfvenom pour génération payloads
ÉVASION: Templates, encoders, custom payloads
DÉFENSE: EDR, behavioral analysis, network monitoring`
            },

            // ==========================================
            // 🔑 PASSWORD ATTACKS
            // ==========================================
            hydra: {
                name: 'Hydra Expert',
                emoji: '🐉',
                category: 'Password Attacks',
                tool: 'hydra',
                description: 'Brute force réseau multi-protocoles',
                commands: ['hydra -l user -P wordlist ssh://target', 'hydra -L users -P pass http-form-post://'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Hydra dans HexStrike.
PROTOCOLES: SSH, FTP, HTTP, SMB, RDP, MySQL, PostgreSQL, etc.
MODES: -l/-L (user), -p/-P (pass), -C (combo)
HTTP: http-form-post, http-form-get, http-basic
THREADS: -t (tasks), -w (timeout)
DÉFENSE: Account lockout, fail2ban, rate limiting`
            },

            john: {
                name: 'John Expert',
                emoji: '🔓',
                category: 'Password Attacks',
                tool: 'john',
                description: 'Cracking de mots de passe CPU',
                commands: ['john hash.txt', 'john --wordlist=rockyou.txt hash.txt'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de John the Ripper dans HexStrike.
FORMATS: --format= pour type de hash
WORDLISTS: --wordlist, règles --rules
MODES: single, wordlist, incremental
SHOW: --show pour afficher crackés
DÉFENSE: Salts forts, algorithmes modernes, KDF`
            },

            hashcat: {
                name: 'Hashcat Expert',
                emoji: '⚡',
                category: 'Password Attacks',
                tool: 'hashcat',
                description: 'Cracking GPU ultra-rapide',
                commands: ['hashcat -m 0 hash.txt wordlist.txt', 'hashcat -a 3 hash.txt ?a?a?a?a'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Hashcat dans HexStrike.
MODES: -m pour type de hash (0=MD5, 1000=NTLM, etc.)
ATTACKS: -a 0 (dict), -a 1 (combo), -a 3 (brute), -a 6/7 (hybrid)
MASKS: ?l, ?u, ?d, ?s, ?a pour patterns
RULES: -r pour règles de mutations
GPU: Utilisation maximale du GPU
DÉFENSE: Argon2, bcrypt, délais progressifs`
            },

            // ==========================================
            // 📡 NETWORK ANALYSIS
            // ==========================================
            wireshark: {
                name: 'Wireshark Expert',
                emoji: '🦈',
                category: 'Network Analysis',
                tool: 'wireshark/tshark',
                description: 'Analyse de paquets réseau',
                commands: ['tshark -i eth0', 'tshark -r capture.pcap -Y "http"'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Wireshark/TShark dans HexStrike.
CAPTURE: Interfaces, filtres de capture
FILTRES: Display filters (http, tcp, dns, etc.)
ANALYSE: Follow stream, statistics, conversations
EXPORT: Objets, JSON, CSV
DÉFENSE: Encryption, traffic obfuscation`
            },

            tcpdump: {
                name: 'Tcpdump Expert',
                emoji: '📶',
                category: 'Network Analysis',
                tool: 'tcpdump',
                description: 'Capture de paquets CLI',
                commands: ['tcpdump -i eth0', 'tcpdump -w capture.pcap'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Tcpdump dans HexStrike.
CAPTURE: -i (interface), -w (write), -r (read)
FILTRES: host, port, net, proto
VERBOSITY: -v, -vv, -vvv
OPTIONS: -n (no resolve), -X (hex+ASCII)
DÉFENSE: Encrypted traffic, VPN tunnels`
            },

            // ==========================================
            // 🕵️ OSINT
            // ==========================================
            sherlock: {
                name: 'Sherlock Expert',
                emoji: '🕵️',
                category: 'OSINT',
                tool: 'sherlock',
                description: 'Recherche de usernames sur 300+ sites',
                commands: ['sherlock username', 'sherlock -o results.txt username'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Sherlock dans HexStrike.
SITES: 300+ réseaux sociaux et plateformes
OUTPUT: -o pour fichier, --csv, --json
OPTIONS: --timeout, --site pour sites spécifiques
DÉFENSE: Monitoring d'usurpation d'identité`
            },

            theharvester: {
                name: 'TheHarvester Expert',
                emoji: '🌾',
                category: 'OSINT',
                tool: 'theHarvester',
                description: 'Collecte emails et subdomains',
                commands: ['theHarvester -d domain.com -b all', 'theHarvester -d domain.com -l 500'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de TheHarvester dans HexStrike.
SOURCES: Google, Bing, LinkedIn, Shodan, DNS
DATA: Emails, noms, subdomains, IPs
OPTIONS: -b (sources), -l (limit), -d (domain)
DÉFENSE: Email harvesting protection, DMARC`
            },

            // ==========================================
            // ☁️ CLOUD SECURITY
            // ==========================================
            prowler: {
                name: 'Prowler Expert',
                emoji: '🦉',
                category: 'Cloud Security',
                tool: 'prowler',
                description: 'Audit sécurité AWS/Azure/GCP',
                commands: ['prowler aws', 'prowler azure --subscription-id xxx'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Prowler dans HexStrike.
PROVIDERS: AWS, Azure, GCP
CHECKS: CIS Benchmarks, security best practices
OUTPUT: JSON, CSV, HTML reports
COMPLIANCE: PCI-DSS, HIPAA, GDPR checks
DÉFENSE: Cloud security posture management`
            },

            trivy: {
                name: 'Trivy Expert',
                emoji: '🐋',
                category: 'Cloud Security',
                tool: 'trivy',
                description: 'Scanner de vulnérabilités containers',
                commands: ['trivy image imagename', 'trivy fs --security-checks vuln,config /'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Trivy dans HexStrike.
SCAN TYPES: image, fs, repo, config
VULN DB: CVE database, auto-update
SEVERITY: --severity HIGH,CRITICAL
OUTPUT: JSON, table, SARIF
DÉFENSE: Image scanning in CI/CD`
            },

            // ==========================================
            // 🔬 BINARY ANALYSIS
            // ==========================================
            ghidra: {
                name: 'Ghidra Expert',
                emoji: '👻',
                category: 'Binary Analysis',
                tool: 'ghidra',
                description: 'Reverse engineering avancé',
                commands: ['ghidraRun', 'analyzeHeadless'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Ghidra dans HexStrike.
ANALYSIS: Decompilation, disassembly, scripting
FEATURES: Function graphs, data type recovery
SCRIPTING: Java/Python scripting API
HEADLESS: Analyse automatisée en CLI
DÉFENSE: Obfuscation, anti-reverse techniques`
            },

            radare2: {
                name: 'Radare2 Expert',
                emoji: '🔧',
                category: 'Binary Analysis',
                tool: 'r2',
                description: 'Framework reverse engineering CLI',
                commands: ['r2 binary', 'aaa; afl; pdf @ main'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Radare2 dans HexStrike.
COMMANDS: a (analysis), p (print), s (seek), v (visual)
ANALYSIS: aaa (full analysis), afl (functions)
VISUAL: V pour mode visuel, VV pour graph
SCRIPTS: r2pipe pour scripting
DÉFENSE: Anti-debug, packers, obfuscation`
            },

            checksec: {
                name: 'Checksec Expert',
                emoji: '🛡️',
                category: 'Binary Analysis',
                tool: 'checksec',
                description: 'Vérification protections binaires',
                commands: ['checksec --file=binary', 'checksec --proc-all'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de Checksec dans HexStrike.
PROTECTIONS: RELRO, Stack Canary, NX, PIE, RPATH
OUTPUT: Format lisible, couleurs
BATCH: Analyse de plusieurs binaires
DÉFENSE: Compilation avec toutes les protections`
            },

            // ==========================================
            // 🔐 CRYPTOGRAPHY
            // ==========================================
            cipherlink: {
                name: 'CipherLink Expert',
                emoji: '🔐',
                category: 'Cryptography',
                tool: 'cipherlink',
                description: 'Transfert de fichiers chiffré AES-256',
                commands: ['cipherlink send', 'cipherlink receive'],
                systemPrompt: `Tu es l'EXPERT ABSOLU de CipherLink dans HexStrike.
ENCRYPTION: AES-256-CBC, PBKDF2-HMAC-SHA256
KEY DERIVATION: 100,000 itérations
TRANSFER: TCP socket, IV aléatoire
MODES: send (envoi), receive (réception)
DÉFENSE: Chiffrement de bout en bout, aucun plaintext sur le réseau`
            }
        };
    }

    /**
     * Initialise tous les agents experts
     */
    initializeAgents() {
        const configs = this.getToolExpertConfigs();

        for (const [toolId, config] of Object.entries(configs)) {
            this.agents.set(toolId, {
                ...config,
                knowledge: [],
                interactions: 0,
                successfulTasks: 0,
                lastUsed: null
            });

            // Index par catégorie
            const category = config.category;
            if (!this.categories.has(category)) {
                this.categories.set(category, []);
            }
            this.categories.get(category).push(toolId);
        }
    }

    /**
     * Consulter un expert HexStrike spécifique
     */
    async consultExpert(toolId, question, context = {}) {
        const agent = this.agents.get(toolId);

        if (!agent) {
            return {
                success: false,
                error: `Expert '${toolId}' not found`,
                availableExperts: Array.from(this.agents.keys())
            };
        }

        try {
            agent.interactions++;
            agent.lastUsed = new Date().toISOString();

            const prompt = `${agent.systemPrompt}

CONTEXTE: ${JSON.stringify(context)}

QUESTION: ${question}

Réponds en tant qu'expert ${agent.name} avec des commandes précises et des explications techniques.`;

            // Use hackergpt provider with gemini-3-pro-preview model
            const response = await this.llmService.generateResponse(
                prompt,
                null,  // image
                'hackergpt',  // provider
                'gemini-3-pro-preview',  // model
                agent.systemPrompt  // system prompt
            );

            return {
                success: true,
                expert: agent.name,
                tool: agent.tool,
                category: agent.category,
                response: response,
                commands: agent.commands
            };

        } catch (error) {
            console.error(`[HEXSTRIKE-EXPERTS] Error consulting ${toolId}:`, error.message);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Obtenir les experts par catégorie
     */
    getExpertsByCategory(category = null) {
        if (category) {
            const experts = this.categories.get(category) || [];
            return experts.map(id => ({
                id,
                ...this.agents.get(id)
            }));
        }

        const result = {};
        for (const [cat, toolIds] of this.categories.entries()) {
            result[cat] = toolIds.map(id => ({
                id,
                name: this.agents.get(id).name,
                emoji: this.agents.get(id).emoji,
                tool: this.agents.get(id).tool
            }));
        }
        return result;
    }

    /**
     * Obtenir un résumé de tous les experts
     */
    getExpertsSummary() {
        const summary = {
            totalExperts: this.agents.size,
            categories: this.categories.size,
            byCategory: {}
        };

        for (const [category, toolIds] of this.categories.entries()) {
            summary.byCategory[category] = {
                count: toolIds.length,
                experts: toolIds.map(id => `${this.agents.get(id).emoji} ${this.agents.get(id).name}`)
            };
        }

        return summary;
    }

    /**
     * Sélectionner le meilleur expert pour une tâche
     */
    selectExpertForTask(taskDescription) {
        const keywords = {
            'port': ['nmap', 'masscan', 'rustscan'],
            'scan': ['nmap', 'nuclei', 'nikto'],
            'subdomain': ['amass', 'subfinder'],
            'directory': ['gobuster', 'feroxbuster', 'ffuf', 'dirsearch'],
            'parameter': ['arjun', 'paramspider', 'x8'],
            'sql': ['sqlmap'],
            'xss': ['dalfox'],
            'vulnerability': ['nuclei', 'jaeles', 'nikto'],
            'password': ['hydra', 'john', 'hashcat'],
            'exploit': ['metasploit', 'sqlmap'],
            'cloud': ['prowler', 'trivy'],
            'container': ['trivy'],
            'reverse': ['ghidra', 'radare2'],
            'binary': ['checksec', 'ghidra', 'radare2'],
            'network': ['wireshark', 'tcpdump'],
            'osint': ['sherlock', 'theharvester'],
            'crawl': ['katana', 'gau'],
            'encrypt': ['cipherlink'],
            'transfer': ['cipherlink']
        };

        const taskLower = taskDescription.toLowerCase();
        const matchedExperts = new Set();

        for (const [keyword, experts] of Object.entries(keywords)) {
            if (taskLower.includes(keyword)) {
                experts.forEach(e => matchedExperts.add(e));
            }
        }

        if (matchedExperts.size === 0) {
            return ['nuclei']; // Default to nuclei for general security
        }

        return Array.from(matchedExperts);
    }

    /**
     * Exécuter une commande via HexStrike avec l'expert approprié
     */
    async executeWithExpert(toolId, params = {}) {
        const agent = this.agents.get(toolId);

        if (!agent) {
            return { success: false, error: `Expert '${toolId}' not found` };
        }

        try {
            // Utiliser le bridge HexStrike pour exécuter
            const result = await hexstrikeBridge.executeTool(agent.tool, params);

            agent.successfulTasks++;

            return {
                success: true,
                expert: agent.name,
                tool: agent.tool,
                result
            };
        } catch (error) {
            return {
                success: false,
                expert: agent.name,
                error: error.message
            };
        }
    }
}

module.exports = HexStrikeExpertAgentsService;
