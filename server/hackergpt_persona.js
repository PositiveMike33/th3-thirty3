/**
 * HackerGPT Persona Integration
 * Based on: https://github.com/hacker-gpt/hackergpt
 * 
 * An Offensive Security Companion for penetration testing and red teaming
 */

const HACKERGPT_PERSONA = {
    name: "HackerGPT",
    version: "2.0.0",
    description: "Offensive Security Companion - Pentesting & Red Team Expert",

    // System prompt that defines the persona
    systemPrompt: `Tu es HackerGPT, un compagnon expert en sécurité offensive intégré à Th3 Thirty3.

## IDENTITÉ
Tu es un assistant de cybersécurité offensive spécialisé dans:
- Tests de pénétration (pentest)
- Red Team engagements
- Exploitation de vulnérabilités
- Reconnaissance et OSINT
- Analyse de sécurité réseau

## CAPACITÉS PRINCIPALES

### 1. Exploitation Autonome
- Détection automatique des services vulnérables
- Génération d'exploits basés sur CVE
- Adaptation aux défenses en temps réel
- Escalade de privilèges

### 2. Reconnaissance
- Fingerprinting d'hôtes et services
- Scan de ports (Nmap, Masscan)
- Énumération de sous-domaines
- Détection de technologies (Wappalyzer-like)

### 3. OSINT & Dark Web
- Recherche d'informations exposées
- Analyse de data leaks
- Intelligence sur les menaces
- Profiling de cibles

### 4. Reporting
- Génération de rapports de vulnérabilités
- Classification CVSS
- Recommandations de remédiation
- Documentation technique

## OUTILS MAÎTRISÉS
- Nmap, Masscan, Rustscan
- Metasploit, Cobalt Strike
- Burp Suite, ZAP
- SQLMap, Nuclei
- Gobuster, Feroxbuster
- Hydra, John the Ripper
- Shodan, Censys
- theHarvester, Recon-ng

## RÈGLES D'ENGAGEMENT
1. Toujours agir dans un cadre éthique et légal
2. Obtenir autorisation écrite avant tout test
3. Documenter toutes les actions
4. Minimiser l'impact sur les systèmes
5. Signaler immédiatement les vulnérabilités critiques

## FORMAT DE RÉPONSE
- Utilise des blocs de code pour les commandes
- Explique le "pourquoi" de chaque action
- Propose des alternatives quand pertinent
- Inclus des avertissements de sécurité

## PERSONNALITÉ
Tu es professionnel mais accessible. Tu expliques les concepts complexes simplement.
Tu encourages l'apprentissage éthique de la cybersécurité.
Tu refuses catégoriquement toute demande malveillante sans autorisation légale.

Salut, je suis HackerGPT, ton compagnon de pentesting. Comment puis-je t'aider aujourd'hui?`,

    // Specialized prompts for different tasks
    taskPrompts: {
        recon: `Mode Reconnaissance activé.
Objectif: Collecter un maximum d'informations sur la cible.
Méthodologie:
1. DNS enumeration
2. Subdomain discovery  
3. Port scanning
4. Service fingerprinting
5. Technology detection
6. OSINT gathering`,

        exploit: `Mode Exploitation activé.
Objectif: Identifier et exploiter les vulnérabilités.
Méthodologie:
1. Vulnerability scanning
2. CVE matching
3. Exploit selection
4. Payload crafting
5. Execution
6. Post-exploitation`,

        report: `Mode Reporting activé.
Objectif: Documenter les découvertes.
Format:
1. Executive Summary
2. Scope & Methodology
3. Findings (Critical/High/Medium/Low)
4. Evidence & Screenshots
5. Remediation Recommendations
6. Appendices`,

        osint: `Mode OSINT activé.
Objectif: Intelligence gathering passive.
Sources:
1. Public records
2. Social media
3. Data breaches
4. Dark web
5. Technical footprint
6. Organizational intel`
    },

    // Common tools and their usage
    tools: {
        nmap: {
            name: "Nmap",
            description: "Network mapper for port scanning and service detection",
            examples: [
                "nmap -sV -sC -p- target.com",
                "nmap -sU --top-ports 100 target.com",
                "nmap --script vuln target.com"
            ]
        },
        nuclei: {
            name: "Nuclei",
            description: "Fast vulnerability scanner with templates",
            examples: [
                "nuclei -u https://target.com -t cves/",
                "nuclei -l urls.txt -t exposures/",
                "nuclei -u target.com -severity critical,high"
            ]
        },
        sqlmap: {
            name: "SQLMap",
            description: "Automatic SQL injection tool",
            examples: [
                "sqlmap -u 'url?id=1' --dbs",
                "sqlmap -r request.txt --level 5 --risk 3",
                "sqlmap -u 'url' --os-shell"
            ]
        },
        metasploit: {
            name: "Metasploit",
            description: "Exploitation framework",
            examples: [
                "use exploit/windows/smb/ms17_010_eternalblue",
                "use auxiliary/scanner/ssh/ssh_login",
                "use post/multi/manage/shell_to_meterpreter"
            ]
        },
        gobuster: {
            name: "Gobuster",
            description: "Directory and subdomain brute-forcing",
            examples: [
                "gobuster dir -u https://target.com -w wordlist.txt",
                "gobuster dns -d target.com -w subdomains.txt",
                "gobuster vhost -u https://target.com -w vhosts.txt"
            ]
        }
    },

    // Common vulnerability categories
    vulnCategories: [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Remote Code Execution (RCE)",
        "Local File Inclusion (LFI)",
        "Server-Side Request Forgery (SSRF)",
        "Broken Authentication",
        "Sensitive Data Exposure",
        "XML External Entity (XXE)",
        "Insecure Deserialization",
        "Security Misconfiguration"
    ],

    // CVSS scoring reference
    cvssReference: {
        critical: { min: 9.0, max: 10.0, color: "#7D1A1A" },
        high: { min: 7.0, max: 8.9, color: "#C62828" },
        medium: { min: 4.0, max: 6.9, color: "#F57C00" },
        low: { min: 0.1, max: 3.9, color: "#FBC02D" },
        info: { min: 0.0, max: 0.0, color: "#1565C0" }
    }
};

/**
 * HackerGPT Service Class
 * Integrates HackerGPT persona with Th3 Thirty3
 */
class HackerGPTService {
    constructor() {
        this.persona = HACKERGPT_PERSONA;
        this.sessionHistory = [];
        this.currentMode = 'general';
        console.log('[HACKERGPT] Service initialized - Offensive Security Companion ready');
    }

    /**
     * Get the system prompt for LLM
     */
    getSystemPrompt(mode = 'general') {
        let basePrompt = this.persona.systemPrompt;

        if (mode && this.persona.taskPrompts[mode]) {
            basePrompt += `\n\n${this.persona.taskPrompts[mode]}`;
        }

        return basePrompt;
    }

    /**
     * Set the operational mode
     */
    setMode(mode) {
        const validModes = ['general', 'recon', 'exploit', 'report', 'osint'];
        if (validModes.includes(mode)) {
            this.currentMode = mode;
            console.log(`[HACKERGPT] Mode changed to: ${mode.toUpperCase()}`);
            return true;
        }
        return false;
    }

    /**
     * Get tool information
     */
    getTool(toolName) {
        return this.persona.tools[toolName.toLowerCase()] || null;
    }

    /**
     * Get all available tools
     */
    getAllTools() {
        return Object.keys(this.persona.tools).map(key => ({
            id: key,
            ...this.persona.tools[key]
        }));
    }

    /**
     * Generate a vulnerability report template
     */
    generateReportTemplate(findings = []) {
        return {
            title: "Penetration Test Report",
            date: new Date().toISOString(),
            generatedBy: "HackerGPT @ Th3 Thirty3",
            sections: {
                executiveSummary: "",
                scope: {
                    targets: [],
                    methodology: "OWASP Testing Guide + PTES",
                    duration: ""
                },
                findings: findings.map((f, i) => ({
                    id: `VULN-${String(i + 1).padStart(3, '0')}`,
                    title: f.title || "",
                    severity: f.severity || "medium",
                    cvss: f.cvss || 5.0,
                    description: f.description || "",
                    impact: f.impact || "",
                    remediation: f.remediation || "",
                    evidence: f.evidence || []
                })),
                recommendations: [],
                conclusion: ""
            }
        };
    }

    /**
     * Classify severity based on CVSS
     */
    classifySeverity(cvssScore) {
        const ref = this.persona.cvssReference;
        if (cvssScore >= ref.critical.min) return 'critical';
        if (cvssScore >= ref.high.min) return 'high';
        if (cvssScore >= ref.medium.min) return 'medium';
        if (cvssScore >= ref.low.min) return 'low';
        return 'info';
    }

    /**
     * Get persona info
     */
    getInfo() {
        return {
            name: this.persona.name,
            version: this.persona.version,
            description: this.persona.description,
            currentMode: this.currentMode,
            availableModes: ['general', 'recon', 'exploit', 'report', 'osint'],
            toolsCount: Object.keys(this.persona.tools).length,
            vulnCategories: this.persona.vulnCategories.length
        };
    }
}

// Singleton instance
const hackerGPTService = new HackerGPTService();

module.exports = {
    hackerGPTService,
    HACKERGPT_PERSONA
};
