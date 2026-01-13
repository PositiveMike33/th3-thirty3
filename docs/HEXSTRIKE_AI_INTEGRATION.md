# 🔥 HexStrike AI - Analysis & Gemini 3 Integration Guide

## 📋 Table of Contents
1. [Overview](#overview)
2. [Architecture Analysis](#architecture-analysis)
3. [150+ Security Tools](#security-tools)
4. [12 AI Agents](#ai-agents)
5. [Installation Guide](#installation-guide)
6. [Gemini 3 Integration](#gemini-3-integration)
7. [Usage Examples](#usage-examples)

---

## 🎯 Overview

**HexStrike AI MCP Agents v6.0** est une plateforme avancée de cybersécurité qui permet aux agents AI (Claude, GPT, Gemini, etc.) d'exécuter **150+ outils de sécurité** de manière autonome.

### Key Features:
- 🔧 **150+ Security Tools** - Network, Web, Cloud, Binary, OSINT
- 🤖 **12+ AI Agents Autonomes** - Bug Bounty, CTF, CVE Intelligence
- 🧠 **Intelligent Decision Engine** - Sélection d'outils optimale
- 📊 **Real-time Visual Engine** - Dashboards et progress tracking
- ⚡ **MCP Protocol** - Protocol standard pour AI agents

---

## 🏗️ Architecture Analysis

```
┌─────────────────────────────────────────────────────────────────────┐
│                    HexStrike AI Architecture                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────┐       MCP Protocol       ┌──────────────────┐ │
│  │   AI Agent      │◄─────────────────────────►│  HexStrike MCP   │ │
│  │  (Gemini 3)     │                          │  Client (Python)  │ │
│  └─────────────────┘                          └────────┬─────────┘ │
│                                                        │           │
│                                               HTTP API │           │
│                                                        ▼           │
│                                            ┌──────────────────────┐│
│                                            │  HexStrike Server    ││
│                                            │  (Flask, Port 8888)  ││
│                                            └──────────┬───────────┘│
│                                                       │            │
│         ┌─────────────────────────────────────────────┼────────┐   │
│         │                                             │        │   │
│         ▼                         ▼                   ▼        │   │
│  ┌─────────────┐          ┌─────────────┐      ┌───────────┐   │   │
│  │ Decision    │          │  12 AI      │      │  150+     │   │   │
│  │ Engine      │          │  Agents     │      │  Tools    │   │   │
│  └─────────────┘          └─────────────┘      └───────────┘   │   │
│                                                                │   │
└────────────────────────────────────────────────────────────────────┘
```

### Files Clés:
| File | Size | Description |
|------|------|-------------|
| `hexstrike_server.py` | 751KB | Serveur Flask avec 150+ outils |
| `hexstrike_mcp.py` | 223KB | Client MCP pour AI agents |
| `requirements.txt` | 4KB | Dépendances Python |
| `hexstrike-ai-mcp.json` | 400B | Configuration MCP |

---

## 🔧 Security Tools (150+)

### 🔍 Network & Reconnaissance (25+ tools)
| Tool | Function |
|------|----------|
| `nmap_scan()` | Port scanning avec scripts NSE |
| `rustscan_scan()` | Ultra-fast port scanning |
| `masscan_scan()` | High-speed Internet-scale scanning |
| `autorecon_scan()` | Automated comprehensive recon |
| `amass_enum()` | Subdomain enumeration & OSINT |
| `subfinder_scan()` | Fast passive subdomain discovery |
| `fierce_scan()` | DNS reconnaissance |
| `dnsenum_scan()` | DNS information gathering |
| `theharvester_scan()` | Email & subdomain harvesting |
| `responder_capture()` | LLMNR/NBT-NS poisoning |
| `netexec_scan()` | Network exploitation framework |
| `enum4linux_scan()` | SMB enumeration |

### 🌐 Web Application Security (40+ tools)
| Tool | Function |
|------|----------|
| `gobuster_scan()` | Directory/file enumeration |
| `feroxbuster_scan()` | Recursive content discovery |
| `ffuf_scan()` | Fast web fuzzing |
| `nuclei_scan()` | Vulnerability scanning (4000+ templates) |
| `nikto_scan()` | Web server vulnerability scanner |
| `sqlmap_scan()` | SQL injection testing |
| `wpscan_scan()` | WordPress security assessment |
| `arjun_scan()` | HTTP parameter discovery |
| `paramspider_scan()` | Parameter mining |
| `dalfox_scan()` | XSS vulnerability scanning |
| `katana_crawl()` | Next-gen web crawling |
| `httpx_probe()` | HTTP probing & tech detection |

### ☁️ Cloud Security (20+ tools)
| Tool | Function |
|------|----------|
| `prowler_scan()` | AWS/Azure/GCP assessment |
| `scout_suite_assessment()` | Multi-cloud auditing |
| `trivy_scan()` | Container vulnerability scanning |
| `kube_hunter_scan()` | Kubernetes pentesting |
| `kube_bench_cis()` | CIS K8s benchmark |
| `docker_bench_security_scan()` | Docker security assessment |
| `cloudmapper_analysis()` | AWS network visualization |
| `pacu_exploitation()` | AWS exploitation framework |
| `clair_vulnerability_scan()` | Container analysis |
| `falco_runtime_monitoring()` | Runtime security |

### 🔬 Binary Analysis & RE (25+ tools)
| Tool | Function |
|------|----------|
| `ghidra_analyze()` | Software reverse engineering |
| `radare2_analyze()` | Advanced RE framework |
| `gdb_debug()` | GNU debugger |
| `pwntools_exploit()` | CTF & exploit development |
| `angr_analyze()` | Symbolic execution |
| `binwalk_analyze()` | Firmware analysis |
| `checksec_check()` | Binary security properties |
| `ropgadget_find()` | ROP gadget finder |
| `volatility_forensics()` | Memory forensics |

### 🔐 Password & Authentication (15+ tools)
| Tool | Function |
|------|----------|
| `hydra_attack()` | Network login cracker |
| `john_crack()` | Password hash cracking |
| `hashcat_crack()` | GPU-accelerated cracking |
| `medusa_attack()` | Parallel login brute-forcer |
| `evil_winrm_shell()` | WinRM shell |
| `hash_identifier()` | Hash type identification |

### 🕵️ OSINT & Intelligence (20+ tools)
| Tool | Function |
|------|----------|
| `sherlock_search()` | Username investigation (400+ sites) |
| `social_analyzer()` | Social media analysis |
| `recon_ng()` | Web recon framework |
| `spiderfoot_osint()` | OSINT automation (200+ modules) |
| `shodan_search()` | Device search |
| `trufflehog_scan()` | Git secret scanning |

---

## 🤖 12 AI Agents

| Agent | Description |
|-------|-------------|
| **IntelligentDecisionEngine** | Sélection d'outils & optimisation |
| **BugBountyWorkflowManager** | Workflows bug bounty |
| **CTFWorkflowManager** | Résolution de challenges CTF |
| **CVEIntelligenceManager** | Intelligence sur vulnérabilités |
| **AIExploitGenerator** | Développement d'exploits automatisé |
| **VulnerabilityCorrelator** | Découverte de chaînes d'attaque |
| **TechnologyDetector** | Identification de stack techno |
| **RateLimitDetector** | Détection de rate limiting |
| **FailureRecoverySystem** | Gestion d'erreurs |
| **PerformanceMonitor** | Optimisation système |
| **ParameterOptimizer** | Optimisation contextuelle |
| **GracefulDegradation** | Opération fault-tolerant |

---

## 📦 Installation Guide

### Prérequis Système
- **OS**: Kali Linux 2024.1+ (recommandé) ou Windows avec WSL2
- **Python**: 3.10+
- **RAM**: 8GB+ minimum
- **Storage**: 20GB+ pour les outils

### Étape 1: Clone & Virtual Environment
```powershell
# Dans th3-thirty3
cd c:\Users\th3th\th3-thirty3\hexstrike-ai

# Créer environnement virtuel
python -m venv hexstrike-env

# Activer (Windows)
.\hexstrike-env\Scripts\Activate.ps1

# Activer (Linux/WSL)
source hexstrike-env/bin/activate
```

### Étape 2: Installer les dépendances Python
```bash
pip install -r requirements.txt
```

### Étape 3: Installer les outils de sécurité (Kali/WSL)
```bash
# Core Network Tools
sudo apt install -y nmap masscan rustscan amass subfinder nuclei

# Web Application Tools
sudo apt install -y gobuster feroxbuster ffuf nikto sqlmap wpscan

# Password Tools
sudo apt install -y hydra john hashcat medusa

# Binary Analysis
sudo apt install -y gdb radare2 binwalk ghidra

# OSINT
pip install sherlock-project
```

### Étape 4: Démarrer le serveur HexStrike
```bash
# Mode normal
python hexstrike_server.py

# Mode debug
python hexstrike_server.py --debug

# Port personnalisé
python hexstrike_server.py --port 8888
```

### Étape 5: Vérifier l'installation
```bash
# Test health
curl http://localhost:8888/health

# Test AI capabilities
curl -X POST http://localhost:8888/api/intelligence/analyze-target \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "analysis_type": "comprehensive"}'
```

---

## 🔗 Gemini 3 Integration

### Option A: Intégration directe dans th3-thirty3

Cette approche intègre HexStrike comme service backend pour ton projet existant.

#### Architecture proposée:
```
┌──────────────────────────────────────────────────────────────┐
│                    th3-thirty3 Enhanced                      │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Frontend (React)                                            │
│  ├── Chat Interface                                          │
│  │   └── Gemini 3 Provider ◄────────────────────┐           │
│  └── Security Dashboard                          │           │
│                                                  │           │
│  Backend (Node.js)                               │           │
│  ├── llm_service.js                              │           │
│  │   ├── generateGeminiResponse() ──────────────┤           │
│  │   └── executeSecurityTool() ─────┐           │           │
│  │                                  │           │           │
│  └── hexstrike_bridge.js ◄──────────┘           │           │
│       │                                          │           │
│       │  HTTP API                                │           │
│       ▼                                          │           │
│  ┌─────────────────────────────────┐            │           │
│  │  HexStrike Server (Python)      │            │           │
│  │  Port 8888                      │            │           │
│  │  ├── 150+ Security Tools        │            │           │
│  │  └── 12 AI Agents               │            │           │
│  └─────────────────────────────────┘            │           │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

#### Fichier: `server/hexstrike_bridge.js`
```javascript
/**
 * HexStrike AI Bridge - Connect th3-thirty3 to HexStrike security tools
 */

const HEXSTRIKE_URL = process.env.HEXSTRIKE_URL || 'http://localhost:8888';

class HexStrikeBridge {
    constructor() {
        this.baseUrl = HEXSTRIKE_URL;
        this.timeout = 300000; // 5 minutes for long scans
    }

    /**
     * Check HexStrike server health
     */
    async checkHealth() {
        try {
            const response = await fetch(`${this.baseUrl}/health`, { timeout: 5000 });
            return await response.json();
        } catch (error) {
            return { status: 'offline', error: error.message };
        }
    }

    /**
     * Execute a security tool via HexStrike
     */
    async executeTool(toolName, params) {
        const response = await fetch(`${this.baseUrl}/api/command`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tool: toolName, params }),
            timeout: this.timeout
        });
        return await response.json();
    }

    /**
     * Nmap scan
     */
    async nmapScan(target, scanType = '-sV', ports = '') {
        return this.executeTool('nmap_scan', { target, scan_type: scanType, ports });
    }

    /**
     * Nuclei vulnerability scan
     */
    async nucleiScan(target, severity = 'high,critical') {
        return this.executeTool('nuclei_scan', { target, severity });
    }

    /**
     * Directory enumeration
     */
    async gobusterScan(url, mode = 'dir') {
        return this.executeTool('gobuster_scan', { url, mode });
    }

    /**
     * Subdomain enumeration
     */
    async amassEnum(domain) {
        return this.executeTool('amass_enum', { domain });
    }

    /**
     * AI-powered target analysis
     */
    async analyzeTarget(target, analysisType = 'comprehensive') {
        const response = await fetch(`${this.baseUrl}/api/intelligence/analyze-target`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, analysis_type: analysisType })
        });
        return await response.json();
    }

    /**
     * Get tool recommendations for a target
     */
    async selectTools(target, objectives = ['vulnerability_assessment']) {
        const response = await fetch(`${this.baseUrl}/api/intelligence/select-tools`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, objectives })
        });
        return await response.json();
    }

    /**
     * List available tools
     */
    async listTools() {
        const response = await fetch(`${this.baseUrl}/api/tools`);
        return await response.json();
    }
}

module.exports = new HexStrikeBridge();
```

### Option B: Gemini 3 comme orchestrateur direct

Utilise Gemini 3 pour interpréter tes commandes et exécuter les outils HexStrike.

#### Fichier: `server/gemini_hexstrike_agent.js`
```javascript
/**
 * Gemini 3 HexStrike Agent
 * Utilise Gemini 3 pour orchestrer 150+ outils de sécurité
 */

const { GoogleGenerativeAI } = require('@google/generative-ai');
const hexstrikeBridge = require('./hexstrike_bridge');
const settingsService = require('./settings_service');

class GeminiHexStrikeAgent {
    constructor() {
        const settings = settingsService.getSettings();
        const geminiKey = process.env.GEMINI_API_KEY || settings.apiKeys?.gemini;
        
        if (!geminiKey) {
            throw new Error('GEMINI_API_KEY required for HexStrike Agent');
        }

        this.genAI = new GoogleGenerativeAI(geminiKey);
        this.model = this.genAI.getGenerativeModel({
            model: 'gemini-3-pro-preview',
            systemInstruction: this.getSystemPrompt()
        });
    }

    getSystemPrompt() {
        return `You are HexStrike AI, an advanced cybersecurity automation agent with access to 150+ professional security tools.

## Your Capabilities:
1. **Network Reconnaissance**: nmap, masscan, rustscan, amass, subfinder
2. **Web Application Testing**: nuclei, gobuster, sqlmap, nikto, burp
3. **Vulnerability Assessment**: nuclei, nessus, openvas
4. **Cloud Security**: prowler, scout-suite, trivy, kube-hunter
5. **Binary Analysis**: ghidra, radare2, gdb, binwalk
6. **Password Attacks**: hydra, john, hashcat
7. **OSINT**: sherlock, spiderfoot, maltego

## When given a security task:
1. Analyze the target to understand its nature (web app, network, cloud, etc.)
2. Select appropriate tools based on the target type
3. Execute tools in the correct order (recon → enumeration → vulnerability scan → exploitation)
4. Provide detailed analysis of findings
5. Suggest remediation steps

## Response Format:
Always respond with:
1. Your analysis of the request
2. The tools you'll use and why
3. Execution plan
4. Results summary with risk ratings (Critical, High, Medium, Low, Info)

## Tool Calling:
When you need to execute a tool, respond with JSON:
\`\`\`json
{
  "action": "execute_tool",
  "tool": "tool_name",
  "params": { ... }
}
\`\`\`

## Ethics:
- Only test authorized targets
- Follow responsible disclosure
- Document all findings
- Never cause damage`;
    }

    /**
     * Process a security request through Gemini 3
     */
    async processRequest(userPrompt, context = {}) {
        try {
            // Get initial analysis from Gemini 3
            const chat = this.model.startChat({
                history: context.history || []
            });

            const result = await chat.sendMessage(userPrompt);
            let response = result.response.text();

            // Check if Gemini wants to execute a tool
            const toolMatch = response.match(/```json\s*({[\s\S]*?})\s*```/);
            if (toolMatch) {
                const toolRequest = JSON.parse(toolMatch[1]);
                
                if (toolRequest.action === 'execute_tool') {
                    console.log(`[GEMINI-HEXSTRIKE] Executing: ${toolRequest.tool}`);
                    
                    // Execute the tool via HexStrike
                    const toolResult = await hexstrikeBridge.executeTool(
                        toolRequest.tool, 
                        toolRequest.params
                    );

                    // Send results back to Gemini for analysis
                    const analysisResult = await chat.sendMessage(
                        `Tool execution complete. Results:\n\`\`\`\n${JSON.stringify(toolResult, null, 2)}\n\`\`\`\n\nAnalyze these results and provide insights.`
                    );
                    
                    response = analysisResult.response.text();
                }
            }

            return {
                success: true,
                response,
                tools_used: context.toolsUsed || []
            };

        } catch (error) {
            console.error('[GEMINI-HEXSTRIKE] Error:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Quick security scan with Gemini analysis
     */
    async quickScan(target) {
        return this.processRequest(
            `Perform a quick security assessment of ${target}. Start with reconnaissance, then identify potential vulnerabilities.`
        );
    }

    /**
     * Full pentest workflow
     */
    async fullPentest(target, scope = 'web') {
        return this.processRequest(
            `Conduct a comprehensive penetration test on ${target}. Scope: ${scope}. Follow the full methodology: recon, enumeration, vulnerability scanning, and exploitation (with caution).`
        );
    }
}

module.exports = GeminiHexStrikeAgent;
```

---

## 💡 Usage Examples

### Exemple 1: Quick Scan via Chat
```
User: "Scan example.com for vulnerabilities"

Gemini 3 + HexStrike:
1. Analyze target → Web application detected
2. Execute: amass_enum(example.com) → Subdomains found
3. Execute: httpx_probe() → Tech stack identified
4. Execute: nuclei_scan(severity=high,critical) → 3 vulns found
5. Returns detailed report with remediation
```

### Exemple 2: Bug Bounty Workflow
```
User: "Start bug bounty recon on target.com"

Workflow:
1. amass + subfinder → Subdomain enumeration
2. httpx → Alive hosts detection  
3. nuclei → Vulnerability scanning
4. gobuster → Directory fuzzing
5. paramspider + arjun → Parameter discovery
6. dalfox → XSS testing
7. sqlmap → SQL injection testing
```

### Exemple 3: Cloud Security Assessment
```
User: "Audit my AWS account"

Workflow:
1. prowler_scan(provider=aws) → CIS benchmark
2. scout_suite_assessment(provider=aws) → Multi-service audit
3. Report with findings and remediation
```

---

## 🚀 Quick Start Commands

```bash
# 1. Start HexStrike Server (Terminal 1)
cd hexstrike-ai
python hexstrike_server.py

# 2. Start th3-thirty3 Backend (Terminal 2)  
cd server
npm start

# 3. Start th3-thirty3 Frontend (Terminal 3)
cd interface
npm run dev

# 4. Access: http://localhost:5173
# Select Gemini 3 Pro model
# Chat: "Scan example.com for vulnerabilities using HexStrike tools"
```

---

## ⚠️ Security Considerations

1. **Authorization Only** - Never scan targets without explicit permission
2. **Isolated Environment** - Run HexStrike in isolated container/VM
3. **Rate Limiting** - Respect target rate limits
4. **Legal Compliance** - Follow local laws and regulations
5. **Responsible Disclosure** - Report vulnerabilities ethically

---

## 📊 Integration Checklist

- [ ] Clone hexstrike-ai repo
- [ ] Create Python virtual environment
- [ ] Install requirements.txt
- [ ] Install security tools (Kali/WSL)
- [ ] Start hexstrike_server.py
- [ ] Create hexstrike_bridge.js
- [ ] Create gemini_hexstrike_agent.js
- [ ] Update llm_service.js
- [ ] Test with simple scan
- [ ] Test Gemini 3 orchestration

---

*Document généré le 2026-01-10 par Antigravity AI*
