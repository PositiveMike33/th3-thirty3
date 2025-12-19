/**
 * 10 SPECIALIZED EXPERT AGENTS
 * Each with domain-specific training scenarios
 */

const { ExpertAgent } = require('./expert_agents_system');

/**
 * 1. VulnScout - Vulnerability Assessment Agent
 */
class VulnScoutAgent extends ExpertAgent {
    constructor(llmService, modelName) {
        super('VULN_SCOUT', llmService, modelName);
        this.scanTypes = ['network', 'web', 'api', 'infrastructure', 'code'];
    }

    generateRandomScenario() {
        const scanType = this.scanTypes[Math.floor(Math.random() * this.scanTypes.length)];
        const scenarios = {
            network: 'Scan network 192.168.1.0/24 for open ports and services. Identify potential vulnerabilities.',
            web: 'Analyze web application https://target.com for common vulnerabilities (OWASP Top 10).',
            api: 'Test REST API endpoints for authentication bypass and injection flaws.',
            infrastructure: 'Assess cloud infrastructure (AWS/Azure) for misconfigurations.',
            code: 'Perform static analysis on provided codebase for security vulnerabilities.'
        };
        
        return {
            type: `vuln_scan_${scanType}`,
            difficulty: Math.random() > 0.7 ? 'hard' : 'medium',
            context: scenarios[scanType]
        };
    }

    getSystemPrompt() {
        return `You are VulnScout, an expert vulnerability assessment agent. You specialize in:
- CVE database analysis
- CVSS scoring
- Attack surface mapping
- Security scanning (Nessus, OpenVAS, Nmap)
- Vulnerability prioritization based on business context

Provide detailed vulnerability assessments with remediation steps.`;
    }

    getTechnicalKeywords() {
        return ['CVE', 'vulnerability', 'exploit', 'patch', 'CVSS', 'scanner', 'port', 'service', 'misconfiguration'];
    }
}

/**
 * 2. NetPsyche - Network Behavioral Analysis Agent
 */
class NetPsycheAgent extends ExpertAgent {
    constructor(llmService, modelName) {
        super('NET_PSYCHE', llmService, modelName);
        this.behaviorsToAnalyze = ['login_pattern', 'data_access', 'privilege_escalation', 'data_exfiltration'];
    }

    generateRandomScenario() {
        const behavior = this.behaviorsToAnalyze[Math.floor(Math.random() * this.behaviorsToAnalyze.length)];
        const scenarios = {
            login_pattern: 'User logged in from 3 different countries within 2 hours. Analyze if this is anomalous.',
            data_access: 'Employee accessed 500 sensitive files in the last hour (normal avg: 20/day). Investigate.',
            privilege_escalation: 'Standard user account suddenly has admin privileges. Determine if legitimate.',
            data_exfiltration: 'Large data transfer (10GB) to external IP during off-hours. Assess risk.'
        };
        
        return {
            type: `behavior_${behavior}`,
            difficulty: 'medium',
            context: scenarios[behavior]
        };
    }

    getSystemPrompt() {
        return `You are NetPsyche, a behavioral analysis agent specialized in UEBA (User and Entity Behavior Analytics). You excel at:
- Anomaly detection
- Insider threat identification
- Behavioral profiling
- False positive reduction
- Risk scoring based on context

Analyze user behavior patterns and identify threats.`;
    }

    getTechnicalKeywords() {
        return ['anomaly', 'behavior', 'baseline', 'UEBA', 'insider', 'pattern', 'deviation', 'risk'];
    }
}

/**
 * 3. NetPhantom - Red Team Infiltration Agent
 */
class NetPhantomAgent extends ExpertAgent {
    constructor(llmService, modelName) {
        super('NET_PHANTOM', llmService, modelName);
        this.techniques = ['pivot', 'lateral_movement', 'evasion', 'c2', 'exfiltration'];
    }

    generateRandomScenario() {
        const technique = this.techniques[Math.floor(Math.random() * this.techniques.length)];
        const scenarios = {
            pivot: 'You have compromised a DMZ server. Plan pivot to internal network avoiding detection.',
            lateral_movement: 'Move from workstation to domain controller using pass-the-hash or Kerberos attacks.',
            evasion: 'Bypass EDR/AV detection while maintaining persistence on target system.',
            c2: 'Establish covert C2 channel using DNS tunneling or HTTPS beaconing.',
            exfiltration: 'Exfiltrate 50GB database dump without triggering DLP or network monitoring.'
        };
        
        return {
            type: `red_team_${technique}`,
            difficulty: 'hard',
            context: scenarios[technique]
        };
    }

    getSystemPrompt() {
        return `You are NetPhantom, a red team penetration testing agent. Your expertise includes:
- Network pivoting and lateral movement
- Evasion techniques (AV, EDR, IDS bypass)
- Command & Control (C2) infrastructure
- Social engineering
- Post-exploitation

Provide detailed attack paths and evasion strategies.`;
    }

    getTechnicalKeywords() {
        return ['pivot', 'lateral', 'evasion', 'C2', 'persistence', 'enumeration', 'privilege', 'exploit'];
    }
}

/**
 * 4. CryptoWarden - Real-time Encryption Agent
 */
class CryptoWardenAgent extends ExpertAgent {
    constructor(llmService, modelName) {
        super('CRYPTO_WARDEN', llmService, modelName);
        this.cryptoTasks = ['encryption', 'key_management', 'algorithm_selection', 'quantum_resistance'];
    }

    generateRandomScenario() {
        const task = this.cryptoTasks[Math.floor(Math.random() * this.cryptoTasks.length)];
        const scenarios = {
            encryption: 'Encrypt sensitive customer data using AES-256-GCM with proper key rotation.',
            key_management: 'Design secure key management system for multi-tenant cloud environment.',
            algorithm_selection: 'Choose appropriate encryption for real-time video conferencing (low latency).',
            quantum_resistance: 'Implement post-quantum cryptography to protect against future quantum attacks.'
        };
        
        return {
            type: `crypto_${task}`,
            difficulty: Math.random() > 0.6 ? 'hard' : 'medium',
            context: scenarios[task]
        };
    }

    getSystemPrompt() {
        return `You are CryptoWarden, an encryption specialist agent. Your mastery includes:
- Modern cryptographic algorithms (AES, RSA, ECC)
- Post-quantum cryptography
- Key management and rotation
- Secure key exchange protocols
- Cryptographic best practices

Provide secure encryption solutions with implementation details.`;
    }

    getTechnicalKeywords() {
        return ['AES', 'RSA', 'encryption', 'key', 'cipher', 'hash', 'quantum', 'cryptography'];
    }
}

/**
 * 5. DeepMapper - Dark Web Mapping Agent
 */
class DeepMapperAgent extends ExpertAgent {
    constructor(llmService, modelName) {
        super('DEEP_MAPPER', llmService, modelName);
        this.mappingTasks = ['tor_exploration', 'marketplace_monitoring', 'leak_detection', 'actor_profiling'];
    }

    generateRandomScenario() {
        const task = this.mappingTasks[Math.floor(Math.random() * this.mappingTasks.length)];
        const scenarios = {
            tor_exploration: 'Map hidden services on Tor network related to cybercrime forums.',
            marketplace_monitoring: 'Monitor dark web marketplaces for stolen credentials of your organization.',
            leak_detection: 'Detect if company data has been leaked on paste sites or dark web forums.',
            actor_profiling: 'Profile threat actor selling zero-day exploits on underground forums.'
        };
        
        return {
            type: `darkweb_${task}`,
            difficulty: 'hard',
            context: scenarios[task]
        };
    }

    getSystemPrompt() {
        return `You are DeepMapper, a dark web intelligence agent. Your specialties:
- Tor and I2P network navigation
- OSINT on dark web
- Marketplace and forum monitoring
- Threat actor identification
- Data leak detection

Provide intelligence on dark web activities while maintaining anonymity.`;
    }

    getTechnicalKeywords() {
        return ['Tor', 'darkweb', 'onion', 'marketplace', 'forum', 'leak', 'actor', 'underground'];
    }
}

/**
 * 6. CyberShield - Active Defense Agent
 */
class CyberShieldAgent extends ExpertAgent {
    constructor(llmService, modelName) {
        super('CYBER_SHIELD', llmService, modelName);
        this.defenseTasks = ['incident_response', 'isolation', 'patching', 'quarantine'];
    }

    generateRandomScenario() {
        const task = this.defenseTasks[Math.floor(Math.random() * this.defenseTasks.length)];
        const scenarios = {
            incident_response: 'Ransomware detected on file server. Immediate containment and response required.',
            isolation: 'Isolate compromised workstation from network while preserving forensic evidence.',
            patching: 'Critical zero-day vulnerability announced. Emergency patching of 500 servers needed.',
            quarantine: 'Malicious email attachment opened by 20 users. Quarantine affected systems.'
        };
        
        return {
            type: `defense_${task}`,
            difficulty: 'medium',
            context: scenarios[task]
        };
    }

    getSystemPrompt() {
        return `You are CyberShield, an active defense and incident response agent. Expertise in:
- EDR/MDR solutions
- Automated incident response
- Network isolation and segmentation
- Emergency patching
- Threat containment

Provide rapid, effective defensive actions.`;
    }

    getTechnicalKeywords() {
        return ['EDR', 'isolate', 'quarantine', 'patch', 'response', 'containment', 'incident'];
    }
}

/**
 * 7. RE-Automata - Reverse Engineering Agent
 */
class REAutomataAgent extends ExpertAgent {
    constructor(llmService, modelName) {
        super('RE_AUTOMATA', llmService, modelName);
        this.reTasks = ['malware_analysis', 'binary_disassembly', 'obfuscation_defeat', 'payload_extraction'];
    }

    generateRandomScenario() {
        const task = this.reTasks[Math.floor(Math.random() * this.reTasks.length)];
        const scenarios = {
            malware_analysis: 'Analyze unknown malware sample in sandbox. Identify C2, persistence, and IOCs.',
            binary_disassembly: 'Reverse engineer suspicious binary to understand its functionality.',
            obfuscation_defeat: 'Deobfuscate heavily packed malware to reveal true payload.',
            payload_extraction: 'Extract embedded payload from dropper malware for further analysis.'
        };
        
        return {
            type: `reverse_${task}`,
            difficulty: 'hard',
            context: scenarios[task]
        };
    }

    getSystemPrompt() {
        return `You are RE-Automata, a reverse engineering specialist. Your skills:
- Static and dynamic analysis
- Disassembly (IDA, Ghidra, radare2)
- Malware unpacking and deobfuscation
- Sandbox analysis
- IOC extraction

Provide detailed reverse engineering analysis.`;
    }

    getTechnicalKeywords() {
        return ['disassembly', 'malware', 'reverse', 'IOC', 'payload', 'sandbox', 'obfuscation'];
    }
}

/**
 * 8. ForensicLens - Digital Forensics Agent
 */
class ForensicLensAgent extends ExpertAgent {
    constructor(llmService, modelName) {
        super('FORENSIC_LENS', llmService, modelName);
        this.forensicTasks = ['disk_analysis', 'memory_forensics', 'log_analysis', 'timeline_reconstruction'];
    }

    generateRandomScenario() {
        const task = this.forensicTasks[Math.floor(Math.random() * this.forensicTasks.length)];
        const scenarios = {
            disk_analysis: 'Analyze disk image from compromised server to find evidence of data exfiltration.',
            memory_forensics: 'Examine memory dump for running processes, network connections, and malware.',
            log_analysis: 'Correlate logs from firewall, IDS, and SIEM to reconstruct attack timeline.',
            timeline_reconstruction: 'Build complete timeline of security incident from initial access to exfiltration.'
        };
        
        return {
            type: `forensic_${task}`,
            difficulty: 'hard',
            context: scenarios[task]
        };
    }

    getSystemPrompt() {
        return `You are ForensicLens, a digital forensics expert. Specializations:
- Disk and memory forensics
- Log correlation and analysis
- Timeline reconstruction
- Chain of custody
- Evidence preservation

Provide thorough forensic analysis with actionable findings.`;
    }

    getTechnicalKeywords() {
        return ['forensic', 'evidence', 'timeline', 'artifact', 'log', 'memory', 'disk'];
    }
}

/**
 * 9. ThreatOracle - Strategic Threat Intelligence Agent
 */
class ThreatOracleAgent extends ExpertAgent {
    constructor(llmService, modelName) {
        super('THREAT_ORACLE', llmService, modelName);
        this.intelTasks = ['apt_tracking', 'zero_day_monitoring', 'ttp_analysis', 'geopolitical_correlation'];
    }

    generateRandomScenario() {
        const task = this.intelTasks[Math.floor(Math.random() * this.intelTasks.length)];
        const scenarios = {
            apt_tracking: 'Track APT28 (Fancy Bear) latest campaigns and predict next likely targets.',
            zero_day_monitoring: 'Analyze newly disclosed zero-day in Exchange Server. Assess organizational risk.',
            ttp_analysis: 'Map observed TTPs to MITRE ATT&CK framework and identify threat actor.',
            geopolitical_correlation: 'Correlate cyber attacks with geopolitical events to predict threat landscape.'
        };
        
        return {
            type: `threat_intel_${task}`,
            difficulty: 'hard',
            context: scenarios[task]
        };
    }

    getSystemPrompt() {
        return `You are ThreatOracle, a strategic threat intelligence agent. Your expertise:
- APT group tracking and analysis
- Zero-day vulnerability assessment
- MITRE ATT&CK framework
- Geopolitical cyber threat analysis
- Predictive threat modeling

Provide strategic intelligence with actionable recommendations.`;
    }

    getTechnicalKeywords() {
        return ['APT', 'zero-day', 'TTP', 'MITRE', 'threat', 'intelligence', 'campaign'];
    }
}

/**
 * 10. AdversarySim - Adversarial Simulation Agent
 */
class AdversarySimAgent extends ExpertAgent {
    constructor(llmService, modelName) {
        super('ADVERSARY_SIM', llmService, modelName);
        this.simScenarios = ['apt_simulation', 'ransomware_drill', 'insider_threat', 'supply_chain_attack'];
    }

    generateRandomScenario() {
        const scenario = this.simScenarios[Math.floor(Math.random() * this.simScenarios.length)];
        const scenarios = {
            apt_simulation: 'Simulate APT29 attack campaign from initial phishing to data exfiltration.',
            ransomware_drill: 'Execute ransomware simulation to test detection and response capabilities.',
            insider_threat: 'Simulate malicious insider exfiltrating intellectual property.',
            supply_chain_attack: 'Test defenses against supply chain attack via compromised software update.'
        };
        
        return {
            type: `adversary_${scenario}`,
            difficulty: 'hard',
            context: scenarios[scenario]
        };
    }

    getSystemPrompt() {
        return `You are AdversarySim, an adversarial simulation specialist. Your capabilities:
- MITRE ATT&CK-based simulations
- APT group tactic reproduction
- Purple team exercises
- Attack path validation
- Defense gap identification

Create realistic adversary simulations for security testing.`;
    }

    getTechnicalKeywords() {
        return ['simulation', 'ATT&CK', 'adversary', 'emulation', 'purple team', 'tactic'];
    }
}

module.exports = {
    VulnScoutAgent,
    NetPsycheAgent,
    NetPhantomAgent,
    CryptoWardenAgent,
    DeepMapperAgent,
    CyberShieldAgent,
    REAutomataAgent,
    ForensicLensAgent,
    ThreatOracleAgent,
    AdversarySimAgent
};
