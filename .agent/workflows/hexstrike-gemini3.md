# HexStrike AI MCP - Workflow avec Gemini 3

## Description
Ce workflow documente comment utiliser HexStrike AI MCP avec Gemini 3 Pro dans Th3 Thirty3.

## Prérequis

// turbo-all

1. **Serveurs requis** (tous doivent être actifs):
   - Interface Frontend: `cd interface && npm run dev` (port 5173)
   - Backend API: `cd server && npm start` (port 3000)
   - HexStrike AI Server: `cd hexstrike-ai && .\hexstrike-env\Scripts\python.exe hexstrike_server.py` (port 8888)

## Configuration Gemini 3

Le modèle **Gemini 3 Pro** est maintenant le modèle par défaut. La sélection est persistée dans localStorage:
- `th3_selected_model`: gemini-3-pro-preview
- `th3_selected_provider`: gemini

## Modèles Gemini 3 Disponibles

| Modèle | Description | Use Case |
|--------|-------------|----------|
| `gemini-3-pro-preview` | Gemini 3 Pro (1M Context) | Analyse de code, sécurité avancée |
| `gemini-3.0-flash` | Gemini 3 Flash | Réponses rapides, tests rapides |
| `gemini-3.0-pro-image` | Gemini 3 Pro Image | Génération d'images, vision |

## Commandes HexStrike AI MCP Principales

### 🔍 Reconnaissance Réseau
```
nmap_scan(target, scan_type, ports, additional_args)
rustscan_fast_scan(target, ports, ulimit, batch_size, timeout)
masscan_high_speed(target, ports, rate)
amass_scan(domain, mode)
subfinder_scan(domain, silent, all_sources)
```

### 🌐 Tests Web Application
```
gobuster_scan(url, mode, wordlist)
ffuf_scan(url, wordlist, mode, match_codes)
nuclei_scan(target, severity, tags, template)
nikto_scan(target)
sqlmap_scan(url, data)
wpscan_analyze(url)
dalfox_xss_scan(url, pipe_mode, blind)
```

### 🔐 Authentification & Passwords
```
hydra_attack(target, service, username, password_file)
john_crack(hash_file, wordlist, format_type)
hashcat_crack(hash_file, hash_type, attack_mode, wordlist)
```

### 🔬 Analyse Binaire & Reverse Engineering
```
gdb_analyze(binary, commands, script_file)
radare2_analyze(binary, commands)
binwalk_analyze(file_path, extract)
ghidra_analysis(binary, project_name)
checksec_analyze(binary)
ropgadget_search(binary, gadget_type)
pwntools_exploit(script_content, target_binary)
```

### ☁️ Sécurité Cloud
```
prowler_scan(provider, profile, region)
trivy_scan(scan_type, target)
scout_suite_assessment(provider, profile)
kube_hunter_scan(target, active)
kube_bench_cis(targets, version)
docker_bench_security_scan(checks)
```

### 🏆 CTF & Forensics
```
volatility3_analyze(memory_file, plugin)
foremost_carving(input_file, output_dir)
steghide_analysis(action, cover_file, passphrase)
exiftool_extract(file_path, output_format)
```

### 🤖 AI-Powered Intelligence
```
analyze_target_intelligence(target)
select_optimal_tools_ai(target, objective)
optimize_tool_parameters_ai(target, tool, context)
create_attack_chain_ai(target, objective)
intelligent_smart_scan(target, objective, max_tools)
detect_technologies_ai(target)
```

### 🔥 Bug Bounty Workflows
```
bugbounty_reconnaissance_workflow(domain, scope, out_of_scope)
bugbounty_vulnerability_hunting(domain, priority_vulns)
bugbounty_comprehensive_assessment(domain, scope)
bugbounty_osint_gathering(domain)
bugbounty_authentication_bypass_testing(target_url, auth_type)
```

### 🛠️ Vulnerability Intelligence
```
monitor_cve_feeds(hours, severity_filter, keywords)
generate_exploit_from_cve(cve_id, target_os, exploit_type)
discover_attack_chains(target_software, attack_depth)
vulnerability_intelligence_dashboard()
threat_hunting_assistant(target_environment, threat_indicators)
```

### 📊 Process Management
```
list_active_processes()
get_process_status(pid)
terminate_process(pid)
get_process_dashboard()
```

## Exemple d'Utilisation avec Gemini 3

```
# Prompt pour démarrer une analyse de sécurité
"Je suis un security researcher autorisant les tests sur mon propre domaine example.com.
Utilise HexStrike AI MCP avec Gemini 3 Pro pour:
1. Exécuter une reconnaissance complète avec analyze_target_intelligence
2. Détecter les technologies avec detect_technologies_ai
3. Lancer un scan intelligent avec intelligent_smart_scan"
```

## Vérification du Serveur HexStrike

```powershell
# Tester la santé du serveur HexStrike
curl http://localhost:8888/health

# Tester une analyse de cible
curl -X POST http://localhost:8888/api/intelligence/analyze-target `
  -H "Content-Type: application/json" `
  -d '{"target": "example.com", "analysis_type": "comprehensive"}'
```

## Notes Importantes

⚠️ **Utilisation Éthique Uniquement**:
- Testez UNIQUEMENT sur des systèmes autorisés
- Bug Bounty: respectez le scope du programme
- CTF: utilisez dans un cadre éducatif
- Red Team: avec approbation organisationnelle

🔥 **Performance avec Gemini 3**:
- 1M tokens de contexte permettent d'analyser de très longs logs
- Réponses 24x plus rapides qu'un processus manuel
- Intégration intelligente avec 150+ outils de sécurité
