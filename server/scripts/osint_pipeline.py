#!/usr/bin/env python3
"""
OSINT Expert Team Pipeline 2025
================================
Équipe d'experts combinant:
- qwen2.5-coder:7b (Analyste technique)
- mistral:7b-instruct (Stratège de renseignement)

Intègre les 10 outils OSINT phares de 2025:
SpiderFoot, Amass, Photon, Maltego, theHarvester,
Shodan, Hunter.io, IntelOwl, Social-Analyzer, Recon-ng
"""

import subprocess
import requests
import json
import os
import sys
import argparse
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================
# CONFIGURATION
# ============================================

@dataclass
class Config:
    # API Keys (from environment)
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
    HUNTER_API_KEY: str = os.getenv("HUNTER_API_KEY", "")
    INTELOWL_API_KEY: str = os.getenv("INTELOWL_API_KEY", "")
    
    # Ollama Configuration
    OLLAMA_URL: str = os.getenv("OLLAMA_URL", "http://localhost:11434")
    TECHNICAL_MODEL: str = "qwen2.5-coder:7b"  # Analyste technique
    STRATEGIST_MODEL: str = "mistral:7b-instruct"  # Stratège
    FALLBACK_MODEL: str = "qwen2.5:3b"  # Fallback léger
    
    # Paths
    OUTPUT_DIR: str = "osint_results"
    TOOLS_PATH: str = "/usr/bin"  # Kali Linux default
    
    # SpiderFoot API (if running)
    SPIDERFOOT_URL: str = "http://localhost:5001"
    
    # IntelOwl
    INTELOWL_URL: str = "http://localhost:8080"

config = Config()

# ============================================
# UTILITIES
# ============================================

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def log(message: str, level: str = "info"):
    colors = {
        "info": Colors.CYAN,
        "success": Colors.GREEN,
        "warning": Colors.YELLOW,
        "error": Colors.RED,
        "header": Colors.HEADER + Colors.BOLD
    }
    color = colors.get(level, Colors.CYAN)
    print(f"{color}[{level.upper()}]{Colors.END} {message}")

def safe_mkdir(path: str):
    if not os.path.exists(path):
        os.makedirs(path)

def run_command(cmd: str, timeout: int = 300) -> tuple[bool, str]:
    """Execute shell command with timeout"""
    log(f"Executing: {cmd[:80]}...", "info")
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=timeout
        )
        return True, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)

def save_result(filename: str, data: Any, output_dir: str = None):
    """Save results to file"""
    output_dir = output_dir or config.OUTPUT_DIR
    filepath = os.path.join(output_dir, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        if isinstance(data, (dict, list)):
            json.dump(data, f, indent=2, ensure_ascii=False)
        else:
            f.write(str(data))
    log(f"Saved: {filepath}", "success")

def load_result(filename: str, output_dir: str = None) -> Optional[Any]:
    """Load results from file"""
    output_dir = output_dir or config.OUTPUT_DIR
    filepath = os.path.join(output_dir, filename)
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            if filename.endswith('.json'):
                return json.load(f)
            return f.read()
    except:
        return None

# ============================================
# OLLAMA LLM INTEGRATION
# ============================================

class OllamaAgent:
    """Agent LLM via Ollama pour analyse OSINT"""
    
    def __init__(self, model: str, role: str, system_prompt: str):
        self.model = model
        self.role = role
        self.system_prompt = system_prompt
        self.url = f"{config.OLLAMA_URL}/api/generate"
    
    def analyze(self, prompt: str, temperature: float = 0.4) -> str:
        """Envoyer une requête à Ollama"""
        full_prompt = f"{self.system_prompt}\n\n{prompt}"
        
        try:
            response = requests.post(
                self.url,
                json={
                    "model": self.model,
                    "prompt": full_prompt,
                    "stream": False,
                    "options": {
                        "temperature": temperature,
                        "num_predict": 2000
                    }
                },
                timeout=120
            )
            
            if response.ok:
                return response.json().get("response", "")
            else:
                # Try fallback model
                log(f"Model {self.model} failed, trying fallback...", "warning")
                response = requests.post(
                    self.url,
                    json={
                        "model": config.FALLBACK_MODEL,
                        "prompt": full_prompt,
                        "stream": False
                    },
                    timeout=120
                )
                return response.json().get("response", "")
                
        except Exception as e:
            log(f"Ollama error: {e}", "error")
            return f"[LLM Error: {str(e)}]"

# Create specialized agents
TECHNICAL_ANALYST = OllamaAgent(
    model=config.TECHNICAL_MODEL,
    role="Analyste Technique",
    system_prompt="""Tu es un ANALYSTE TECHNIQUE OSINT senior.
ENVIRONNEMENT: Kali Linux 2024.1
SPÉCIALITÉS: SpiderFoot, Amass, Photon, Maltego, theHarvester
COMPÉTENCES: Scripting, parsing, extraction de données, automatisation
FORMAT: Réponds en français, de manière technique et structurée.
Génère des commandes Kali Linux précises et exploitables."""
)

INTELLIGENCE_STRATEGIST = OllamaAgent(
    model=config.STRATEGIST_MODEL,
    role="Stratège de Renseignement",
    system_prompt="""Tu es un STRATÈGE DE RENSEIGNEMENT OSINT.
ENVIRONNEMENT: Kali Linux 2024.1
SPÉCIALITÉS: Shodan, Hunter.io, IntelOwl, Social-Analyzer, Recon-ng
COMPÉTENCES: Analyse stratégique, corrélation, synthèse, priorisation
FORMAT: Réponds en français. Priorise les findings par criticité.
Identifie les patterns et propose des actions concrètes."""
)

# ============================================
# OSINT TOOLS
# ============================================

class OSINTTool:
    """Base class for OSINT tools"""
    
    name: str = "Base Tool"
    category: str = "Unknown"
    
    def __init__(self, target: str, output_dir: str):
        self.target = target
        self.output_dir = output_dir
        self.results = {}
    
    def run(self) -> Dict:
        raise NotImplementedError
    
    def parse_results(self, raw_output: str) -> Dict:
        return {"raw": raw_output}


class TheHarvesterTool(OSINTTool):
    """theHarvester - Email/Domain reconnaissance"""
    
    name = "theHarvester"
    category = "Email/Domain OSINT"
    
    def run(self) -> Dict:
        log(f"🌾 Running {self.name}...", "header")
        
        output_file = os.path.join(self.output_dir, "theharvester")
        cmd = f"theHarvester -d {self.target} -l 200 -b all -f {output_file}"
        
        success, output = run_command(cmd, timeout=300)
        
        self.results = {
            "tool": self.name,
            "target": self.target,
            "success": success,
            "output": output,
            "files_generated": [f"{output_file}.xml", f"{output_file}.json"]
        }
        
        # Parse JSON output if exists
        try:
            with open(f"{output_file}.json", 'r') as f:
                self.results["parsed"] = json.load(f)
        except:
            self.results["parsed"] = self.parse_results(output)
        
        return self.results


class AmassTool(OSINTTool):
    """OWASP Amass - DNS Enumeration"""
    
    name = "Amass"
    category = "DNS Enumeration"
    
    def run(self) -> Dict:
        log(f"📡 Running {self.name}...", "header")
        
        output_file = os.path.join(self.output_dir, "amass.txt")
        cmd = f"amass enum -passive -d {self.target} -o {output_file}"
        
        success, output = run_command(cmd, timeout=600)
        
        # Parse subdomains
        subdomains = []
        try:
            with open(output_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        except:
            pass
        
        self.results = {
            "tool": self.name,
            "target": self.target,
            "success": success,
            "subdomains_count": len(subdomains),
            "subdomains": subdomains[:100],  # Limit for JSON size
            "output_file": output_file
        }
        
        return self.results


class ShodanTool(OSINTTool):
    """Shodan - IoT/Banner Search"""
    
    name = "Shodan"
    category = "Search Engines"
    
    def run(self) -> Dict:
        log(f"🔍 Running {self.name}...", "header")
        
        if not config.SHODAN_API_KEY:
            return {"tool": self.name, "error": "SHODAN_API_KEY not configured"}
        
        results = {
            "tool": self.name,
            "target": self.target,
            "host_info": None,
            "search_results": None
        }
        
        try:
            # Resolve domain to IP
            success, ip_output = run_command(f"dig +short {self.target}")
            ip = ip_output.strip().split('\n')[0] if success else None
            
            if ip:
                # Get host info
                url = f"https://api.shodan.io/shodan/host/{ip}?key={config.SHODAN_API_KEY}"
                response = requests.get(url, timeout=30)
                if response.ok:
                    results["host_info"] = response.json()
            
            # Search for domain
            search_url = f"https://api.shodan.io/shodan/host/search?key={config.SHODAN_API_KEY}&query=hostname:{self.target}"
            response = requests.get(search_url, timeout=30)
            if response.ok:
                results["search_results"] = response.json()
            
            results["success"] = True
            
        except Exception as e:
            results["error"] = str(e)
            results["success"] = False
        
        self.results = results
        return results


class HunterIOTool(OSINTTool):
    """Hunter.io - Email Discovery"""
    
    name = "Hunter.io"
    category = "Email Discovery"
    
    def run(self) -> Dict:
        log(f"📧 Running {self.name}...", "header")
        
        if not config.HUNTER_API_KEY:
            return {"tool": self.name, "error": "HUNTER_API_KEY not configured"}
        
        results = {
            "tool": self.name,
            "target": self.target,
            "emails": [],
            "domain_info": None
        }
        
        try:
            url = f"https://api.hunter.io/v2/domain-search?domain={self.target}&api_key={config.HUNTER_API_KEY}"
            response = requests.get(url, timeout=30)
            
            if response.ok:
                data = response.json()
                results["domain_info"] = data.get("data", {}).get("domain")
                results["emails"] = [
                    {
                        "email": e.get("value"),
                        "type": e.get("type"),
                        "confidence": e.get("confidence"),
                        "first_name": e.get("first_name"),
                        "last_name": e.get("last_name"),
                        "position": e.get("position")
                    }
                    for e in data.get("data", {}).get("emails", [])
                ]
                results["success"] = True
            else:
                results["error"] = response.text
                results["success"] = False
                
        except Exception as e:
            results["error"] = str(e)
            results["success"] = False
        
        self.results = results
        return results


class SpiderFootTool(OSINTTool):
    """SpiderFoot - Automated OSINT"""
    
    name = "SpiderFoot"
    category = "Automated OSINT"
    
    def run(self) -> Dict:
        log(f"🕷️ Running {self.name}...", "header")
        
        results = {
            "tool": self.name,
            "target": self.target,
            "scan_id": None,
            "modules": []
        }
        
        try:
            # Check if SpiderFoot API is available
            status = requests.get(f"{config.SPIDERFOOT_URL}/scanstatus", timeout=5)
            
            if status.ok:
                # Start a new scan
                scan_data = {
                    "scanname": f"OSINT_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                    "scantarget": self.target,
                    "usecase": "passive",
                    "modulelist": ""
                }
                
                response = requests.post(
                    f"{config.SPIDERFOOT_URL}/startscan",
                    data=scan_data,
                    timeout=30
                )
                
                if response.ok:
                    results["scan_id"] = response.text
                    results["success"] = True
                    results["note"] = "Scan started. Results available in SpiderFoot UI."
                else:
                    results["error"] = "Failed to start scan"
                    results["success"] = False
            else:
                results["error"] = "SpiderFoot API not available"
                results["success"] = False
                
        except requests.exceptions.ConnectionError:
            # SpiderFoot not running, try CLI
            log("SpiderFoot API not available, trying CLI...", "warning")
            output_file = os.path.join(self.output_dir, "spiderfoot.json")
            cmd = f"spiderfoot -s {self.target} -t Domain -o {output_file} 2>/dev/null"
            success, output = run_command(cmd, timeout=600)
            results["success"] = success
            results["output"] = output[:500] if not success else "Results saved"
            
        except Exception as e:
            results["error"] = str(e)
            results["success"] = False
        
        self.results = results
        return results


class ReconNgTool(OSINTTool):
    """Recon-ng - Reconnaissance Framework"""
    
    name = "Recon-ng"
    category = "Reconnaissance Framework"
    
    def run(self) -> Dict:
        log(f"🔬 Running {self.name}...", "header")
        
        # Create Recon-ng commands file
        commands = f"""
workspaces create osint_{self.target.replace('.', '_')}
db insert domains {self.target}
modules load recon/domains-hosts/hackertarget
run
modules load recon/hosts-hosts/resolve
run
show hosts
exit
"""
        cmd_file = os.path.join(self.output_dir, "reconng_commands.rc")
        with open(cmd_file, 'w') as f:
            f.write(commands)
        
        success, output = run_command(f"recon-ng -r {cmd_file}", timeout=300)
        
        self.results = {
            "tool": self.name,
            "target": self.target,
            "success": success,
            "output": output,
            "commands_executed": commands.strip().split('\n')
        }
        
        return self.results


class SocialAnalyzerTool(OSINTTool):
    """Social-Analyzer - Social Media Analysis"""
    
    name = "Social-Analyzer"
    category = "Social Networks"
    
    def run(self) -> Dict:
        log(f"📱 Running {self.name}...", "header")
        
        output_file = os.path.join(self.output_dir, "social_analyzer.json")
        cmd = f"python3 -m social_analyzer --username {self.target} --metadata --output json > {output_file}"
        
        success, output = run_command(cmd, timeout=300)
        
        results = {
            "tool": self.name,
            "target": self.target,
            "success": success
        }
        
        try:
            with open(output_file, 'r') as f:
                results["profiles"] = json.load(f)
        except:
            results["output"] = output
        
        self.results = results
        return results

# ============================================
# PIPELINE ORCHESTRATOR
# ============================================

class OSINTPipeline:
    """
    OSINT Investigation Pipeline
    Orchestrates tools and LLM analysis
    """
    
    def __init__(self, target: str, target_type: str = "domain"):
        self.target = target
        self.target_type = target_type
        self.output_dir = os.path.join(
            config.OUTPUT_DIR, 
            f"{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        safe_mkdir(self.output_dir)
        
        self.results = {
            "target": target,
            "target_type": target_type,
            "start_time": datetime.now().isoformat(),
            "steps": [],
            "tools_results": {},
            "llm_analysis": {},
            "summary": None
        }
        
        # Tool mapping by step
        self.step_tools = {
            1: [TheHarvesterTool, HunterIOTool],
            2: [AmassTool, SpiderFootTool],
            3: [ShodanTool, ReconNgTool],
            4: [SocialAnalyzerTool]
        }
    
    def run_step(self, step_num: int) -> Dict:
        """Execute a single pipeline step"""
        log(f"\n{'='*60}", "header")
        log(f"STEP {step_num}: {self.get_step_name(step_num)}", "header")
        log(f"{'='*60}\n", "header")
        
        step_results = {
            "step": step_num,
            "name": self.get_step_name(step_num),
            "tools": [],
            "start_time": datetime.now().isoformat()
        }
        
        # Get tools for this step
        tools = self.step_tools.get(step_num, [])
        
        # Run tools in parallel
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}
            for ToolClass in tools:
                tool = ToolClass(self.target, self.output_dir)
                futures[executor.submit(tool.run)] = tool.name
            
            for future in as_completed(futures):
                tool_name = futures[future]
                try:
                    result = future.result()
                    step_results["tools"].append(result)
                    self.results["tools_results"][tool_name] = result
                    save_result(f"{tool_name.lower().replace(' ', '_')}.json", result, self.output_dir)
                except Exception as e:
                    step_results["tools"].append({
                        "tool": tool_name,
                        "error": str(e)
                    })
        
        step_results["end_time"] = datetime.now().isoformat()
        self.results["steps"].append(step_results)
        
        return step_results
    
    def get_step_name(self, step_num: int) -> str:
        names = {
            1: "Recherche initiale (emails/domaines)",
            2: "Énumération passive et active",
            3: "Analyse de surface d'attaque",
            4: "Validation et corrélation"
        }
        return names.get(step_num, f"Step {step_num}")
    
    def llm_analyze_step(self, step_num: int, step_results: Dict) -> str:
        """Use LLM to analyze step results"""
        agent = TECHNICAL_ANALYST if step_num in [1, 2] else INTELLIGENCE_STRATEGIST
        
        prompt = f"""## Analyse des résultats - {self.get_step_name(step_num)}

Cible: {self.target}

Résultats des outils:
```json
{json.dumps(step_results, indent=2, default=str)[:3000]}
```

Analyse ces résultats et fournis:
1. Synthèse des findings importants
2. Éléments à investiguer davantage
3. Risques identifiés
4. Recommandations pour l'étape suivante"""
        
        log(f"🤖 {agent.role} analyse les résultats...", "info")
        analysis = agent.analyze(prompt)
        
        self.results["llm_analysis"][f"step_{step_num}"] = {
            "agent": agent.role,
            "model": agent.model,
            "analysis": analysis
        }
        
        return analysis
    
    def generate_final_report(self) -> str:
        """Generate final investigation report using LLM"""
        log("\n📝 Generating final report...", "header")
        
        # Combine all results
        combined_results = {
            "target": self.target,
            "tools_executed": list(self.results["tools_results"].keys()),
            "key_findings": {}
        }
        
        # Extract key findings from each tool
        for tool_name, result in self.results["tools_results"].items():
            if result.get("success"):
                if "emails" in result:
                    combined_results["key_findings"]["emails"] = result["emails"][:10]
                if "subdomains" in result:
                    combined_results["key_findings"]["subdomains"] = result["subdomains"][:20]
                if "host_info" in result and result["host_info"]:
                    combined_results["key_findings"]["shodan_host"] = {
                        "ip": result["host_info"].get("ip_str"),
                        "ports": result["host_info"].get("ports", [])[:10],
                        "vulns": result["host_info"].get("vulns", [])
                    }
        
        prompt = f"""## RAPPORT FINAL D'INVESTIGATION OSINT

Cible: {self.target}
Type: {self.target_type}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}

### Résultats combinés:
```json
{json.dumps(combined_results, indent=2, default=str)[:4000]}
```

### Analyses précédentes:
{json.dumps(self.results.get("llm_analysis", {}), indent=2, default=str)[:2000]}

---

Génère un RAPPORT EXÉCUTIF complet incluant:

1. **RÉSUMÉ EXÉCUTIF** (3-5 phrases)
2. **SURFACE D'ATTAQUE IDENTIFIÉE**
   - Sous-domaines découverts
   - Services exposés
   - Emails et employés
3. **VULNÉRABILITÉS ET RISQUES** (classés par criticité)
4. **RECOMMANDATIONS** (actions immédiates + long terme)
5. **PROCHAINES ÉTAPES** suggérées

Format le rapport de manière professionnelle."""

        report = INTELLIGENCE_STRATEGIST.analyze(prompt, temperature=0.3)
        
        self.results["summary"] = report
        self.results["end_time"] = datetime.now().isoformat()
        
        return report
    
    def run_full_pipeline(self, with_analysis: bool = True) -> Dict:
        """Run the complete OSINT pipeline"""
        log(f"\n{'#'*60}", "header")
        log(f"  OSINT EXPERT TEAM 2025 - INVESTIGATION PIPELINE", "header")
        log(f"  Target: {self.target} ({self.target_type})", "header")
        log(f"{'#'*60}\n", "header")
        
        # Execute all steps
        for step_num in range(1, 5):
            step_results = self.run_step(step_num)
            
            # LLM analysis after each step
            if with_analysis:
                analysis = self.llm_analyze_step(step_num, step_results)
                print(f"\n{Colors.CYAN}--- Analyse ---{Colors.END}")
                print(analysis[:500] + "..." if len(analysis) > 500 else analysis)
            
            time.sleep(1)  # Rate limiting
        
        # Generate final report
        if with_analysis:
            report = self.generate_final_report()
            print(f"\n{Colors.GREEN}{'='*60}{Colors.END}")
            print(f"{Colors.BOLD}RAPPORT FINAL{Colors.END}")
            print(f"{Colors.GREEN}{'='*60}{Colors.END}")
            print(report)
        
        # Save all results
        save_result("full_investigation.json", self.results, self.output_dir)
        save_result("report.md", self.results.get("summary", ""), self.output_dir)
        
        log(f"\n✅ Investigation complete. Results saved in: {self.output_dir}", "success")
        
        return self.results


# ============================================
# CLI INTERFACE
# ============================================

def main():
    parser = argparse.ArgumentParser(
        description="OSINT Expert Team 2025 - Automated Investigation Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python osint_pipeline.py example.com
  python osint_pipeline.py example.com --type domain --no-analysis
  python osint_pipeline.py john.doe --type username --step 1
        """
    )
    
    parser.add_argument("target", help="Target (domain, email, username, IP)")
    parser.add_argument("--type", "-t", default="domain",
                       choices=["domain", "email", "username", "ip"],
                       help="Target type")
    parser.add_argument("--step", "-s", type=int,
                       help="Run only specific step (1-4)")
    parser.add_argument("--no-analysis", action="store_true",
                       help="Skip LLM analysis")
    parser.add_argument("--output", "-o", default=None,
                       help="Custom output directory")
    
    args = parser.parse_args()
    
    # Override output dir if specified
    if args.output:
        config.OUTPUT_DIR = args.output
    
    # Create and run pipeline
    pipeline = OSINTPipeline(args.target, args.type)
    
    if args.step:
        # Run single step
        results = pipeline.run_step(args.step)
        if not args.no_analysis:
            pipeline.llm_analyze_step(args.step, results)
    else:
        # Run full pipeline
        pipeline.run_full_pipeline(with_analysis=not args.no_analysis)


if __name__ == "__main__":
    main()
