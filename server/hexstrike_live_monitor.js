/**
 * HexStrike Live Training Monitor
 * 
 * Boucle continue qui enseigne les commandes de chaque outil HexStrike
 * en temps réel avec explications éducatives.
 */

const EventEmitter = require('events');
const LLMService = require('./llm_service');

class HexStrikeLiveMonitor extends EventEmitter {
    constructor() {
        super();
        this.llmService = new LLMService();
        this.isRunning = false;
        this.currentExpertIndex = 0;
        this.intervalMs = 30000; // 30 secondes entre chaque leçon
        this.loopTimer = null;

        // Liste de tous les experts HexStrike avec leurs commandes exemples
        this.experts = [
            {
                id: 'nmap', name: 'Nmap Master', emoji: '🔬',
                commands: ['nmap -sS -sV -O target', 'nmap -p- -T4 target', 'nmap --script vuln target']
            },
            {
                id: 'masscan', name: 'Masscan Expert', emoji: '⚡',
                commands: ['masscan -p80,443 10.0.0.0/8 --rate 10000', 'masscan --banners -p80 target']
            },
            {
                id: 'rustscan', name: 'RustScan Expert', emoji: '🦀',
                commands: ['rustscan -a target', 'rustscan -a target -- -sC -sV']
            },
            {
                id: 'amass', name: 'Amass Expert', emoji: '🕸️',
                commands: ['amass enum -d domain.com', 'amass intel -whois -d domain.com']
            },
            {
                id: 'subfinder', name: 'Subfinder Expert', emoji: '🔎',
                commands: ['subfinder -d domain.com -all', 'subfinder -dL domains.txt']
            },
            {
                id: 'httpx', name: 'HTTPX Expert', emoji: '📡',
                commands: ['httpx -l urls.txt -tech-detect', 'httpx -sc -title -td']
            },
            {
                id: 'katana', name: 'Katana Expert', emoji: '🗡️',
                commands: ['katana -u url -jc -d 3', 'katana -u url -f form-fields']
            },
            {
                id: 'gobuster', name: 'Gobuster Expert', emoji: '🔨',
                commands: ['gobuster dir -u url -w wordlist', 'gobuster dns -d domain -w wordlist']
            },
            {
                id: 'feroxbuster', name: 'Feroxbuster Expert', emoji: '🦾',
                commands: ['feroxbuster -u url -w wordlist', 'feroxbuster -u url --smart']
            },
            {
                id: 'ffuf', name: 'FFUF Expert', emoji: '🎯',
                commands: ['ffuf -u url/FUZZ -w wordlist', 'ffuf -u url -X POST -d "param=FUZZ"']
            },
            {
                id: 'nuclei', name: 'Nuclei Expert', emoji: '☢️',
                commands: ['nuclei -u url -t cves/', 'nuclei -l urls.txt -severity critical,high']
            },
            {
                id: 'nikto', name: 'Nikto Expert', emoji: '🔧',
                commands: ['nikto -h url', 'nikto -h url -Tuning x']
            },
            {
                id: 'dalfox', name: 'Dalfox Expert', emoji: '🦊',
                commands: ['dalfox url url', 'dalfox file urls.txt --blind xss.hunter']
            },
            {
                id: 'sqlmap', name: 'SQLMap Expert', emoji: '💾',
                commands: ['sqlmap -u "url?id=1" --dbs', 'sqlmap -r request.txt --level 5 --risk 3']
            },
            {
                id: 'metasploit', name: 'Metasploit Expert', emoji: '💉',
                commands: ['use exploit/windows/smb/ms17_010_eternalblue', 'search type:exploit platform:windows']
            },
            {
                id: 'hydra', name: 'Hydra Expert', emoji: '🐉',
                commands: ['hydra -l admin -P wordlist ssh://target', 'hydra -L users -P pass http-form-post://']
            },
            {
                id: 'john', name: 'John Expert', emoji: '🔓',
                commands: ['john --wordlist=rockyou.txt hash.txt', 'john --format=raw-md5 hash.txt']
            },
            {
                id: 'hashcat', name: 'Hashcat Expert', emoji: '⚡',
                commands: ['hashcat -m 0 hash.txt wordlist.txt', 'hashcat -a 3 hash.txt ?a?a?a?a?a?a']
            },
            {
                id: 'wireshark', name: 'Wireshark Expert', emoji: '🦈',
                commands: ['tshark -i eth0 -w capture.pcap', 'tshark -r file.pcap -Y "http.request"']
            },
            {
                id: 'sherlock', name: 'Sherlock Expert', emoji: '🕵️',
                commands: ['sherlock username', 'sherlock -o results.txt username']
            },
            {
                id: 'theharvester', name: 'TheHarvester Expert', emoji: '🌾',
                commands: ['theHarvester -d domain.com -b google', 'theHarvester -d domain.com -b all']
            },
            {
                id: 'prowler', name: 'Prowler Expert', emoji: '🦉',
                commands: ['prowler aws', 'prowler azure --subscription-id xxx']
            },
            {
                id: 'trivy', name: 'Trivy Expert', emoji: '🐋',
                commands: ['trivy image imagename', 'trivy fs --security-checks vuln,config /']
            },
            {
                id: 'ghidra', name: 'Ghidra Expert', emoji: '👻',
                commands: ['ghidraRun', 'analyzeHeadless project/ folder -import binary']
            },
            {
                id: 'radare2', name: 'Radare2 Expert', emoji: '🔧',
                commands: ['r2 binary', 'aaa; afl; pdf @ main']
            },
            {
                id: 'checksec', name: 'Checksec Expert', emoji: '🛡️',
                commands: ['checksec --file=binary', 'checksec --proc-all']
            }
        ];

        console.log(`[LIVE-MONITOR] 🎓 HexStrike Live Training Monitor initialized with ${this.experts.length} experts`);
    }

    /**
     * Démarrer le monitoring en boucle continue
     */
    start(intervalSeconds = 30) {
        if (this.isRunning) {
            console.log('[LIVE-MONITOR] Already running');
            return;
        }

        this.intervalMs = intervalSeconds * 1000;
        this.isRunning = true;
        this.currentExpertIndex = 0;

        console.log(`[LIVE-MONITOR] 🚀 Starting continuous training loop (${intervalSeconds}s interval)`);
        this.emit('monitor:start', { experts: this.experts.length, interval: intervalSeconds });

        // Première leçon immédiate
        this.teachNextLesson();

        // Boucle continue
        this.loopTimer = setInterval(() => {
            if (this.isRunning) {
                this.teachNextLesson();
            }
        }, this.intervalMs);
    }

    /**
     * Arrêter le monitoring
     */
    stop() {
        this.isRunning = false;
        if (this.loopTimer) {
            clearInterval(this.loopTimer);
            this.loopTimer = null;
        }
        console.log('[LIVE-MONITOR] ⏹️ Training loop stopped');
        this.emit('monitor:stop');
    }

    /**
     * Enseigner la prochaine leçon
     */
    async teachNextLesson() {
        const expert = this.experts[this.currentExpertIndex];
        const command = expert.commands[Math.floor(Math.random() * expert.commands.length)];

        console.log(`\n[LIVE-MONITOR] 📚 Teaching ${expert.emoji} ${expert.name}: ${command}`);
        this.emit('monitor:teaching', { expert: expert.name, command });

        try {
            const lesson = await this.generateLesson(expert, command);

            // Émettre la leçon
            this.emit('monitor:lesson', {
                expert: expert.name,
                emoji: expert.emoji,
                command: command,
                lesson: lesson,
                timestamp: new Date().toISOString()
            });

            console.log(`[LIVE-MONITOR] ✅ Lesson complete: ${expert.name}`);

        } catch (error) {
            console.error(`[LIVE-MONITOR] ❌ Error teaching ${expert.name}:`, error.message);
            this.emit('monitor:error', { expert: expert.name, error: error.message });
        }

        // Passer au prochain expert (boucle infinie)
        this.currentExpertIndex = (this.currentExpertIndex + 1) % this.experts.length;
    }

    /**
     * Générer une leçon éducative pour une commande
     */
    async generateLesson(expert, command) {
        const prompt = `Tu es ${expert.name}, expert HexStrike spécialisé dans ton outil.

COMMANDE À ENSEIGNER: ${command}

Génère une LEÇON ÉDUCATIVE en français avec:

## 📝 Ce que fait cette commande
[Explication technique claire de la commande]

## 🎯 Pourquoi on l'utilise
[Justification et cas d'usage réels]

## 🔍 Scénarios appropriés
[3 scénarios concrets où cette commande est utile]

## ⚠️ Précautions
[Considérations de sécurité et légalité]

## 💡 Variantes utiles
[2-3 variations de la commande pour différents cas]

Sois concis mais complet. Réponds comme un formateur expert en cybersécurité.`;

        const response = await this.llmService.generateResponse(
            prompt,
            null,
            'hackergpt',
            'gemini-3-pro-preview',
            `Tu es ${expert.name}, un expert en cybersécurité éthique sur Kali Linux.`
        );

        return response;
    }

    /**
     * Obtenir le statut actuel
     */
    getStatus() {
        return {
            isRunning: this.isRunning,
            currentExpert: this.experts[this.currentExpertIndex]?.name || 'None',
            totalExperts: this.experts.length,
            intervalSeconds: this.intervalMs / 1000,
            nextLessonIn: this.isRunning ? 'Active' : 'Stopped'
        };
    }

    /**
     * Forcer une leçon sur un expert spécifique
     */
    async teachExpert(expertId) {
        const expert = this.experts.find(e => e.id === expertId);
        if (!expert) {
            throw new Error(`Expert ${expertId} not found`);
        }

        const command = expert.commands[0];
        console.log(`[LIVE-MONITOR] 📚 Manual lesson: ${expert.emoji} ${expert.name}`);

        const lesson = await this.generateLesson(expert, command);

        return {
            expert: expert.name,
            emoji: expert.emoji,
            command: command,
            lesson: lesson,
            timestamp: new Date().toISOString()
        };
    }
    /**
     * Forcer une leçon personnalisée (ex: Activée par un scénario)
     */
    forceLesson(lessonData) {
        console.log(`[LIVE-MONITOR] 🚨 Forcing lesson: ${lessonData.expert}`);
        this.emit('monitor:lesson', lessonData);
        // Reset timer to avoid immediate overwrite
        if (this.loopTimer) {
            clearInterval(this.loopTimer);
            this.loopTimer = setInterval(() => {
                if (this.isRunning) {
                    this.teachNextLesson();
                }
            }, this.intervalMs);
        }
    }
}

module.exports = HexStrikeLiveMonitor;
