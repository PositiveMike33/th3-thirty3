/**
 * OSINT Expert Agents Service - Cloud Enabled
 * Agents spécialisés par outil OSINT avec apprentissage indépendant
 * Utilise LLM Cloud pour l'analyse
 */

const fs = require('fs');
const path = require('path');
const KALI_ENVIRONMENT = require('./config/kali_environment');
const LLMService = require('./llm_service');

class OsintExpertAgentsService {
    constructor() {
        this.dataPath = path.join(__dirname, 'data', 'osint_experts');
        this.model = 'gemini-3-pro-preview';
        this.kaliEnv = KALI_ENVIRONMENT;

        this.llmService = new LLMService();

        this.ensureDataFolder();
        this.initializeAgents();

        console.log(`[OSINT-EXPERTS] Service initialized (Cloud Mode) with ${Object.keys(this.agents).length} experts`);
    }

    ensureDataFolder() {
        if (!fs.existsSync(this.dataPath)) {
            fs.mkdirSync(this.dataPath, { recursive: true });
        }
    }

    /**
     * Configuration de tous les agents experts OSINT par outil
     */
    getOsintToolConfigs() {
        return {
            // Reconnaissance passive
            shodan: {
                name: 'Shodan Expert',
                emoji: '🔍',
                category: 'Search Engines',
                tool: 'Shodan',
                provider: 'gemini',
                description: 'Expert en recherche de dispositifs connectés, IoT, services exposés',
                commands: [
                    'shodan search "apache"',
                    'shodan host 8.8.8.8',
                    'shodan scan submit 10.0.0.0/24',
                    'shodan stats --facets country ssl.cert.issuer.cn:google'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de Shodan.
EXPERTISE: Recherche IoT, services exposés, vulnérabilités, filtres avancés
COMMANDES: search, host, scan, stats, download, parse
FILTRES: port:, country:, org:, ssl:, http.title:, product:, version:
DORKS: webcam, scada, default password, router, database
RÈGLE: Toujours expliquer les risques de sécurité découverts`
            },

            theharvester: {
                name: 'TheHarvester Expert',
                emoji: '🌾',
                category: 'Email/Domain OSINT',
                tool: 'TheHarvester',
                provider: 'gemini',
                description: 'Expert en récolte d\'emails, sous-domaines, IPs, noms',
                commands: [
                    'theHarvester -d example.com -b google',
                    'theHarvester -d example.com -b linkedin -l 500',
                    'theHarvester -d example.com -b all'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de TheHarvester.
EXPERTISE: Récolte emails, sous-domaines, virtual hosts, IPs
SOURCES: google, bing, linkedin, twitter, shodan, virustotal, dnsdumpster
OPTIONS: -d domain, -b source, -l limit, -f output, --dns-lookup
TECHNIQUES: Pivot sur emails découverts, corrélation noms/domaines
RÈGLE: Technique de validation des emails trouvés`
            },

            maltego: {
                name: 'Maltego Expert',
                emoji: '🕸️',
                category: 'Link Analysis',
                tool: 'Maltego',
                provider: 'gemini',
                description: 'Expert en visualisation de liens, graphes relationnels',
                commands: [
                    'maltego: Transform Domain to DNS Names',
                    'maltego: Person to Email, Phone, Social',
                    'maltego: Company to People, Domains'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de Maltego.
EXPERTISE: Link analysis, graph visualization, entity pivoting
TRANSFORMS: DNS, WHOIS, Social, People, Infrastructure
ENTITIES: Person, Domain, IP, Company, Email, Phone, Location
TECHNIQUES: Pivot chains, entity expansion, pattern recognition
RÈGLE: Construire la chaîne de liens logique entre entités`
            },

            reconng: {
                name: 'Recon-ng Expert',
                emoji: '🔬',
                category: 'Reconnaissance Framework',
                tool: 'Recon-ng',
                provider: 'gemini',
                description: 'Expert en framework de reconnaissance modulaire',
                commands: [
                    'recon-ng: marketplace search',
                    'recon-ng: modules load recon/domains-hosts/hackertarget',
                    'recon-ng: run',
                    'recon-ng: db query select * from hosts'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de Recon-ng.
EXPERTISE: Framework modulaire, automatisation recon, base de données
MODULES: domains, hosts, contacts, credentials, netblocks
WORKSPACES: Création, switch, export
DATABASE: Schema, queries, reports
RÈGLE: Chaîner les modules pour enrichissement progressif`
            },

            spiderfoot: {
                name: 'SpiderFoot Expert',
                emoji: '🕷️',
                category: 'Automated OSINT',
                tool: 'SpiderFoot',
                provider: 'gemini',
                description: 'Expert en OSINT automatisé, scans complets',
                commands: [
                    'spiderfoot: New scan > Target: domain.com',
                    'spiderfoot: Module selection > All/Passive/Footprint',
                    'spiderfoot: Export results JSON/CSV'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de SpiderFoot.
EXPERTISE: Scans automatisés, 200+ modules, corrélation
SCAN TYPES: All, Passive Only, Footprint, Investigate
MODULES: DNS, WHOIS, Social, Dark Web, Leaks, Paste sites
INTEGRATIONS: Shodan, VirusTotal, HaveIBeenPwned
RÈGLE: Interpréter les résultats, prioriser les findings`
            },

            amass: {
                name: 'Amass Expert',
                emoji: '📡',
                category: 'DNS Enumeration',
                tool: 'OWASP Amass',
                provider: 'gemini',
                description: 'Expert en énumération DNS et mapping attack surface',
                commands: [
                    'amass enum -d example.com',
                    'amass enum -passive -d example.com',
                    'amass intel -org "Company Name"',
                    'amass viz -d3 -d example.com'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de OWASP Amass.
EXPERTISE: DNS enumeration, subdomain discovery, ASN mapping
MODES: enum (active/passive), intel (organization), viz (graph)
TECHNIQUES: Brute force, permutation, alterations, certificate logs
SOURCES: 20+ data sources, APIs, certificate transparency
RÈGLE: Mapper l'attack surface complète, identifier shadow IT`
            },

            osintframework: {
                name: 'OSINT Framework Expert',
                emoji: '📚',
                category: 'Resource Directory',
                tool: 'OSINT Framework',
                provider: 'gemini',
                description: 'Expert en navigation des ressources OSINT',
                commands: [
                    'osintframework.com: Username search tools',
                    'osintframework.com: Email verification',
                    'osintframework.com: Social networks analysis'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de OSINT Framework et ses outils.
EXPERTISE: Connaissance de 500+ outils OSINT catégorisés
CATEGORIES: Username, Email, Domain, IP, Social, Images, Search
TOOLS: Namechk, Hunter.io, WhatsMyName, Holehe, Sherlock
WORKFLOW: Sélection d'outil adapté au besoin, chaînage
RÈGLE: Recommander le bon outil pour chaque tâche spécifique`
            },

            socialmedia: {
                name: 'Social Media OSINT Expert',
                emoji: '📱',
                category: 'Social Networks',
                tool: 'Social Media Tools',
                provider: 'gemini',
                description: 'Expert en investigation réseaux sociaux',
                commands: [
                    'sherlock username',
                    'holehe email@example.com',
                    'twint -u username --followers',
                    'instaloader profile_name'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de l'OSINT sur réseaux sociaux.
EXPERTISE: Facebook, Twitter, Instagram, LinkedIn, TikTok
OUTILS: Sherlock, Holehe, Twint, Instaloader, Social-Analyzer
TECHNIQUES: Username correlation, photo EXIF, geolocation
ANALYSIS: Timeline, connections, sentiment, metadata
RÈGLE: Respecter vie privée, focus sur informations publiques`
            },

            geoint: {
                name: 'GEOINT Expert',
                emoji: '🗺️',
                category: 'Geospatial Intelligence',
                tool: 'GEOINT Tools',
                provider: 'gemini',
                description: 'Expert en géolocalisation et imagerie satellite',
                commands: [
                    'Google Earth Pro: Historical imagery',
                    'SunCalc: Shadow analysis',
                    'ExifTool -gps image.jpg',
                    'GeoSpy: Photo geolocation AI'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU en GEOINT/géolocalisation.
EXPERTISE: Imagerie satellite, analyse ombre, EXIF GPS, landmarks
OUTILS: Google Earth, Sentinel Hub, SunCalc, ExifTool, Yandex Images
TECHNIQUES: Shadow analysis, chronolocation, landmark matching
VÉRIFICATION: Cross-reference, timeline, metadata validation
RÈGLE: Triangulation multi-sources pour confirmer localisation`
            },

            darkweb: {
                name: 'Dark Web OSINT Expert',
                emoji: '🌑',
                category: 'Dark Web Intelligence',
                tool: 'Dark Web Tools',
                provider: 'gemini',
                description: 'Expert en investigation dark web et leaks',
                commands: [
                    'Ahmia.fi search',
                    'IntelligenceX email/domain search',
                    'HaveIBeenPwned check',
                    'DeHashed credential search'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de l'OSINT Dark Web.
EXPERTISE: Tor, onion sites, leaks, breaches, marketplaces
OUTILS: Ahmia, IntelligenceX, HIBP, DeHashed, Snusbase
SOURCES: Paste sites, forums, marketplaces, leak databases
SÉCURITÉ: Anonymat, OPSEC, Tor best practices
RÈGLE: Légalité, éthique, ne pas acheter sur dark web`
            },

            imagint: {
                name: 'Image OSINT Expert',
                emoji: '🖼️',
                category: 'Image Analysis',
                tool: 'Image OSINT Tools',
                provider: 'gemini',
                description: 'Expert en rétro-ingénierie d\'images',
                commands: [
                    'TinEye reverse image search',
                    'Google Lens analysis',
                    'FotoForensics ELA analysis',
                    'ExifTool -all image.jpg'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de l'OSINT sur images.
EXPERTISE: Reverse image search, EXIF, forensics, face recognition
OUTILS: TinEye, Google Lens, Yandex, FotoForensics, PimEyes
METADATA: EXIF, GPS, camera model, software, timestamps
FORENSICS: ELA, clone detection, manipulation analysis
RÈGLE: Vérifier authenticité, détecter modifications`
            },

            crypto: {
                name: 'Crypto OSINT Expert',
                emoji: '₿',
                category: 'Blockchain Intelligence',
                tool: 'Blockchain OSINT',
                provider: 'gemini',
                description: 'Expert en traçage blockchain et crypto',
                commands: [
                    'Etherscan address lookup',
                    'Blockchain.com explorer',
                    'Chainalysis Reactor trace',
                    'Breadcrumbs.app flow analysis'
                ],
                systemPrompt: `Tu es un EXPERT ABSOLU de l'OSINT blockchain.
EXPERTISE: Bitcoin, Ethereum, tracing, mixers, exchanges
OUTILS: Etherscan, Blockchain.com, Breadcrumbs, Crystal
TECHNIQUES: Address clustering, flow analysis, mixer detection
PATTERNS: Exchange deposits, mixing, tumblers, DEX
RÈGLE: Suivre le flux, identifier les exchanges, wallet profiling`
            }
        };
    }

    /**
     * Initialiser tous les agents
     */
    initializeAgents() {
        this.agents = {};
        const configs = this.getOsintToolConfigs();

        for (const [id, config] of Object.entries(configs)) {
            const knowledgePath = path.join(this.dataPath, `${id}_knowledge.json`);
            let knowledge = {
                interactions: 0,
                learned: [],
                investigations: [],
                successfulTechniques: [],
                commonQueries: {}
            };

            if (fs.existsSync(knowledgePath)) {
                knowledge = JSON.parse(fs.readFileSync(knowledgePath, 'utf8'));
            }

            this.agents[id] = { ...config, knowledge, knowledgePath };
        }
    }

    saveAgentKnowledge(agentId) {
        const agent = this.agents[agentId];
        if (!agent) return;
        fs.writeFileSync(agent.knowledgePath, JSON.stringify(agent.knowledge, null, 2));
    }

    /**
     * Consulter un expert OSINT spécifique
     */
    async consultExpert(agentId, question, context = '') {
        const agent = this.agents[agentId];
        if (!agent) {
            throw new Error(`OSINT Expert "${agentId}" not found`);
        }

        console.log(`[OSINT-EXPERTS] ${agent.emoji} ${agent.name} analyzing (via Gemini)...`);

        // Construire le contexte avec les connaissances apprises
        let learnedContext = '';
        if (agent.knowledge.learned.length > 0) {
            learnedContext = '\n\nTECHNIQUES APPRISES:\n' +
                agent.knowledge.learned.slice(-10).map(l => `- ${l.content}`).join('\n');
        }
        if (agent.knowledge.successfulTechniques.length > 0) {
            learnedContext += '\n\nTECHNIQUES RÉUSSIES:\n' +
                agent.knowledge.successfulTechniques.slice(-5).join('\n');
        }

        const fullPrompt = `${this.kaliEnv.getSystemPrompt()}
${agent.systemPrompt}

OUTIL: ${agent.tool}
COMMANDES PRINCIPALES:
${agent.commands.map(c => `- ${c}`).join('\n')}
${learnedContext}

${context}

QUESTION: ${question}

Réponds en expert ${agent.tool} sur Kali Linux. Sois technique, précis, et donne des commandes compatibles Kali.`;

        try {
            const response = await this.llmService.generateResponse(
                fullPrompt,
                null,
                agent.provider || 'gemini',
                this.model,
                'Tu es un expert en Cybersécurité et OSINT sur Kali Linux.'
            );

            return this.processResponse(agent, agentId, question, response, this.model);

        } catch (error) {
            console.error(`[OSINT-EXPERTS] ${agent.name} error:`, error.message);
            throw error;
        }
    }

    processResponse(agent, agentId, question, response, modelUsed) {
        // Incrémenter et tracker
        agent.knowledge.interactions++;

        // Tracker les queries communes
        const queryKey = question.toLowerCase().substring(0, 50);
        agent.knowledge.commonQueries[queryKey] = (agent.knowledge.commonQueries[queryKey] || 0) + 1;

        this.saveAgentKnowledge(agentId);

        return {
            expert: agent.name,
            emoji: agent.emoji,
            tool: agent.tool,
            category: agent.category,
            model: modelUsed,
            response: response,
            interactions: agent.knowledge.interactions,
            expertise: agent.knowledge.learned.length
        };
    }

    /**
     * Enseigner une nouvelle technique à un expert
     */
    teachExpert(agentId, technique, successful = true) {
        const agent = this.agents[agentId];
        if (!agent) return false;

        agent.knowledge.learned.push({
            content: technique,
            timestamp: new Date().toISOString(),
            successful
        });

        if (successful) {
            agent.knowledge.successfulTechniques.push(technique);
        }

        // Garder les 100 dernières
        if (agent.knowledge.learned.length > 100) {
            agent.knowledge.learned = agent.knowledge.learned.slice(-100);
        }
        if (agent.knowledge.successfulTechniques.length > 50) {
            agent.knowledge.successfulTechniques = agent.knowledge.successfulTechniques.slice(-50);
        }

        this.saveAgentKnowledge(agentId);
        console.log(`[OSINT-EXPERTS] ${agent.emoji} ${agent.name} learned: ${technique.substring(0, 50)}...`);
        return true;
    }

    /**
     * Enregistrer une investigation réussie
     */
    recordInvestigation(agentId, investigation) {
        const agent = this.agents[agentId];
        if (!agent) return false;

        agent.knowledge.investigations.push({
            ...investigation,
            timestamp: new Date().toISOString()
        });

        if (agent.knowledge.investigations.length > 50) {
            agent.knowledge.investigations = agent.knowledge.investigations.slice(-50);
        }

        this.saveAgentKnowledge(agentId);
        return true;
    }

    /**
     * Obtenir l'expert recommandé pour une tâche
     */
    recommendExpert(task) {
        const taskLower = task.toLowerCase();

        const keywords = {
            shodan: ['iot', 'device', 'port', 'service', 'exposed', 'shodan'],
            theharvester: ['email', 'harvest', 'domain', 'subdomain', 'linkedin'],
            maltego: ['graph', 'link', 'relation', 'connection', 'visual', 'maltego'],
            reconng: ['recon-ng', 'framework', 'module', 'workspace'],
            spiderfoot: ['automated', 'scan', 'spiderfoot', 'comprehensive'],
            amass: ['dns', 'subdomain', 'amass', 'attack surface', 'asn'],
            osintframework: ['tool', 'resource', 'what tool', 'recommend'],
            socialmedia: ['twitter', 'instagram', 'facebook', 'linkedin', 'social', 'profile', 'username'],
            geoint: ['location', 'geolocate', 'satellite', 'photo', 'where', 'gps', 'exif'],
            darkweb: ['dark web', 'tor', 'onion', 'breach', 'leak', 'password'],
            imagint: ['image', 'photo', 'picture', 'reverse', 'face', 'forensic'],
            crypto: ['bitcoin', 'ethereum', 'wallet', 'blockchain', 'crypto', 'trace']
        };

        let bestMatch = 'osintframework';
        let bestScore = 0;

        for (const [agentId, words] of Object.entries(keywords)) {
            const score = words.filter(w => taskLower.includes(w)).length;
            if (score > bestScore) {
                bestScore = score;
                bestMatch = agentId;
            }
        }

        return {
            recommended: bestMatch,
            agent: this.agents[bestMatch],
            confidence: bestScore > 0 ? 'high' : 'low'
        };
    }

    /**
     * Consultation multi-experts pour investigation complexe
     */
    async multiExpertInvestigation(target, targetType = 'domain') {
        console.log(`[OSINT-EXPERTS] Multi-expert investigation: ${target} (${targetType})`);

        const expertsToConsult = {
            domain: ['amass', 'theharvester', 'shodan'],
            person: ['socialmedia', 'osintframework', 'geoint'],
            email: ['theharvester', 'darkweb', 'socialmedia'],
            image: ['imagint', 'geoint', 'socialmedia'],
            username: ['socialmedia', 'osintframework', 'darkweb'],
            ip: ['shodan', 'amass', 'geoint'],
            crypto: ['crypto', 'darkweb', 'osintframework']
        };

        const agentsToUse = expertsToConsult[targetType] || ['osintframework'];
        const results = [];

        for (const agentId of agentsToUse) {
            try {
                const question = `Analyse ce ${targetType}: "${target}". Quelles commandes utiliser et que chercher?`;
                const result = await this.consultExpert(agentId, question);
                results.push(result);
            } catch (error) {
                results.push({ expert: agentId, error: error.message });
            }
        }

        return {
            target,
            targetType,
            expertsConsulted: agentsToUse,
            results,
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Entraînement continu sur un sujet OSINT
     */
    async continuousTraining(agentId, topic, iterations = 3) {
        const agent = this.agents[agentId];
        if (!agent) throw new Error(`OSINT Agent ${agentId} not found`);

        console.log(`[OSINT-EXPERTS] ${agent.emoji} Starting continuous training on "${topic}" (${iterations} iterations)`);

        const trainingQuestions = [
            `Explique l'utilisation de base de ${agent.tool} pour ${topic}`,
            `Quelles sont les techniques avancées de ${agent.tool} pour ${topic}?`,
            `Comment automatiser la collecte d'informations sur ${topic}?`,
            `Quelles sont les sources alternatives pour investiguer ${topic}?`,
            `Comment valider et croiser les informations trouvées sur ${topic}?`
        ];

        const results = [];
        const selectedQuestions = trainingQuestions.slice(0, iterations);

        for (const question of selectedQuestions) {
            try {
                const result = await this.consultExpert(agentId, question);
                results.push(result);

                // Auto-teach from the response
                this.teachExpert(agentId, `Topic: ${topic} - ${question.substring(0, 50)}`, true);

                await new Promise(resolve => setTimeout(resolve, 500));
            } catch (error) {
                results.push({ error: error.message });
            }
        }

        return {
            agent: agent.name,
            tool: agent.tool,
            topic,
            iterations: results.length,
            results,
            newKnowledge: agent.knowledge.learned.length
        };
    }

    /**
     * Obtenir les stats de tous les experts
     */
    getExpertsStats() {
        return Object.entries(this.agents).map(([id, agent]) => ({
            id,
            name: agent.name,
            emoji: agent.emoji,
            tool: agent.tool,
            category: agent.category,
            interactions: agent.knowledge.interactions,
            techniquesLearned: agent.knowledge.learned.length,
            successfulTechniques: agent.knowledge.successfulTechniques.length,
            investigations: agent.knowledge.investigations.length
        })).sort((a, b) => b.interactions - a.interactions);
    }
}

module.exports = OsintExpertAgentsService;
