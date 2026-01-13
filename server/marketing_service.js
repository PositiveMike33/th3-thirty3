/**
 * Marketing Service - Utilise AnythingLLM workspace "marketing" (Fabric)
 * Pour générer du contenu marketing pour KeelClip VPO Analyzer
 */

class MarketingService {
    constructor() {
        this.marketingWorkspace = 'marketing'; // Workspace Fabric dans AnythingLLM
        this.baseUrl = process.env.ANYTHING_LLM_URL || 'http://localhost:3001/api/v1';
        this.apiKey = process.env.ANYTHING_LLM_KEY;
        
        console.log('[MARKETING] Service initialized');
        console.log(`[MARKETING] Workspace: ${this.marketingWorkspace}`);
    }

    /**
     * Envoie une requête au workspace marketing
     */
    async sendToMarketing(prompt, mode = 'chat') {
        if (!this.apiKey) {
            throw new Error('ANYTHING_LLM_KEY not configured');
        }

        try {
            const response = await fetch(`${this.baseUrl}/workspace/${this.marketingWorkspace}/chat`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    message: prompt,
                    mode: mode // 'chat' ou 'query'
                })
            });

            if (!response.ok) {
                const error = await response.text();
                throw new Error(`Marketing workspace failed: ${response.status} - ${error}`);
            }

            const data = await response.json();
            return data.textResponse;

        } catch (error) {
            console.error('[MARKETING] Error:', error.message);
            throw error;
        }
    }

    /**
     * Génère un pitch court (elevator pitch)
     */
    async generateElevatorPitch(target = 'investor') {
        const prompt = `Tu es un expert en marketing B2B pour software manufacturier.

Génère un **elevator pitch de 30 secondes** pour KeelClip VPO Analyzer, ciblant ${target}.

**Produit**: 
- AI qui génère des rapports 5-Why conformes VPO pour incidents machines KeelClip
- Économise 45 minutes par rapport (45 min → 2 min)
- 100% compliance VPO garantie
- Pricing: $299/mois subscription, $4,999 perpetual

**Target**: ${target}

**Format**: 
1. Hook (problème)
2. Solution (notre produit)
3. Différenciation (pourquoi nous)
4. Call-to-action

Reste concis, impactant, mémorable.`;

        return await this.sendToMarketing(prompt);
    }

    /**
     * Génère un post LinkedIn pour annonce produit
     */
    async generateLinkedInPost(topic = 'product_launch') {
        const prompts = {
            product_launch: `Crée un post LinkedIn annonçant le lancement de KeelClip VPO Analyzer.

**Ton**: Professionnel mais enthousiaste
**Longueur**: 150-200 mots max
**Inclure**: 
- Problème (45 min par rapport manuel)
- Solution (AI 2 min)
- Bénéfice (96% temps économisé)
- Call-to-action (Free trial)
- Hashtags: #Manufacturing #Industry40 #AI #VPO #QualityManagement

Format pour engagement maximal (questions, storytelling).`,

            case_study: `Crée un post LinkedIn partageant un case study fictif mais réaliste.

**Scénario**: Brewery X a sauvé 20h/semaine avec KeelClip VPO Analyzer

**Inclure**:
- Avant/Après (métriques)
- Quote testimonial
- Call-to-action
- #CaseStudy #ManufacturingExcellence

Storytelling engageant.`,

            problem_agitate: `Crée un post LinkedIn sur le problème des rapports 5-Why manuels.

**Angle**: Pain point (engineers passent 20h/semaine sur paperwork)
**Ton**: Empathique, relatable
**But**: Créer discussion, génerer leads
**Pas de vente directe** - juste awareness problème

Finir avec question ouverte pour engagement.`
        };

        const prompt = prompts[topic] || prompts.product_launch;
        return await this.sendToMarketing(prompt);
    }

    /**
     * Génère un email cold outreach
     */
    async generateColdEmail(recipient = 'manufacturing_engineer') {
        const prompt = `Génère un email cold outreach pour ${recipient} ciblant KeelClip VPO Analyzer.

**Personas**:
- manufacturing_engineer: Celui qui écrit les rapports (pain direct)
- quality_manager: Celui qui audite (compliance pain)
- plant_director: Celui qui paie (ROI focus)

**Format**:
- Subject line accrocheur
- 100 mots max
- Personnalisé (recherche LinkedIn)
- 1 stat impactante
- 1 question
- CTA clair (demo 15 min)

**Ton**: Professionnel, direct, value-first (pas pushy).`;

        return await this.sendToMarketing(prompt);
    }

    /**
     * Génère une landing page copy
     */
    async generateLandingPageCopy(section = 'hero') {
        const sections = {
            hero: `Génère le texte pour la section HERO de notre landing page.

**Inclure**:
- Headline (10 mots max, impactant)
- Subheadline (20 mots, bénéfice clair)
- CTA button text (3 mots)

**Formule**: 
- Headline: Transformation promise
- Subheadline: Comment + pour qui
- CTA: Action évidente

Exemples style: Stripe, Notion, Figma (clean, benefit-driven).`,

            features: `Génère la copy pour la section FEATURES.

**3 features clés**:
1. AI Vision Analysis - Identifie composants automatiquement
2. VPO Compliance - 100% audit-proof
3. Time Savings - 45 min → 2 min

Pour chaque:
- Titre (4-5 mots)
- Description (20 mots)
- Bénéfice user (pas feature description)

Ton: Benefit-focused, scannable.`,

            pricing: `Génère la copy pour la section PRICING.

**3 tiers**:
- Trial: Gratuit 30 jours
- Subscription: $299/mois
- Enterprise: Custom

Pour chaque:
- Tagline (3 mots, qui c'est pour)
- Features list (5 bullets)
- CTA button text

Highlight "Most Popular" = Subscription.`,

            testimonials: `Crée 3 faux testimonials réalistes pour beta users.

**Personas**:
1. Quality Engineer (compliance angle)
2. Plant Manager (ROI angle)  
3. Operator (ease-of-use angle)

Format:
- Quote (30 mots, specific)
- Name + Title + Company
- Photo (description pour AI generation)

Crédibles, pas trop marketing-y.`
        };

        const prompt = sections[section] || sections.hero;
        return await this.sendToMarketing(prompt);
    }

    /**
     * Génère un script vidéo démo
     */
    async generateVideoScript(duration = '3min') {
        const prompt = `Crée un script pour vidéo démo de ${duration}.

**Structure**:
1. Hook (5 sec) - Problème visuel
2. Problème (30 sec) - Pain points
3. Solution (90 sec) - Demo produit (screen recording)
4. Résultats (30 sec) - Avant/Après metrics
5. Call-to-action (15 sec) - Trial gratuit

**Format**:
- Timestamp
- Voiceover text
- Screen action (ce qu'on voit)

**Ton**: Énergétique mais professionnel, like Loom/Notion demos.`;

        return await this.sendToMarketing(prompt);
    }

    /**
     * Génère des réponses FAQ
     */
    async generateFAQ(category = 'product') {
        const categories = {
            product: 'Questions sur fonctionnalités produit',
            pricing: 'Questions sur pricing et licences',
            technical: 'Questions techniques (AI, security, deployment)',
            vpo: 'Questions sur VPO compliance'
        };

        const prompt = `Génère 5 FAQs pour catégorie: ${categories[category]}

Format pour chaque:
**Q**: [Question utilisateur réaliste]
**A**: [Réponse claire, 50 mots max, rassurante]

Questions doivent adresser objections communes.`;

        return await this.sendToMarketing(prompt);
    }

    /**
     * Génère un communiqué de presse
     */
    async generatePressRelease(event = 'product_launch') {
        const prompt = `Génère un communiqué de presse pour ${event}.

**Format AP Style**:
- Headline
- Dateline (Québec, Canada - [Date])
- Lead paragraph (who, what, when, where, why)
- Quote founder
- Company background
- Call-to-action
- Boilerplate

**Événements possibles**:
- product_launch: Lancement KeelClip VPO Analyzer
- funding: $40k seed raised
- milestone: 100th customer

Ton: Newsworthy, factuel, third-person.`;

        return await this.sendToMarketing(prompt);
    }
}

module.exports = MarketingService;
