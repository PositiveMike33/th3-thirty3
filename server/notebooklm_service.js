/**
 * NOTEBOOKLM INTEGRATION SERVICE
 * ================================
 * 
 * Intégration avec NotebookLM (Google) pour l'enseignement guidé.
 * 
 * Fonctionnement:
 * 1. L'utilisateur exporte/copie le contenu de NotebookLM dans un dossier local
 * 2. Ce service lit les fichiers de ce dossier (.txt, .md, .pdf summaries)
 * 3. Gemini utilise ce contenu pour créer des leçons personnalisées
 * 4. Les modèles locaux sont formés sur ce contenu
 * 
 * Structure des dossiers:
 * /server/data/notebooklm/
 *   ├── osint/           <- Cours OSINT depuis NotebookLM
 *   ├── network/         <- Cours réseau
 *   ├── vuln/            <- Cours vulnérabilités
 *   ├── coding/          <- Cours programmation sécurité
 *   └── custom/          <- Cours personnalisés
 */

const fs = require('fs');
const path = require('path');

class NotebookLMService {
    constructor(llmService) {
        this.llmService = llmService;
        this.basePath = path.join(__dirname, 'data', 'notebooklm');
        this.lessonsCache = {};
        
        // Créer le dossier s'il n'existe pas
        this.ensureDirectories();
        
        console.log('[NOTEBOOKLM] 📓 Service initialisé');
        console.log(`  → Dossier: ${this.basePath}`);
    }

    ensureDirectories() {
        const dirs = ['osint', 'network', 'vuln', 'coding', 'custom'];
        
        if (!fs.existsSync(this.basePath)) {
            fs.mkdirSync(this.basePath, { recursive: true });
        }
        
        for (const dir of dirs) {
            const dirPath = path.join(this.basePath, dir);
            if (!fs.existsSync(dirPath)) {
                fs.mkdirSync(dirPath, { recursive: true });
                
                // Créer un fichier README dans chaque dossier
                const readme = `# ${dir.toUpperCase()} - NotebookLM Teaching Content

Placez vos notes et exports NotebookLM ici.

## Formats supportés:
- .txt - Texte brut
- .md - Markdown
- .json - Structure JSON

## Comment utiliser:
1. Exportez ou copiez le contenu de votre NotebookLM
2. Sauvegardez-le dans ce dossier
3. L'API /notebooklm/teach/:domain l'utilisera automatiquement

## Exemple de structure de fichier:
{
  "title": "Nom de la leçon",
  "content": "Contenu détaillé...",
  "keyPoints": ["point1", "point2"],
  "exercises": ["exercice1", "exercice2"]
}
`;
                fs.writeFileSync(path.join(dirPath, 'README.md'), readme);
            }
        }
    }

    /**
     * Liste tous les domaines disponibles avec leur contenu
     */
    listDomains() {
        const domains = [];
        
        try {
            const dirs = fs.readdirSync(this.basePath, { withFileTypes: true });
            
            for (const dir of dirs) {
                if (dir.isDirectory()) {
                    const domainPath = path.join(this.basePath, dir.name);
                    const files = fs.readdirSync(domainPath)
                        .filter(f => !f.startsWith('README') && ['.txt', '.md', '.json'].some(ext => f.endsWith(ext)));
                    
                    domains.push({
                        name: dir.name,
                        path: domainPath,
                        fileCount: files.length,
                        files: files
                    });
                }
            }
        } catch (error) {
            console.error('[NOTEBOOKLM] Erreur listDomains:', error.message);
        }
        
        return domains;
    }

    /**
     * Lit tout le contenu d'un domaine
     */
    getDomainContent(domain) {
        const domainPath = path.join(this.basePath, domain);
        
        if (!fs.existsSync(domainPath)) {
            return { success: false, error: `Domaine ${domain} non trouvé` };
        }

        const content = [];
        const files = fs.readdirSync(domainPath)
            .filter(f => !f.startsWith('README') && ['.txt', '.md', '.json'].some(ext => f.endsWith(ext)));

        for (const file of files) {
            try {
                const filePath = path.join(domainPath, file);
                const fileContent = fs.readFileSync(filePath, 'utf8');
                
                let parsed;
                if (file.endsWith('.json')) {
                    parsed = JSON.parse(fileContent);
                } else {
                    parsed = {
                        title: file.replace(/\.(txt|md|json)$/, ''),
                        content: fileContent,
                        type: file.endsWith('.md') ? 'markdown' : 'text'
                    };
                }
                
                content.push({
                    filename: file,
                    ...parsed
                });
            } catch (error) {
                console.error(`[NOTEBOOKLM] Erreur lecture ${file}:`, error.message);
            }
        }

        return {
            success: true,
            domain,
            fileCount: content.length,
            content
        };
    }

    /**
     * Ajoute du contenu à un domaine (depuis l'interface ou API)
     */
    addContent(domain, title, content, metadata = {}) {
        const domainPath = path.join(this.basePath, domain);
        
        if (!fs.existsSync(domainPath)) {
            fs.mkdirSync(domainPath, { recursive: true });
        }

        const filename = `${title.replace(/[^a-zA-Z0-9]/g, '_')}.json`;
        const filePath = path.join(domainPath, filename);
        
        const data = {
            title,
            content,
            createdAt: new Date().toISOString(),
            ...metadata
        };

        fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
        
        console.log(`[NOTEBOOKLM] ✅ Contenu ajouté: ${domain}/${filename}`);
        
        return { success: true, filename, path: filePath };
    }

    /**
     * Génère une leçon à partir du contenu NotebookLM avec Gemini
     * C'est ici que Gemini analyse le contenu et crée une leçon structurée
     */
    async generateLesson(domain, topic = null) {
        const domainContent = this.getDomainContent(domain);
        
        if (!domainContent.success || domainContent.fileCount === 0) {
            return { 
                success: false, 
                error: `Aucun contenu trouvé pour ${domain}. Ajoutez des fichiers dans ${this.basePath}/${domain}/` 
            };
        }

        // Combiner tout le contenu du domaine
        let combinedContent = '';
        for (const item of domainContent.content) {
            combinedContent += `\n\n### ${item.title}\n${item.content}`;
        }

        // Utiliser Gemini pour créer une leçon
        const prompt = `Tu es un expert pédagogue en cybersécurité. 
Analyse ce contenu provenant de NotebookLM et crée une leçon structurée.

CONTENU À ANALYSER:
${combinedContent.substring(0, 15000)}  // Limiter la taille

${topic ? `FOCUS SUR: ${topic}` : ''}

Génère une leçon complète en JSON avec ce format:
{
  "title": "Titre de la leçon",
  "summary": "Résumé en 2-3 phrases",
  "prerequisites": ["prérequis1", "prérequis2"],
  "objectives": ["objectif1", "objectif2", "objectif3"],
  "sections": [
    {
      "title": "Section 1",
      "content": "Explication détaillée...",
      "keyPoints": ["point1", "point2"]
    }
  ],
  "exercises": [
    {
      "type": "practice|theory|quiz",
      "question": "Question ou exercice",
      "difficulty": 1-5,
      "hints": ["indice1"]
    }
  ],
  "assessment": {
    "questions": ["Q1?", "Q2?"],
    "passingScore": 70
  }
}`;

        try {
            const response = await this.llmService.generateResponse(
                prompt,
                null,
                'gemini',
                'gemini-2.0-flash-exp',
                'Tu es un créateur de cours expert. Réponds uniquement en JSON valide.'
            );

            // Parser la réponse JSON
            const jsonMatch = response.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                const lesson = JSON.parse(jsonMatch[0]);
                lesson.domain = domain;
                lesson.generatedAt = new Date().toISOString();
                lesson.sourceFiles = domainContent.content.map(c => c.filename);
                
                // Mettre en cache
                if (!this.lessonsCache[domain]) this.lessonsCache[domain] = [];
                this.lessonsCache[domain].push(lesson);
                
                return { success: true, lesson };
            }

            return { success: false, error: 'Impossible de parser la réponse Gemini', raw: response };
        } catch (error) {
            console.error('[NOTEBOOKLM] Erreur génération leçon:', error.message);
            return { success: false, error: error.message };
        }
    }

    /**
     * Enseigne un modèle avec le contenu NotebookLM
     * Utilise le contenu du domaine pour créer des exercices d'entraînement
     */
    async teachModel(studentModel, domain, options = {}) {
        const { exerciseCount = 5 } = options;

        console.log(`[NOTEBOOKLM] 📚 Enseignement de ${studentModel} sur ${domain}`);

        // Générer une leçon si pas en cache
        if (!this.lessonsCache[domain] || this.lessonsCache[domain].length === 0) {
            const lessonResult = await this.generateLesson(domain);
            if (!lessonResult.success) {
                return lessonResult;
            }
        }

        const lesson = this.lessonsCache[domain][this.lessonsCache[domain].length - 1];
        const results = [];

        // Utiliser les exercices de la leçon
        const exercises = lesson.exercises || [];
        const useCount = Math.min(exerciseCount, exercises.length);

        for (let i = 0; i < useCount; i++) {
            const exercise = exercises[i];
            
            console.log(`[NOTEBOOKLM] Exercice ${i + 1}/${useCount}: ${exercise.question.substring(0, 50)}...`);

            try {
                // L'étudiant répond
                const studentResponse = await this.llmService.generateResponse(
                    exercise.question,
                    null,
                    'local',
                    studentModel,
                    `Tu apprends le domaine: ${domain}. Réponds de manière précise et concise.`
                );

                // Gemini évalue
                const evaluation = await this.evaluateWithGemini(exercise, studentResponse, lesson);

                results.push({
                    exercise: exercise.question,
                    type: exercise.type,
                    studentResponse: studentResponse.substring(0, 300),
                    evaluation
                });

                console.log(`  → Score: ${evaluation.score}/100 | ${evaluation.correct ? '✅' : '❌'}`);

            } catch (error) {
                console.error(`[NOTEBOOKLM] Erreur exercice ${i + 1}:`, error.message);
                results.push({
                    exercise: exercise.question,
                    error: error.message
                });
            }
        }

        // Calculer les stats
        const successCount = results.filter(r => r.evaluation?.correct).length;
        const avgScore = results.reduce((sum, r) => sum + (r.evaluation?.score || 0), 0) / results.length;

        return {
            success: true,
            studentModel,
            domain,
            lessonTitle: lesson.title,
            exerciseCount: useCount,
            successCount,
            successRate: `${((successCount / useCount) * 100).toFixed(0)}%`,
            averageScore: avgScore.toFixed(1),
            results
        };
    }

    /**
     * Évaluation avec Gemini basée sur le contenu de la leçon
     */
    async evaluateWithGemini(exercise, studentResponse, lesson) {
        const prompt = `Tu es un professeur évaluant une réponse d'étudiant.

CONTEXTE DE LA LEÇON: ${lesson.title}
OBJECTIFS: ${lesson.objectives?.join(', ')}

EXERCICE: ${exercise.question}
TYPE: ${exercise.type}
DIFFICULTÉ: ${exercise.difficulty}/5

RÉPONSE DE L'ÉTUDIANT:
${studentResponse}

Évalue cette réponse. Réponds en JSON:
{
  "correct": true/false,
  "score": 0-100,
  "feedback": "explication",
  "keyPointsCovered": ["point1", "point2"],
  "improvement": "suggestion d'amélioration"
}`;

        try {
            const response = await this.llmService.generateResponse(
                prompt,
                null,
                'gemini',
                'gemini-2.0-flash-exp',
                'Évaluateur expert. JSON uniquement.'
            );

            const jsonMatch = response.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                return JSON.parse(jsonMatch[0]);
            }

            return { correct: false, score: 50, feedback: 'Évaluation manuelle requise' };
        } catch (error) {
            return { correct: false, score: 0, feedback: error.message };
        }
    }

    /**
     * Importe du contenu depuis un texte (copié de NotebookLM)
     */
    importFromText(domain, title, text) {
        // Analyser le texte pour extraire des sections
        const sections = text.split(/\n##?\s+/).filter(s => s.trim());
        
        const content = {
            title,
            rawText: text,
            sections: sections.map((s, i) => ({
                index: i,
                content: s.trim()
            })),
            importedAt: new Date().toISOString(),
            source: 'NotebookLM Import'
        };

        return this.addContent(domain, title, JSON.stringify(content, null, 2), {
            type: 'notebooklm_import'
        });
    }

    /**
     * Obtient les leçons générées en cache
     */
    getCachedLessons(domain = null) {
        if (domain) {
            return this.lessonsCache[domain] || [];
        }
        return this.lessonsCache;
    }

    /**
     * Génère un résumé audio-style (comme le podcast NotebookLM)
     */
    async generatePodcastSummary(domain) {
        const domainContent = this.getDomainContent(domain);
        
        if (!domainContent.success || domainContent.fileCount === 0) {
            return { success: false, error: `Aucun contenu pour ${domain}` };
        }

        let combinedContent = domainContent.content.map(c => c.content || c.rawText).join('\n\n');

        const prompt = `Tu es un animateur de podcast tech engageant.
Crée un résumé style podcast du contenu suivant.
Le ton doit être conversationnel, engageant, avec des exemples pratiques.

CONTENU:
${combinedContent.substring(0, 10000)}

Génère un script de podcast (3-5 minutes de lecture):`;

        try {
            const response = await this.llmService.generateResponse(
                prompt,
                null,
                'gemini',
                'gemini-2.0-flash-exp',
                'Tu es un podcasteur tech populaire. Style conversationnel et engageant.'
            );

            return {
                success: true,
                domain,
                podcastScript: response,
                estimatedDuration: '3-5 minutes',
                generatedAt: new Date().toISOString()
            };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }
}

module.exports = NotebookLMService;
