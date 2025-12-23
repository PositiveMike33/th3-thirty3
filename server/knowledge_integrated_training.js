/**
 * Knowledge-Integrated Training System
 * 
 * Uses real datasets from the project's knowledge base to:
 * - Generate contextual exam questions
 * - Provide RAG-enhanced learning material
 * - Create domain-specific challenges from real data
 * - Grade responses based on knowledge base accuracy
 * 
 * @author Th3 Thirty3
 */

const fs = require('fs');
const path = require('path');
const EventEmitter = require('events');

// Golden Ratio for learning curves
const PHI = 1.618033988749895;

class KnowledgeIntegratedTraining extends EventEmitter {
    constructor(llmService) {
        super();
        
        this.llmService = llmService;
        
        // Knowledge base paths
        this.knowledgePath = path.join(__dirname, 'knowledge');
        this.trainingDataPath = path.join(__dirname, 'data', 'training');
        this.notebookLMPath = path.join(__dirname, 'data', 'notebooklm');
        
        // Loaded knowledge bases
        this.knowledgeBases = {};
        this.trainingData = {};
        
        // Domain to file mapping
        this.domainMapping = {
            'osint': [
                'osint_shodan_training.json',
                'osint_tools.json',
                'osint_expert_team.json',
                'kinetic_osint.json'
            ],
            'pentesting': [
                'pentestgpt_methodology.json',
                'defense_training_workflows.json'
            ],
            'network': [
                'network_defense_reverse_engineering.json',
                'opsec_scenarios.json'
            ],
            'web_security': [
                'pentestgpt_methodology.json'  // Contains web exploitation
            ],
            'exploit_dev': [
                'pentestgpt_methodology.json',
                'network_defense_reverse_engineering.json'
            ],
            'malware': [
                'network_defense_reverse_engineering.json'
            ],
            'wireless': [
                'wifi_security_training_scenarios.json'
            ],
            'social_engineering': [
                'opsec_scenarios.json'
            ],
            'cryptography': [
                'pentestgpt_methodology.json'
            ],
            'forensics': [
                'pentestgpt_methodology.json'
            ],
            'red_team': [
                'pentestgpt_methodology.json',
                'defense_training_workflows.json'
            ],
            'cloud': [
                'cyber_physical_systems.json'
            ]
        };
        
        // Load all knowledge bases
        this.loadKnowledgeBases();
        
        console.log('[KB-TRAINING] Knowledge-Integrated Training System initialized');
        console.log(`[KB-TRAINING] Loaded ${Object.keys(this.knowledgeBases).length} knowledge bases`);
    }
    
    /**
     * Load all knowledge base files
     */
    loadKnowledgeBases() {
        // Load from knowledge folder
        this.loadFromDirectory(this.knowledgePath, 'knowledge');
        
        // Load from training data folder
        this.loadFromDirectory(this.trainingDataPath, 'training');
        
        // Load from notebookLM
        if (fs.existsSync(this.notebookLMPath)) {
            this.loadFromDirectory(this.notebookLMPath, 'notebooklm', true);
        }
    }
    
    /**
     * Load JSON files from a directory
     */
    loadFromDirectory(dirPath, prefix, recursive = false) {
        try {
            if (!fs.existsSync(dirPath)) return;
            
            const items = fs.readdirSync(dirPath);
            
            for (const item of items) {
                const fullPath = path.join(dirPath, item);
                const stat = fs.statSync(fullPath);
                
                if (stat.isDirectory() && recursive) {
                    this.loadFromDirectory(fullPath, `${prefix}/${item}`, recursive);
                } else if (item.endsWith('.json')) {
                    try {
                        const data = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
                        const key = `${prefix}/${item.replace('.json', '')}`;
                        this.knowledgeBases[key] = data;
                    } catch (e) {
                        console.warn(`[KB-TRAINING] Failed to load ${fullPath}:`, e.message);
                    }
                }
            }
        } catch (error) {
            console.error(`[KB-TRAINING] Error loading from ${dirPath}:`, error.message);
        }
    }
    
    /**
     * Get relevant knowledge for a domain
     */
    getKnowledgeForDomain(domain) {
        const relevantFiles = this.domainMapping[domain] || [];
        const knowledge = [];
        
        for (const file of relevantFiles) {
            const baseName = file.replace('.json', '');
            
            // Check in knowledge folder
            if (this.knowledgeBases[`knowledge/${baseName}`]) {
                knowledge.push({
                    source: `knowledge/${baseName}`,
                    data: this.knowledgeBases[`knowledge/${baseName}`]
                });
            }
            
            // Check in training folder
            if (this.knowledgeBases[`training/${baseName}`]) {
                knowledge.push({
                    source: `training/${baseName}`,
                    data: this.knowledgeBases[`training/${baseName}`]
                });
            }
        }
        
        return knowledge;
    }
    
    /**
     * Generate exam questions from knowledge base
     */
    generateExamFromKnowledge(domain, difficulty = 'medium', count = 3) {
        const knowledge = this.getKnowledgeForDomain(domain);
        
        if (knowledge.length === 0) {
            console.warn(`[KB-TRAINING] No knowledge base for domain: ${domain}`);
            return this.generateGenericExam(domain, count);
        }
        
        const questions = [];
        
        for (const kb of knowledge) {
            const extracted = this.extractQuestionsFromKB(kb.data, domain, difficulty);
            questions.push(...extracted);
        }
        
        // Shuffle and limit
        const shuffled = questions.sort(() => Math.random() - 0.5);
        return shuffled.slice(0, count);
    }
    
    /**
     * Extract questions from a knowledge base
     */
    extractQuestionsFromKB(data, domain, difficulty) {
        const questions = [];
        
        // Handle training_data format (like osint_shodan_training.json)
        if (data.training_data && Array.isArray(data.training_data)) {
            for (const item of data.training_data) {
                if (item.instruction && item.response) {
                    questions.push({
                        id: `kb-${domain}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                        question: item.instruction,
                        expectedAnswer: item.response,
                        keywords: this.extractKeywords(item.response),
                        difficulty: difficulty,
                        source: 'training_data'
                    });
                }
            }
        }
        
        // Handle training_scenarios format (like pentestgpt_methodology.json)
        if (data.training_scenarios && Array.isArray(data.training_scenarios)) {
            for (const scenario of data.training_scenarios) {
                questions.push({
                    id: scenario.id || `scenario-${Date.now()}`,
                    question: scenario.scenario,
                    expectedAnswer: scenario.expected_approach,
                    keywords: scenario.methodology_focus || [],
                    difficulty: scenario.difficulty || difficulty,
                    source: 'training_scenario'
                });
            }
        }
        
        // Handle random_training_prompts format
        if (data.random_training_prompts && Array.isArray(data.random_training_prompts)) {
            for (const prompt of data.random_training_prompts) {
                questions.push({
                    id: `prompt-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                    question: prompt,
                    keywords: this.extractKeywordsFromPrompt(prompt),
                    difficulty: difficulty,
                    source: 'random_prompt'
                });
            }
        }
        
        // Handle ctf_categories format
        if (data.ctf_categories && Array.isArray(data.ctf_categories)) {
            for (const cat of data.ctf_categories) {
                questions.push({
                    id: `ctf-${cat.category.replace(/\s+/g, '-').toLowerCase()}`,
                    question: cat.training_prompt,
                    keywords: [...(cat.techniques || []), ...(cat.tools || [])],
                    difficulty: difficulty,
                    source: 'ctf_category',
                    category: cat.category
                });
            }
        }
        
        // Handle fallback_strategies format
        if (data.fallback_strategies) {
            for (const [key, strategy] of Object.entries(data.fallback_strategies)) {
                questions.push({
                    id: `fallback-${key}`,
                    question: `You encounter this situation: ${strategy.description}. What alternatives would you try?`,
                    expectedAnswer: strategy.alternatives.join('\n'),
                    keywords: this.extractKeywords(strategy.alternatives.join(' ')),
                    difficulty: 'hard',
                    source: 'fallback_strategy'
                });
            }
        }
        
        return questions;
    }
    
    /**
     * Extract keywords from text
     */
    extractKeywords(text) {
        // Extract technical terms, commands, tools
        const patterns = [
            /`([^`]+)`/g,  // Code blocks
            /\b(nmap|gobuster|sqlmap|burp|metasploit|hashcat|wireshark|volatility|ghidra)\b/gi,  // Tools
            /\b(CVE-\d+-\d+)\b/g,  // CVEs
            /\b(port\s*\d+|\d+\s*port)\b/gi,  // Ports
            /\b(SQL|XSS|SSRF|LFI|RFI|RCE|XXE|CSRF)\b/gi,  // Vuln types
            /\b(root|admin|shell|exploit|payload|bypass)\b/gi  // Key terms
        ];
        
        const keywords = new Set();
        
        for (const pattern of patterns) {
            const matches = text.matchAll(pattern);
            for (const match of matches) {
                keywords.add(match[1] || match[0]);
            }
        }
        
        return Array.from(keywords).slice(0, 10);
    }
    
    /**
     * Extract keywords from a prompt question
     */
    extractKeywordsFromPrompt(prompt) {
        const words = prompt.toLowerCase().split(/\s+/);
        const techTerms = words.filter(w => 
            w.length > 4 && 
            /^[a-z]+$/i.test(w) &&
            !['comment', 'quels', 'quand', 'pourquoi', 'comment'].includes(w)
        );
        
        return techTerms.slice(0, 5);
    }
    
    /**
     * Generate generic exam if no KB available
     */
    generateGenericExam(domain, count) {
        const genericQuestions = {
            'osint': [
                { question: 'Explain passive reconnaissance techniques using Shodan', keywords: ['shodan', 'passive', 'reconnaissance', 'ports', 'services'] },
                { question: 'How would you enumerate a target domain without active scanning?', keywords: ['whois', 'dns', 'certificate transparency', 'passive'] }
            ],
            'pentesting': [
                { question: 'Describe your methodology for initial network enumeration', keywords: ['nmap', 'ports', 'services', 'enumeration'] },
                { question: 'How do you identify and exploit common misconfigurations?', keywords: ['misconfiguration', 'default', 'credentials', 'permissions'] }
            ],
            'social_engineering': [
                { question: 'Design a phishing campaign for a corporate target', keywords: ['phishing', 'pretext', 'email', 'landing page'] },
                { question: 'Explain influence principles used in social engineering', keywords: ['authority', 'urgency', 'reciprocity', 'trust'] }
            ]
        };
        
        const questions = genericQuestions[domain] || [
            { question: `Explain key concepts and tools for ${domain}`, keywords: [domain, 'tools', 'techniques'] }
        ];
        
        return questions.slice(0, count).map((q, i) => ({
            id: `generic-${domain}-${i}`,
            question: q.question,
            keywords: q.keywords,
            difficulty: 'medium',
            source: 'generic'
        }));
    }
    
    /**
     * Create contextual training material from KB
     */
    async generateTrainingMaterial(domain, modelExpertise = 0) {
        const knowledge = this.getKnowledgeForDomain(domain);
        
        // Select content based on expertise level
        let difficulty = 'beginner';
        if (modelExpertise >= 80) difficulty = 'expert';
        else if (modelExpertise >= 50) difficulty = 'advanced';
        else if (modelExpertise >= 25) difficulty = 'intermediate';
        
        const material = {
            domain,
            difficulty,
            sections: []
        };
        
        for (const kb of knowledge) {
            const section = {
                source: kb.source,
                content: []
            };
            
            // Extract relevant content
            if (kb.data.training_data) {
                section.content.push({
                    type: 'qa_pairs',
                    data: kb.data.training_data.slice(0, 3)
                });
            }
            
            if (kb.data.pentesting_methodology?.phases) {
                section.content.push({
                    type: 'methodology',
                    data: kb.data.pentesting_methodology.phases
                });
            }
            
            if (kb.data.ctf_categories) {
                section.content.push({
                    type: 'categories',
                    data: kb.data.ctf_categories
                });
            }
            
            if (kb.data.tools_arsenal) {
                section.content.push({
                    type: 'tools',
                    data: kb.data.tools_arsenal
                });
            }
            
            if (section.content.length > 0) {
                material.sections.push(section);
            }
        }
        
        return material;
    }
    
    /**
     * Grade an answer using KB as reference
     */
    gradeWithKnowledge(answer, question) {
        const score = { total: 0, breakdown: {} };
        
        // Keyword matching (60% of score)
        if (question.keywords && question.keywords.length > 0) {
            const answerLower = answer.toLowerCase();
            const foundKeywords = question.keywords.filter(kw => 
                answerLower.includes(kw.toLowerCase())
            );
            
            score.breakdown.keywords = {
                found: foundKeywords,
                missed: question.keywords.filter(kw => !foundKeywords.includes(kw)),
                score: (foundKeywords.length / question.keywords.length) * 60
            };
            score.total += score.breakdown.keywords.score;
        }
        
        // Length/depth bonus (20% of score)
        const wordCount = answer.split(/\s+/).length;
        let lengthScore = 0;
        if (wordCount >= 50) lengthScore = 5;
        if (wordCount >= 100) lengthScore = 10;
        if (wordCount >= 200) lengthScore = 15;
        if (wordCount >= 300) lengthScore = 20;
        
        score.breakdown.depth = { wordCount, score: lengthScore };
        score.total += lengthScore;
        
        // Technical accuracy (20% of score)
        let technicalScore = 0;
        if (answer.includes('```')) technicalScore += 10;  // Code blocks
        if (answer.match(/\$|>|#|nmap|sudo|curl/)) technicalScore += 5;  // Commands
        if (answer.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) technicalScore += 5;  // IPs
        
        score.breakdown.technical = { score: Math.min(20, technicalScore) };
        score.total += score.breakdown.technical.score;
        
        // Compare with expected answer if available
        if (question.expectedAnswer) {
            const similarity = this.calculateSimilarity(answer, question.expectedAnswer);
            score.breakdown.similarity = { score: similarity * 20, value: similarity };
            // Bonus for matching expected answer
            score.total = Math.min(100, score.total + (similarity * 10));
        }
        
        return {
            score: Math.round(score.total),
            passed: score.total >= 60,
            breakdown: score.breakdown,
            feedback: this.generateFeedback(score)
        };
    }
    
    /**
     * Calculate text similarity
     */
    calculateSimilarity(text1, text2) {
        const words1 = new Set(text1.toLowerCase().split(/\s+/));
        const words2 = new Set(text2.toLowerCase().split(/\s+/));
        
        const intersection = new Set([...words1].filter(x => words2.has(x)));
        const union = new Set([...words1, ...words2]);
        
        return intersection.size / union.size;
    }
    
    /**
     * Generate feedback based on score
     */
    generateFeedback(score) {
        const feedback = [];
        
        if (score.breakdown.keywords) {
            const kw = score.breakdown.keywords;
            if (kw.missed.length > 0) {
                feedback.push(`Missing key concepts: ${kw.missed.slice(0, 3).join(', ')}`);
            }
            if (kw.found.length >= kw.missed.length) {
                feedback.push(`Good coverage of: ${kw.found.slice(0, 3).join(', ')}`);
            }
        }
        
        if (score.breakdown.depth && score.breakdown.depth.wordCount < 100) {
            feedback.push('Answer could be more detailed');
        }
        
        if (score.breakdown.technical && score.breakdown.technical.score < 10) {
            feedback.push('Include more practical examples and commands');
        }
        
        return feedback.join('. ');
    }
    
    /**
     * Build RAG context from knowledge base for a domain
     * This injects relevant knowledge into the model's context
     */
    buildRAGContext(domain, maxTokens = 2000) {
        const knowledge = this.getKnowledgeForDomain(domain);
        const contextParts = [];
        let estimatedTokens = 0;
        
        for (const kb of knowledge) {
            // Extract most relevant content
            const content = this.extractRAGContent(kb.data);
            
            for (const item of content) {
                const itemText = typeof item === 'string' ? item : JSON.stringify(item);
                const itemTokens = itemText.split(/\s+/).length;
                
                if (estimatedTokens + itemTokens < maxTokens) {
                    contextParts.push(itemText);
                    estimatedTokens += itemTokens;
                }
            }
        }
        
        return contextParts.join('\n\n---\n\n');
    }
    
    /**
     * Extract RAG-relevant content from knowledge base
     */
    extractRAGContent(data) {
        const content = [];
        
        // Training data Q&A pairs
        if (data.training_data) {
            for (const item of data.training_data.slice(0, 3)) {
                if (item.instruction && item.response) {
                    content.push(`Q: ${item.instruction}\nA: ${item.response}`);
                }
            }
        }
        
        // System prompts
        if (data.system) {
            content.push(`Expert Knowledge: ${data.system}`);
        }
        
        // Methodology phases
        if (data.pentesting_methodology?.phases) {
            const phases = data.pentesting_methodology.phases
                .map(p => `Phase ${p.phase}: ${p.name} - ${p.description}`)
                .join('\n');
            content.push(`Methodology:\n${phases}`);
        }
        
        // CTF categories and techniques
        if (data.ctf_categories) {
            for (const cat of data.ctf_categories.slice(0, 3)) {
                content.push(`${cat.category}: Techniques - ${cat.techniques?.join(', ')}. Tools - ${cat.tools?.join(', ')}`);
            }
        }
        
        // Tools arsenal
        if (data.tools_arsenal) {
            const tools = Object.entries(data.tools_arsenal)
                .map(([cat, list]) => `${cat}: ${list.join(', ')}`)
                .join('\n');
            content.push(`Tools:\n${tools}`);
        }
        
        // Fallback strategies
        if (data.fallback_strategies) {
            for (const [key, strategy] of Object.entries(data.fallback_strategies).slice(0, 2)) {
                content.push(`Strategy for ${key}: ${strategy.alternatives?.slice(0, 3).join('; ')}`);
            }
        }
        
        // Compact config
        if (data.compact_config) {
            content.push(`Config: ${JSON.stringify(data.compact_config)}`);
        }
        
        return content;
    }
    
    /**
     * Run a knowledge-based exam WITH RAG CONTEXT INJECTION
     * 
     * This is the enhanced version that provides models with
     * relevant knowledge base context before each question.
     */
    async runKnowledgeExam(modelName, domain, useRAG = true) {
        console.log(`[KB-TRAINING] Running knowledge exam: ${domain} for ${modelName}`);
        console.log(`[KB-TRAINING] RAG Context Injection: ${useRAG ? 'ENABLED' : 'DISABLED'}`);
        
        // Generate questions from knowledge base
        const questions = this.generateExamFromKnowledge(domain, 'medium', 3);
        
        if (questions.length === 0) {
            throw new Error(`No questions available for domain: ${domain}`);
        }
        
        // Build RAG context if enabled
        let ragContext = '';
        if (useRAG) {
            ragContext = this.buildRAGContext(domain, 2000);
            console.log(`[KB-TRAINING] RAG Context: ${ragContext.split(/\s+/).length} tokens`);
        }
        
        const results = {
            modelName,
            domain,
            ragEnabled: useRAG,
            startTime: new Date().toISOString(),
            questions: [],
            totalScore: 0
        };
        
        for (const question of questions) {
            console.log(`[KB-TRAINING] Q: ${question.question.substring(0, 50)}...`);
            
            try {
                // Build enhanced system prompt with RAG context
                let systemPrompt = `You are an expert in ${domain}. Provide a detailed, technical answer.`;
                
                if (useRAG && ragContext) {
                    systemPrompt = `You are an expert in ${domain}. 

=== REFERENCE KNOWLEDGE BASE ===
${ragContext}
=== END KNOWLEDGE BASE ===

Use the above knowledge base as your primary reference. 
Provide a detailed, technical answer that incorporates the specific techniques, tools, and methodologies from the knowledge base.
Include code examples, commands, and specific procedures when relevant.`;
                }
                
                // Get model's answer
                const answer = await this.llmService.generateOllamaResponse(
                    question.question,
                    null,
                    modelName,
                    systemPrompt
                );
                
                // Grade with knowledge base
                const grade = this.gradeWithKnowledge(answer, question);
                
                results.questions.push({
                    question: question.question,
                    answer: answer.substring(0, 500) + '...',
                    ragInjected: useRAG,
                    ...grade
                });
                
                results.totalScore += grade.score;
                
                console.log(`[KB-TRAINING] Score: ${grade.score}% ${grade.passed ? '✅' : '❌'}`);
                
            } catch (error) {
                console.error(`[KB-TRAINING] Error: ${error.message}`);
                results.questions.push({
                    question: question.question,
                    error: error.message,
                    score: 0,
                    passed: false
                });
            }
        }
        
        results.averageScore = Math.round(results.totalScore / questions.length);
        results.passed = results.averageScore >= 60;
        results.endTime = new Date().toISOString();
        
        return results;
    }
    
    /**
     * Run comparative exam - with and without RAG
     * Shows the improvement from knowledge injection
     */
    async runComparativeExam(modelName, domain) {
        console.log(`[KB-TRAINING] Running comparative exam for ${modelName} on ${domain}`);
        
        // Run without RAG first
        console.log('\n📊 WITHOUT RAG:');
        const withoutRAG = await this.runKnowledgeExamCore(modelName, domain, false);
        
        // Small delay
        await new Promise(r => setTimeout(r, 1000));
        
        // Run with RAG
        console.log('\n📊 WITH RAG:');
        const withRAG = await this.runKnowledgeExamCore(modelName, domain, true);
        
        const improvement = withRAG.averageScore - withoutRAG.averageScore;
        
        return {
            modelName,
            domain,
            withoutRAG: {
                averageScore: withoutRAG.averageScore,
                passed: withoutRAG.passed
            },
            withRAG: {
                averageScore: withRAG.averageScore,
                passed: withRAG.passed
            },
            improvement: improvement,
            percentImprovement: withoutRAG.averageScore > 0 
                ? Math.round((improvement / withoutRAG.averageScore) * 100) 
                : improvement > 0 ? 100 : 0,
            conclusion: improvement > 20 
                ? '🚀 Significant improvement with RAG!' 
                : improvement > 0 
                    ? '📈 Moderate improvement with RAG' 
                    : '📊 Similar performance'
        };
    }
    
    /**
     * Core exam function (internal)
     */
    async runKnowledgeExamCore(modelName, domain, useRAG) {
        const questions = this.generateExamFromKnowledge(domain, 'medium', 2);
        
        let ragContext = '';
        if (useRAG) {
            ragContext = this.buildRAGContext(domain, 1500);
        }
        
        const results = { questions: [], totalScore: 0 };
        
        for (const question of questions) {
            try {
                let systemPrompt = `You are an expert in ${domain}. Answer concisely but completely.`;
                
                if (useRAG && ragContext) {
                    systemPrompt = `You are an expert in ${domain}.

=== KNOWLEDGE BASE ===
${ragContext}
===

Use this knowledge to answer. Include specific techniques and commands from the KB.`;
                }
                
                const answer = await this.llmService.generateOllamaResponse(
                    question.question, null, modelName, systemPrompt
                );
                
                const grade = this.gradeWithKnowledge(answer, question);
                results.questions.push({ ...grade });
                results.totalScore += grade.score;
                
                console.log(`   ${grade.passed ? '✅' : '❌'} ${grade.score}%`);
                
            } catch (error) {
                results.questions.push({ score: 0, passed: false });
            }
        }
        
        results.averageScore = Math.round(results.totalScore / questions.length);
        results.passed = results.averageScore >= 60;
        
        return results;
    }
    
    /**
     * Get available knowledge bases summary
     */
    getKnowledgeSummary() {
        const summary = {};
        
        for (const domain of Object.keys(this.domainMapping)) {
            const knowledge = this.getKnowledgeForDomain(domain);
            summary[domain] = {
                sources: knowledge.map(k => k.source),
                questionCount: this.generateExamFromKnowledge(domain, 'medium', 100).length
            };
        }
        
        return {
            totalKnowledgeBases: Object.keys(this.knowledgeBases).length,
            domains: summary,
            files: Object.keys(this.knowledgeBases)
        };
    }
}

module.exports = KnowledgeIntegratedTraining;
