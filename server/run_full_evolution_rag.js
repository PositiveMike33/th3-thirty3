/**
 * Full Evolution Training with RAG
 * 
 * Runs intensive training on all 3 models using RAG context injection
 * for maximum knowledge absorption from the project's KB
 */

const ContinuousEvolutionSystem = require('./continuous_evolution_system');
const HackerGPTTrainingService = require('./hackergpt_training_service');
const KnowledgeIntegratedTraining = require('./knowledge_integrated_training');

// Mock LLM Service
class MockLLMService {
    async generateOllamaResponse(prompt, imageBase64, modelName, systemPrompt) {
        const { Ollama } = require('ollama');
        const ollama = new Ollama({ host: process.env.OLLAMA_URL || 'http://localhost:11434' });
        
        const response = await ollama.chat({
            model: modelName,
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: prompt }
            ]
        });
        return response.message.content;
    }
    
    async generateGroqResponse(prompt, model, systemPrompt) {
        if (!process.env.GROQ_API_KEY) return 'Mock lesson';
        
        const OpenAI = require('openai');
        const client = new OpenAI({
            apiKey: process.env.GROQ_API_KEY,
            baseURL: 'https://api.groq.com/openai/v1'
        });
        
        const completion = await client.chat.completions.create({
            model: model || 'llama-3.3-70b-versatile',
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: prompt }
            ]
        });
        
        return completion.choices[0].message.content;
    }
}

// Training plan - Focus on each model's strengths
const TRAINING_PLAN = [
    {
        model: 'sadiq-bd/llama3.2-3b-uncensored',
        name: 'Sadiq',
        icon: '🎭',
        domains: ['osint', 'pentesting', 'wireless']  // His strengths + related
    },
    {
        model: 'uandinotai/dolphin-uncensored',
        name: 'Dolphin',
        icon: '🐬',
        domains: ['pentesting', 'exploit_dev', 'red_team']  // His strengths
    },
    {
        model: 'nidumai/nidum-llama-3.2-3b-uncensored',
        name: 'Nidum',
        icon: '⚡',
        domains: ['exploit_dev', 'cryptography', 'forensics']  // His strengths
    }
];

async function runFullEvolutionWithRAG() {
    console.log('\n');
    console.log('╔═══════════════════════════════════════════════════════════════════╗');
    console.log('║     🧬 FULL EVOLUTION TRAINING WITH RAG INJECTION                 ║');
    console.log('╠═══════════════════════════════════════════════════════════════════╣');
    console.log('║  Mode: Intensive training with Knowledge Base context             ║');
    console.log('║  RAG: ENABLED - Models receive KB context before each question    ║');
    console.log('║  Goal: Maximize learning from real project data                   ║');
    console.log('╚═══════════════════════════════════════════════════════════════════╝\n');
    
    require('dotenv').config();
    
    const llmService = new MockLLMService();
    const kbTraining = new KnowledgeIntegratedTraining(llmService);
    const hackergpt = new HackerGPTTrainingService(llmService, null);
    const evolution = new ContinuousEvolutionSystem(hackergpt, llmService);
    
    // Show KB summary
    const summary = kbTraining.getKnowledgeSummary();
    console.log(`📚 Knowledge Bases Loaded: ${summary.totalKnowledgeBases}`);
    console.log('─'.repeat(50));
    
    const results = {
        timestamp: new Date().toISOString(),
        models: {}
    };
    
    // Train each model on their strength domains
    for (const plan of TRAINING_PLAN) {
        console.log('\n\n' + '═'.repeat(70));
        console.log(`${plan.icon} TRAINING: ${plan.name}`);
        console.log(`   Domains: ${plan.domains.join(', ')}`);
        console.log('═'.repeat(70));
        
        results.models[plan.model] = {
            name: plan.name,
            domains: {},
            totalScore: 0,
            trainingCount: 0
        };
        
        for (const domain of plan.domains) {
            console.log(`\n📚 Domain: ${domain.toUpperCase()}`);
            console.log('─'.repeat(50));
            
            // Check if domain has questions
            const questions = kbTraining.generateExamFromKnowledge(domain, 'medium', 10);
            if (questions.length === 0) {
                console.log(`   ⚠️ No KB questions for ${domain}, skipping...`);
                continue;
            }
            
            try {
                // Run exam WITH RAG
                const examResult = await kbTraining.runKnowledgeExam(
                    plan.model,
                    domain,
                    true  // Enable RAG
                );
                
                results.models[plan.model].domains[domain] = {
                    score: examResult.averageScore,
                    passed: examResult.passed,
                    questions: examResult.questions.length
                };
                
                results.models[plan.model].totalScore += examResult.averageScore;
                results.models[plan.model].trainingCount++;
                
                // Update evolution state
                const state = evolution.getModelState(plan.model);
                state.domainExpertise[domain] = Math.max(
                    state.domainExpertise[domain] || 0,
                    examResult.averageScore * 0.8  // Weighted by performance
                );
                state.experiencePoints += examResult.averageScore;
                evolution.saveState();
                
                // Sync with Fibonacci
                hackergpt.syncWithFibonacci(plan.model, domain, examResult.averageScore, examResult.passed);
                
                console.log(`\n   📊 Result: ${examResult.averageScore}% ${examResult.passed ? '✅' : '❌'}`);
                
            } catch (error) {
                console.error(`   ❌ Error: ${error.message}`);
            }
        }
        
        // Calculate average for model
        const modelResult = results.models[plan.model];
        if (modelResult.trainingCount > 0) {
            modelResult.averageScore = Math.round(modelResult.totalScore / modelResult.trainingCount);
        }
    }
    
    // Final report
    console.log('\n\n');
    console.log('╔═══════════════════════════════════════════════════════════════════╗');
    console.log('║                    📊 TRAINING REPORT                             ║');
    console.log('╚═══════════════════════════════════════════════════════════════════╝\n');
    
    for (const plan of TRAINING_PLAN) {
        const modelResult = results.models[plan.model];
        console.log(`${plan.icon} ${plan.name}:`);
        console.log(`   Average Score: ${modelResult.averageScore || 0}%`);
        console.log(`   Domains Trained: ${modelResult.trainingCount}`);
        
        for (const [domain, data] of Object.entries(modelResult.domains || {})) {
            const status = data.passed ? '✅' : '❌';
            console.log(`     ${domain}: ${data.score}% ${status}`);
        }
        console.log('');
    }
    
    // Evolution status
    console.log('─'.repeat(70));
    console.log('🧬 EVOLUTION STATUS:');
    console.log('─'.repeat(70));
    
    const evolutionStatus = evolution.getEvolutionStatus();
    for (const model of evolutionStatus.models) {
        console.log(`\n${model.name}:`);
        console.log(`   Level: ${model.evolutionLevel} - ${model.levelName}`);
        console.log(`   XP: ${model.stats.xp}`);
        
        // Top domains
        const sortedDomains = Object.entries(model.domainExpertise || {})
            .sort((a, b) => b[1] - a[1])
            .slice(0, 3);
        
        if (sortedDomains.length > 0) {
            console.log('   Top Expertise:');
            for (const [domain, expertise] of sortedDomains) {
                const bar = '█'.repeat(Math.floor(expertise / 10)) + '░'.repeat(10 - Math.floor(expertise / 10));
                console.log(`     ${domain.padEnd(20)} ${bar} ${expertise.toFixed(1)}%`);
            }
        }
    }
    
    console.log('\n\n🎓 Full RAG-enhanced training complete!\n');
    console.log('Models are now learning from real project knowledge.\n');
    console.log('Run this script regularly to continue their evolution.\n');
    
    return results;
}

runFullEvolutionWithRAG().catch(console.error);
