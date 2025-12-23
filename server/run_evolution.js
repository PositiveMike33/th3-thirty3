/**
 * Launch Continuous Evolution Training
 * 
 * Runs focused training on each model's strengths
 */

const ContinuousEvolutionSystem = require('./continuous_evolution_system');
const HackerGPTTrainingService = require('./hackergpt_training_service');

// Mock LLM Service
class MockLLMService {
    async generateOllamaResponse(prompt, imageBase64, modelName, systemPrompt) {
        const { Ollama } = require('ollama');
        const ollama = new Ollama({ host: process.env.OLLAMA_URL || 'http://localhost:11434' });
        
        try {
            const response = await ollama.chat({
                model: modelName,
                messages: [
                    { role: 'system', content: systemPrompt },
                    { role: 'user', content: prompt }
                ]
            });
            return response.message.content;
        } catch (error) {
            throw error;
        }
    }
    
    async generateGroqResponse(prompt, model, systemPrompt) {
        if (!process.env.GROQ_API_KEY) return 'Mock lesson content';
        
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

async function runEvolution() {
    console.log('\n');
    console.log('╔═══════════════════════════════════════════════════════════════════╗');
    console.log('║       🧬 CONTINUOUS EVOLUTION SYSTEM - STRENGTH TRAINING          ║');
    console.log('╠═══════════════════════════════════════════════════════════════════╣');
    console.log('║  Focus: Each model\'s PRIMARY strengths                            ║');
    console.log('║  Goal: Evolve towards Prodigy level (Score 1-10)                  ║');
    console.log('║  Method: Adaptive training with φ complexity scaling              ║');
    console.log('╚═══════════════════════════════════════════════════════════════════╝\n');
    
    require('dotenv').config();
    
    const llmService = new MockLLMService();
    const hackergpt = new HackerGPTTrainingService(llmService, null);
    const evolution = new ContinuousEvolutionSystem(hackergpt, llmService);
    
    // Listen for events
    evolution.on('trainingCompleted', (data) => {
        const status = data.passed ? '✅' : '❌';
        console.log(`   ${status} ${data.domain}: ${data.score}% → Expertise: ${data.newExpertise.toFixed(1)}%`);
    });
    
    evolution.on('levelUp', (data) => {
        console.log(`\n   🎉 LEVEL UP! ${data.levelName}\n`);
    });
    
    evolution.on('prodigyAchieved', (data) => {
        console.log(`\n   ⭐ PRODIGY ACHIEVED! Score: ${data.prodigyScore}/10\n`);
    });
    
    // Models and their primary strengths
    const trainingPlan = [
        {
            model: 'sadiq-bd/llama3.2-3b-uncensored',
            name: 'Sadiq',
            focus: ['social_engineering', 'osint'],  // Primary strengths
            icon: '🎭'
        },
        {
            model: 'uandinotai/dolphin-uncensored',
            name: 'Dolphin',
            focus: ['pentesting', 'exploit_dev'],  // Primary strengths
            icon: '🐬'
        },
        {
            model: 'nidumai/nidum-llama-3.2-3b-uncensored',
            name: 'Nidum',
            focus: ['exploit_dev', 'malware'],  // Primary strengths
            icon: '⚡'
        }
    ];
    
    // Run focused training for each model
    for (const plan of trainingPlan) {
        console.log('═'.repeat(70));
        console.log(`${plan.icon} EVOLVING: ${plan.name}`);
        console.log(`   Strengths: ${plan.focus.join(', ')}`);
        console.log('═'.repeat(70));
        
        for (const domain of plan.focus) {
            console.log(`\n📚 Training: ${domain.toUpperCase()}`);
            console.log('─'.repeat(50));
            
            try {
                const result = await evolution.runEvolutionCycle(plan.model);
                
                if (result.status === 'resting') {
                    console.log(`   😴 Model fatigued, resting...`);
                } else {
                    const state = evolution.getModelState(plan.model);
                    console.log(`   Level: ${state.evolutionLevel} (${evolution.constructor.EVOLUTION_LEVELS || 'Loading...'})`);
                    console.log(`   XP: ${state.experiencePoints}`);
                    console.log(`   Momentum: ${state.momentum.toFixed(2)}x`);
                }
            } catch (error) {
                console.error(`   ❌ Error: ${error.message}`);
            }
            
            // Small delay between trainings
            await new Promise(r => setTimeout(r, 1000));
        }
    }
    
    // Print final status
    console.log('\n\n');
    console.log('╔═══════════════════════════════════════════════════════════════════╗');
    console.log('║                    📊 EVOLUTION STATUS                            ║');
    console.log('╚═══════════════════════════════════════════════════════════════════╝\n');
    
    const status = evolution.getEvolutionStatus();
    
    for (const model of status.models) {
        console.log(`\n${model.name}:`);
        console.log(`  Level: ${model.evolutionLevel} - ${model.levelName}`);
        console.log(`  Sessions: ${model.stats.sessions} | Passed: ${model.stats.passed} | Failed: ${model.stats.failed}`);
        console.log(`  XP: ${model.stats.xp} | Momentum: ${model.stats.momentum.toFixed(2)}x`);
        
        // Show top 3 expertise domains
        const sortedDomains = Object.entries(model.domainExpertise)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 3);
        
        console.log(`  Top Domains:`);
        for (const [domain, expertise] of sortedDomains) {
            const bar = '█'.repeat(Math.floor(expertise / 10)) + '░'.repeat(10 - Math.floor(expertise / 10));
            console.log(`    ${domain.padEnd(20)} ${bar} ${expertise.toFixed(1)}%`);
        }
        
        if (model.prodigyScore) {
            console.log(`  ⭐ PRODIGY SCORE: ${model.prodigyScore}/10`);
        }
    }
    
    console.log('\n\n🎓 Evolution cycle complete!\n');
    console.log('Run this script periodically to continue evolution.');
    console.log('Models will progressively improve in their specialized domains.\n');
}

runEvolution().catch(console.error);
