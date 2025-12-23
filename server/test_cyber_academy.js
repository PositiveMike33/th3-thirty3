/**
 * HackerGPT Elite Cyber Academy - Full Training Suite
 * 
 * Tests all 3 uncensored models across multiple cybersecurity domains
 * Generates a comprehensive report card for each model
 */

const HackerGPTTrainingService = require('./hackergpt_training_service');
const fs = require('fs');
const path = require('path');

// Load comprehensive curriculum
const CURRICULUM = JSON.parse(fs.readFileSync(
    path.join(__dirname, 'data', 'training', 'cyber_academy_curriculum.json'), 
    'utf8'
));

// Models to test
const MODELS = [
    {
        name: 'uandinotai/dolphin-uncensored',
        displayName: 'Dolphin',
        specialty: 'Kernel & Complex Instructions',
        strengths: ['exploit_dev', 'web_security', 'redteam']
    },
    {
        name: 'nidumai/nidum-llama-3.2-3b-uncensored',
        displayName: 'Nidum',
        specialty: 'Precision & Code Generation',
        strengths: ['exploit_dev', 'network', 'pentesting']
    },
    {
        name: 'sadiq-bd/llama3.2-3b-uncensored',
        displayName: 'Sadiq',
        specialty: 'Creativity & Social Engineering',
        strengths: ['social_engineering', 'osint', 'wireless']
    }
];

// Tests to run (selected for speed - one per domain)
const QUICK_TESTS = [
    { course: 'osint-1', track: 'OSINT' },
    { course: 'pentest-1', track: 'Pentesting' },
    { course: 'web-1', track: 'Web Security' },
    { course: 'social-1', track: 'Social Engineering' }
];

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
            console.error(`[ERROR] ${modelName}: ${error.message}`);
            throw error;
        }
    }
    
    async generateGeminiResponse() { return 'Mock lesson'; }
    async generateGroqResponse() { return 'Mock lesson'; }
}

async function runFullAcademy() {
    console.log('\n');
    console.log('╔═══════════════════════════════════════════════════════════════════╗');
    console.log('║     🎓 HACKERGPT ELITE CYBER ACADEMY - FULL EVALUATION            ║');
    console.log('╠═══════════════════════════════════════════════════════════════════╣');
    console.log('║  Models: Dolphin, Nidum, Sadiq                                    ║');
    console.log('║  Domains: OSINT, Pentesting, Web Security, Social Engineering     ║');
    console.log('║  Sync: Fibonacci Cognitive Optimizer φ=1.618                      ║');
    console.log('╚═══════════════════════════════════════════════════════════════════╝\n');
    
    require('dotenv').config();
    
    const llmService = new MockLLMService();
    const hackergpt = new HackerGPTTrainingService(llmService, null);
    
    const results = {
        timestamp: new Date().toISOString(),
        models: {},
        summary: {
            bestOverall: null,
            bestByDomain: {},
            recommendations: []
        }
    };
    
    // Test each model on each domain
    for (const model of MODELS) {
        console.log(`\n${'═'.repeat(70)}`);
        console.log(`🤖 TESTING: ${model.displayName}`);
        console.log(`   Specialty: ${model.specialty}`);
        console.log('═'.repeat(70));
        
        results.models[model.name] = {
            displayName: model.displayName,
            specialty: model.specialty,
            exams: {},
            totalScore: 0,
            examsTaken: 0,
            examsPassed: 0
        };
        
        for (const test of QUICK_TESTS) {
            console.log(`\n📝 Exam: ${test.track} (${test.course})`);
            console.log('─'.repeat(50));
            
            try {
                const startTime = Date.now();
                const examResult = await hackergpt.giveExam(model.name, test.course);
                const duration = ((Date.now() - startTime) / 1000).toFixed(1);
                
                const passed = examResult.passed;
                const score = examResult.averageScore;
                
                console.log(`   Score: ${score}% ${passed ? '✅ PASSED' : '❌ FAILED'} (${duration}s)`);
                
                results.models[model.name].exams[test.course] = {
                    track: test.track,
                    score: score,
                    passed: passed,
                    duration: duration
                };
                
                results.models[model.name].totalScore += score;
                results.models[model.name].examsTaken++;
                if (passed) results.models[model.name].examsPassed++;
                
            } catch (error) {
                console.log(`   ❌ ERROR: ${error.message}`);
                results.models[model.name].exams[test.course] = {
                    track: test.track,
                    score: 0,
                    passed: false,
                    error: error.message
                };
                results.models[model.name].examsTaken++;
            }
        }
        
        // Calculate average
        const modelResult = results.models[model.name];
        modelResult.averageScore = Math.round(modelResult.totalScore / modelResult.examsTaken);
        
        // Get Fibonacci status
        const fibStatus = hackergpt.getFibonacciStatus(model.name);
        modelResult.hackergptLevel = fibStatus.hackergpt.skillLevel?.title;
        modelResult.fibonacciLevel = fibStatus.fibonacci?.level;
        modelResult.combinedScore = fibStatus.combined.effectiveScore;
    }
    
    // Generate summary
    generateSummary(results);
    
    // Print report card
    printReportCard(results, hackergpt);
    
    // Save results
    const resultsPath = path.join(__dirname, 'data', 'hackergpt_academy_results.json');
    fs.writeFileSync(resultsPath, JSON.stringify(results, null, 2));
    console.log(`\n📁 Results saved to: ${resultsPath}`);
    
    return results;
}

function generateSummary(results) {
    const models = Object.entries(results.models);
    
    // Find best overall
    let bestScore = 0;
    let bestModel = null;
    
    for (const [name, data] of models) {
        if (data.averageScore > bestScore) {
            bestScore = data.averageScore;
            bestModel = name;
        }
    }
    
    results.summary.bestOverall = {
        model: bestModel,
        displayName: results.models[bestModel].displayName,
        score: bestScore
    };
    
    // Find best per domain
    for (const test of QUICK_TESTS) {
        let bestDomainScore = 0;
        let bestDomainModel = null;
        
        for (const [name, data] of models) {
            const examScore = data.exams[test.course]?.score || 0;
            if (examScore > bestDomainScore) {
                bestDomainScore = examScore;
                bestDomainModel = name;
            }
        }
        
        results.summary.bestByDomain[test.track] = {
            model: bestDomainModel,
            displayName: results.models[bestDomainModel].displayName,
            score: bestDomainScore
        };
    }
    
    // Generate recommendations
    results.summary.recommendations = [
        `🏆 Best Overall: ${results.summary.bestOverall.displayName} (${bestScore}%)`,
        ...Object.entries(results.summary.bestByDomain).map(([domain, data]) => 
            `${domain}: Use ${data.displayName} (${data.score}%)`
        )
    ];
}

function printReportCard(results, hackergpt) {
    console.log('\n');
    console.log('╔═══════════════════════════════════════════════════════════════════╗');
    console.log('║                    📊 ACADEMY REPORT CARD                         ║');
    console.log('╠═══════════════════════════════════════════════════════════════════╣');
    
    // Header
    console.log('║                  │ Dolphin │  Nidum  │  Sadiq  │                  ║');
    console.log('╠══════════════════╪═════════╪═════════╪═════════╪══════════════════╣');
    
    // Scores per domain
    for (const test of QUICK_TESTS) {
        const dolphin = results.models['uandinotai/dolphin-uncensored']?.exams[test.course]?.score || 0;
        const nidum = results.models['nidumai/nidum-llama-3.2-3b-uncensored']?.exams[test.course]?.score || 0;
        const sadiq = results.models['sadiq-bd/llama3.2-3b-uncensored']?.exams[test.course]?.score || 0;
        
        const dStatus = dolphin >= 60 ? '✅' : '❌';
        const nStatus = nidum >= 60 ? '✅' : '❌';
        const sStatus = sadiq >= 60 ? '✅' : '❌';
        
        const row = `║ ${test.track.padEnd(16)} │ ${(dolphin + '%').padStart(4)} ${dStatus} │ ${(nidum + '%').padStart(4)} ${nStatus} │ ${(sadiq + '%').padStart(4)} ${sStatus} │`;
        console.log(row.padEnd(71) + '║');
    }
    
    console.log('╠══════════════════╪═════════╪═════════╪═════════╪══════════════════╣');
    
    // Averages
    const dAvg = results.models['uandinotai/dolphin-uncensored']?.averageScore || 0;
    const nAvg = results.models['nidumai/nidum-llama-3.2-3b-uncensored']?.averageScore || 0;
    const sAvg = results.models['sadiq-bd/llama3.2-3b-uncensored']?.averageScore || 0;
    
    console.log(`║ AVERAGE          │ ${(dAvg + '%').padStart(6)}  │ ${(nAvg + '%').padStart(6)}  │ ${(sAvg + '%').padStart(6)}  │`.padEnd(71) + '║');
    
    // Levels
    const dLevel = results.models['uandinotai/dolphin-uncensored']?.hackergptLevel || 'N/A';
    const nLevel = results.models['nidumai/nidum-llama-3.2-3b-uncensored']?.hackergptLevel || 'N/A';
    const sLevel = results.models['sadiq-bd/llama3.2-3b-uncensored']?.hackergptLevel || 'N/A';
    
    console.log('╠══════════════════╧═════════╧═════════╧═════════╧══════════════════╣');
    console.log('║                         SKILL LEVELS                              ║');
    console.log('╠═══════════════════════════════════════════════════════════════════╣');
    console.log(`║  Dolphin: ${dLevel}`.padEnd(71) + '║');
    console.log(`║  Nidum:   ${nLevel}`.padEnd(71) + '║');
    console.log(`║  Sadiq:   ${sLevel}`.padEnd(71) + '║');
    
    console.log('╠═══════════════════════════════════════════════════════════════════╣');
    console.log('║                       RECOMMENDATIONS                             ║');
    console.log('╠═══════════════════════════════════════════════════════════════════╣');
    
    for (const rec of results.summary.recommendations) {
        console.log(`║  ${rec}`.padEnd(71) + '║');
    }
    
    console.log('╚═══════════════════════════════════════════════════════════════════╝');
}

// Run the academy
runFullAcademy().then(() => {
    console.log('\n🎓 Academy evaluation complete!\n');
}).catch(err => {
    console.error('Academy error:', err);
});
