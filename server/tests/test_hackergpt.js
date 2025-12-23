/**
 * HackerGPT Training Test with Fibonacci Sync
 * 
 * Tests the training system and Fibonacci cognitive harmonization
 */

const HackerGPTTrainingService = require('./hackergpt_training_service');

// Mock LLM Service for testing
class MockLLMService {
    constructor() {
        this.ollamaAvailable = true;
    }
    
    async generateOllamaResponse(prompt, imageBase64, modelName, systemPrompt) {
        console.log(`\n[TEST] Calling Ollama: ${modelName}`);
        
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
            console.error('[TEST] Ollama error:', error.message);
            throw error;
        }
    }
    
    async generateGeminiResponse(prompt, model, systemPrompt) {
        return this.generateGroqResponse(prompt, 'llama-3.3-70b-versatile', systemPrompt);
    }
    
    async generateGroqResponse(prompt, model, systemPrompt) {
        if (!process.env.GROQ_API_KEY) {
            return `# Mock Lesson\n\nPlaceholder for testing.`;
        }
        
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

// Mock Model Metrics Service  
class MockModelMetricsService {
    recordQuery(modelName, data) {
        console.log(`[METRICS] ${modelName}: score=${data.qualityScore}`);
    }
}

async function runTest() {
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║  🎓 HACKERGPT + FIBONACCI COGNITIVE - LIVE TEST              ║');
    console.log('╠══════════════════════════════════════════════════════════════╣');
    console.log('║  Model: nidumai/nidum-llama-3.2-3b-uncensored                ║');
    console.log('║  Course: osint-1 (Passive Reconnaissance)                    ║');
    console.log('║  Sync: Fibonacci Cognitive Optimizer φ=1.618                 ║');
    console.log('╚══════════════════════════════════════════════════════════════╝\n');
    
    require('dotenv').config();
    
    const llmService = new MockLLMService();
    const metricsService = new MockModelMetricsService();
    
    const hackergpt = new HackerGPTTrainingService(llmService, metricsService);
    
    // Test with Nidum this time (precision model)
    const testModel = 'nidumai/nidum-llama-3.2-3b-uncensored';
    const testCourse = 'osint-1';
    
    try {
        // Step 1: Show Fibonacci status BEFORE
        console.log('\n📊 BEFORE EXAM - Fibonacci Status');
        console.log('─'.repeat(50));
        const beforeStatus = hackergpt.getFibonacciStatus(testModel);
        console.log('HackerGPT Level:', beforeStatus.hackergpt.skillLevel?.title || 'Not trained');
        console.log('HackerGPT Score:', beforeStatus.hackergpt.overallScore || 0, '%');
        console.log('Fibonacci Connected:', !!hackergpt.cognitiveOptimizer);
        
        // Step 2: Give exam
        console.log('\n📝 GIVING EXAM: OSINT Fundamentals');
        console.log('─'.repeat(50));
        
        const startTime = Date.now();
        const examResult = await hackergpt.giveExam(testModel, testCourse);
        const duration = ((Date.now() - startTime) / 1000).toFixed(1);
        
        // Step 3: Show results
        console.log('\n📋 EXAM RESULTS');
        console.log('═'.repeat(50));
        console.log(`Model: ${examResult.modelName}`);
        console.log(`Course: ${examResult.courseId}`);
        console.log(`Score: ${examResult.averageScore}%`);
        console.log(`Status: ${examResult.passed ? '✅ PASSED' : '❌ FAILED'}`);
        console.log(`Duration: ${duration}s`);
        
        // Step 4: Show Fibonacci status AFTER
        console.log('\n📈 AFTER EXAM - Fibonacci Sync Status');
        console.log('─'.repeat(50));
        const afterStatus = hackergpt.getFibonacciStatus(testModel);
        console.log('HackerGPT Level:', afterStatus.hackergpt.skillLevel?.title);
        console.log('HackerGPT Score:', afterStatus.hackergpt.overallScore, '%');
        console.log('Exams Completed:', afterStatus.hackergpt.examsCompleted);
        
        if (afterStatus.fibonacci) {
            console.log('\n🌀 Fibonacci Cognitive Metrics:');
            console.log('  φ Level:', afterStatus.fibonacci.level);
            console.log('  Interactions:', afterStatus.fibonacci.totalInteractions);
            console.log('  Success Rate:', (afterStatus.fibonacci.successRate * 100).toFixed(1), '%');
            console.log('  Thinking Reduction:', afterStatus.fibonacci.thinkingReduction);
        }
        
        console.log('\n🎯 Combined Effective Score:', afterStatus.combined.effectiveScore || afterStatus.hackergpt.overallScore, '%');
        console.log('🏆 Elite Status:', afterStatus.combined.isElite ? 'YES' : 'Not yet');
        
        // Summary
        console.log('\n╔══════════════════════════════════════════════════════════════╗');
        console.log('║                  🎉 TEST COMPLETE                            ║');
        console.log('╠══════════════════════════════════════════════════════════════╣');
        console.log(`║  Model: Nidum (Precision)                                    ║`);
        console.log(`║  Score: ${(examResult.averageScore + '%').padEnd(51)}║`);
        console.log(`║  Level: ${(afterStatus.hackergpt.skillLevel?.title || 'N/A').padEnd(51)}║`);
        console.log(`║  φ Sync: ✅ Fibonacci Cognitive Updated                      ║`);
        console.log('╚══════════════════════════════════════════════════════════════╝');
        
    } catch (error) {
        console.error('\n❌ TEST FAILED:', error.message);
        console.error(error.stack);
    }
}

runTest();
