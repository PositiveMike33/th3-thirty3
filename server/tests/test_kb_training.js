/**
 * Test Knowledge-Integrated Training
 * 
 * Tests the system with real knowledge base data
 */

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
}

async function testKBTraining() {
    console.log('\n');
    console.log('╔═══════════════════════════════════════════════════════════════════╗');
    console.log('║     📚 KNOWLEDGE-INTEGRATED TRAINING TEST                         ║');
    console.log('╠═══════════════════════════════════════════════════════════════════╣');
    console.log('║  Using: Real project datasets                                     ║');
    console.log('║  Sources: osint_shodan, pentestgpt_methodology, etc.              ║');
    console.log('╚═══════════════════════════════════════════════════════════════════╝\n');
    
    require('dotenv').config();
    
    const llmService = new MockLLMService();
    const kbTraining = new KnowledgeIntegratedTraining(llmService);
    
    // Show knowledge summary
    console.log('📊 Knowledge Base Summary:');
    console.log('─'.repeat(50));
    const summary = kbTraining.getKnowledgeSummary();
    console.log(`Total KB files: ${summary.totalKnowledgeBases}`);
    console.log('\nDomain coverage:');
    
    for (const [domain, info] of Object.entries(summary.domains)) {
        console.log(`  ${domain}: ${info.questionCount} questions from ${info.sources.length} sources`);
    }
    
    // Test with Sadiq on OSINT (real data!)
    console.log('\n\n═'.repeat(70));
    console.log('🧪 TESTING: Sadiq on OSINT (with real Shodan training data)');
    console.log('═'.repeat(70));
    
    try {
        const result = await kbTraining.runKnowledgeExam(
            'sadiq-bd/llama3.2-3b-uncensored',
            'osint'
        );
        
        console.log('\n📋 RESULTS:');
        console.log('─'.repeat(50));
        console.log(`Average Score: ${result.averageScore}%`);
        console.log(`Status: ${result.passed ? '✅ PASSED' : '❌ FAILED'}`);
        
        console.log('\n📝 Question Breakdown:');
        for (const q of result.questions) {
            const status = q.passed ? '✅' : '❌';
            console.log(`\n${status} Score: ${q.score}%`);
            console.log(`   Q: ${q.question.substring(0, 60)}...`);
            if (q.feedback) {
                console.log(`   Feedback: ${q.feedback}`);
            }
        }
    } catch (error) {
        console.error('Test failed:', error.message);
    }
    
    // Test with Dolphin on Pentesting (with PentestGPT methodology!)
    console.log('\n\n═'.repeat(70));
    console.log('🧪 TESTING: Dolphin on Pentesting (with PentestGPT methodology)');
    console.log('═'.repeat(70));
    
    try {
        const result = await kbTraining.runKnowledgeExam(
            'uandinotai/dolphin-uncensored',
            'pentesting'
        );
        
        console.log('\n📋 RESULTS:');
        console.log('─'.repeat(50));
        console.log(`Average Score: ${result.averageScore}%`);
        console.log(`Status: ${result.passed ? '✅ PASSED' : '❌ FAILED'}`);
        
        for (const q of result.questions) {
            const status = q.passed ? '✅' : '❌';
            console.log(`\n${status} Score: ${q.score}%`);
            console.log(`   Q: ${q.question.substring(0, 60)}...`);
        }
    } catch (error) {
        console.error('Test failed:', error.message);
    }
    
    console.log('\n\n🎓 Knowledge-Integrated Training test complete!');
    console.log('Real project data is now being used for model evaluation.\n');
}

testKBTraining().catch(console.error);
