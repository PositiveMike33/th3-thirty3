/**
 * Test RAG Context Injection
 * 
 * Compares model performance WITH and WITHOUT RAG context
 * to demonstrate the improvement from knowledge injection
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

async function testRAGComparison() {
    console.log('\n');
    console.log('╔═══════════════════════════════════════════════════════════════════╗');
    console.log('║     🧪 RAG CONTEXT INJECTION - COMPARATIVE TEST                   ║');
    console.log('╠═══════════════════════════════════════════════════════════════════╣');
    console.log('║  Comparing: Same questions WITH vs WITHOUT knowledge context      ║');
    console.log('║  Goal: Demonstrate improvement from RAG injection                 ║');
    console.log('╚═══════════════════════════════════════════════════════════════════╝\n');
    
    require('dotenv').config();
    
    const llmService = new MockLLMService();
    const kbTraining = new KnowledgeIntegratedTraining(llmService);
    
    // Test Sadiq on OSINT with RAG
    console.log('═'.repeat(70));
    console.log('🎭 MODEL: Sadiq | DOMAIN: OSINT');
    console.log('═'.repeat(70));
    
    try {
        // Show what RAG context looks like
        const ragContext = kbTraining.buildRAGContext('osint', 500);
        console.log('\n📚 RAG Context Preview (first 300 chars):');
        console.log('─'.repeat(50));
        console.log(ragContext.substring(0, 300) + '...');
        console.log('─'.repeat(50));
        
        // Run WITH RAG
        console.log('\n\n✅ TEST WITH RAG CONTEXT:');
        console.log('─'.repeat(50));
        
        const withRAG = await kbTraining.runKnowledgeExam(
            'sadiq-bd/llama3.2-3b-uncensored',
            'osint',
            true  // Enable RAG
        );
        
        console.log(`\nResult: ${withRAG.averageScore}% ${withRAG.passed ? '✅ PASSED' : '❌ FAILED'}`);
        
        // Run WITHOUT RAG
        console.log('\n\n❌ TEST WITHOUT RAG CONTEXT:');
        console.log('─'.repeat(50));
        
        const withoutRAG = await kbTraining.runKnowledgeExam(
            'sadiq-bd/llama3.2-3b-uncensored',
            'osint',
            false  // Disable RAG
        );
        
        console.log(`\nResult: ${withoutRAG.averageScore}% ${withoutRAG.passed ? '✅ PASSED' : '❌ FAILED'}`);
        
        // Calculate improvement
        const improvement = withRAG.averageScore - withoutRAG.averageScore;
        
        console.log('\n\n');
        console.log('╔═══════════════════════════════════════════════════════════════════╗');
        console.log('║                    📊 COMPARISON RESULTS                          ║');
        console.log('╠═══════════════════════════════════════════════════════════════════╣');
        console.log(`║  WITHOUT RAG:  ${(withoutRAG.averageScore + '%').padEnd(54)}║`);
        console.log(`║  WITH RAG:     ${(withRAG.averageScore + '%').padEnd(54)}║`);
        console.log('╠═══════════════════════════════════════════════════════════════════╣');
        console.log(`║  IMPROVEMENT:  ${improvement > 0 ? '+' : ''}${improvement}% ${improvement > 20 ? '🚀 SIGNIFICANT!' : improvement > 0 ? '📈 Positive' : ''}`.padEnd(68) + '║');
        console.log('╚═══════════════════════════════════════════════════════════════════╝');
        
        // Detailed breakdown
        console.log('\n📝 Question by Question:');
        console.log('─'.repeat(50));
        
        for (let i = 0; i < Math.min(withRAG.questions.length, withoutRAG.questions.length); i++) {
            const qWithRAG = withRAG.questions[i];
            const qWithoutRAG = withoutRAG.questions[i];
            
            console.log(`\nQ${i + 1}: ${qWithRAG.question?.substring(0, 40) || 'N/A'}...`);
            console.log(`   Without RAG: ${qWithoutRAG.score}%`);
            console.log(`   With RAG:    ${qWithRAG.score}%`);
            console.log(`   Change:      ${qWithRAG.score - qWithoutRAG.score > 0 ? '+' : ''}${qWithRAG.score - qWithoutRAG.score}%`);
        }
        
    } catch (error) {
        console.error('Test failed:', error.message);
        console.error(error.stack);
    }
    
    console.log('\n\n🎓 RAG Comparison test complete!\n');
}

testRAGComparison().catch(console.error);
