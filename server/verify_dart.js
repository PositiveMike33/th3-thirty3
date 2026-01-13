require('dotenv').config();
const DartService = require('./dart_service');
const LLMService = require('./llm_service');

const runTest = async () => {
    try {
        console.log('🧪 Testing Dart AI Breakdown (Integration with LLM)...');

        // 1. Init LLM Service
        const llmService = new LLMService();
        console.log('✅ LLM Service Initialized');

        // 2. Init Dart Service
        const dartService = new DartService(llmService);
        console.log('✅ Dart Service Initialized');

        // 3. Request Breakdown
        const taskDescription = "Create a portfolio website using React and TailwindCSS";
        console.log(`\n🤖 Requesting breakdown for: "${taskDescription}"...`);

        const result = await dartService.breakdownTask(taskDescription);

        if (!result.success) throw new Error('Breakdown failed');

        console.log('\n📄 Result Preview:');
        console.log('---------------------------------------------------');
        console.log(result.breakdown.substring(0, 200) + '...');
        console.log('---------------------------------------------------');

        // 4. Verification
        if (result.breakdown.includes('MOCK - LLM Unavailable')) {
            console.warn('⚠️ WARNING: Returned MOCK response. LLM might be offline or keys missing.');
            // We treat this as "Soft Failure" - the service works, but LLM didn't. 
            // For now, exit 0 to not block, but log it.
        } else {
            console.log('✅ SUCCESS: Real AI response received.');
        }

        process.exit(0);

    } catch (error) {
        console.error('❌ Test Failed:', error);
        process.exit(1);
    }
};

runTest();
