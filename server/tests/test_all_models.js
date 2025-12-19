/**
 * Model Performance Test Suite
 * Tests all available Ollama models for response time, quality, and compatibility
 */

const http = require('http');

// All available models (4 models only)
const MODELS = [
    'qwen2.5-coder:7b',        // Code/Technical
    'mistral:7b-instruct',     // Strategy/General
    'granite3.1-moe:1b'        // Fast/Fallback
    // nomic-embed-text excluded (embedding model, not generation)
];

// Test prompts for different capabilities
const TEST_PROMPTS = {

    coding: "Write a JavaScript function that checks if a string is a palindrome. Keep it short.",
    analysis: "What is SQL injection? Explain in 2 sentences.",
    creative: "Write a haiku about cybersecurity.",
    reasoning: "If all hackers are programmers, and some programmers are artists, can hackers be artists? Answer briefly."
};

class ModelTester {
    constructor() {
        this.results = [];
    }

    async testModel(modelName, prompt, category) {
        return new Promise((resolve) => {
            const startTime = Date.now();
            let response = '';
            let error = null;

            const postData = JSON.stringify({
                model: modelName,
                prompt: prompt,
                stream: false,
                options: {
                    temperature: 0.7,
                    num_predict: 150  // Limit tokens for faster testing
                }
            });

            const options = {
                hostname: 'localhost',
                port: 11434,
                path: '/api/generate',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(postData)
                },
                timeout: 60000  // 60s timeout
            };

            const req = http.request(options, (res) => {
                res.on('data', (chunk) => {
                    try {
                        const data = JSON.parse(chunk.toString());
                        response += data.response || '';
                    } catch (e) {
                        response += chunk.toString();
                    }
                });

                res.on('end', () => {
                    const endTime = Date.now();
                    resolve({
                        model: modelName,
                        category,
                        success: res.statusCode === 200,
                        responseTime: endTime - startTime,
                        responseLength: response.length,
                        preview: response.substring(0, 100).replace(/\n/g, ' '),
                        error: null
                    });
                });
            });

            req.on('error', (e) => {
                resolve({
                    model: modelName,
                    category,
                    success: false,
                    responseTime: Date.now() - startTime,
                    responseLength: 0,
                    preview: '',
                    error: e.message
                });
            });

            req.on('timeout', () => {
                req.destroy();
                resolve({
                    model: modelName,
                    category,
                    success: false,
                    responseTime: 60000,
                    responseLength: 0,
                    preview: '',
                    error: 'Timeout (60s)'
                });
            });

            req.write(postData);
            req.end();
        });
    }

    async runFullTest() {
        console.log('╔════════════════════════════════════════════════════════════════╗');
        console.log('║           MODEL PERFORMANCE TEST SUITE                         ║');
        console.log('║           Testing 6 models × 4 categories = 24 tests           ║');
        console.log('╚════════════════════════════════════════════════════════════════╝\n');

        const results = {};

        for (const model of MODELS) {
            console.log(`\n📦 Testing: ${model}`);
            console.log('─'.repeat(60));
            
            results[model] = {
                tests: [],
                avgResponseTime: 0,
                successRate: 0
            };

            for (const [category, prompt] of Object.entries(TEST_PROMPTS)) {
                process.stdout.write(`  [${category}] `);
                
                const result = await this.testModel(model, prompt, category);
                results[model].tests.push(result);
                
                if (result.success) {
                    console.log(`✅ ${result.responseTime}ms (${result.responseLength} chars)`);
                } else {
                    console.log(`❌ ${result.error || 'Failed'}`);
                }
            }

            // Calculate stats
            const tests = results[model].tests;
            const successful = tests.filter(t => t.success);
            results[model].avgResponseTime = successful.length > 0 
                ? Math.round(successful.reduce((a, t) => a + t.responseTime, 0) / successful.length)
                : 0;
            results[model].successRate = Math.round((successful.length / tests.length) * 100);
        }

        // Print summary
        console.log('\n\n╔════════════════════════════════════════════════════════════════╗');
        console.log('║                    TEST SUMMARY                                 ║');
        console.log('╚════════════════════════════════════════════════════════════════╝\n');

        console.log('┌─────────────────────────────────────┬───────────┬───────────────┐');
        console.log('│ Model                               │ Success   │ Avg Time      │');
        console.log('├─────────────────────────────────────┼───────────┼───────────────┤');
        
        for (const [model, data] of Object.entries(results)) {
            const name = model.padEnd(35);
            const success = `${data.successRate}%`.padEnd(9);
            const time = data.avgResponseTime > 0 ? `${data.avgResponseTime}ms`.padEnd(13) : 'N/A'.padEnd(13);
            console.log(`│ ${name} │ ${success} │ ${time} │`);
        }
        
        console.log('└─────────────────────────────────────┴───────────┴───────────────┘');

        // Save results to JSON
        const fs = require('fs');
        fs.writeFileSync(
            require('path').join(__dirname, 'data', 'model_test_results.json'),
            JSON.stringify({ timestamp: new Date().toISOString(), results }, null, 2)
        );
        console.log('\n📄 Results saved to data/model_test_results.json');

        return results;
    }
}

// Run if executed directly
if (require.main === module) {
    const tester = new ModelTester();
    tester.runFullTest().then(() => {
        console.log('\n✅ All tests complete!');
        process.exit(0);
    }).catch(err => {
        console.error('Test failed:', err);
        process.exit(1);
    });
}

module.exports = ModelTester;
