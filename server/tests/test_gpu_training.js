/**
 * GPU Training Test Suite
 * Verify TensorFlow GPU integration is working
 */

const fetch = require('node-fetch');

const GPU_TRAINER_URL = process.env.GPU_TRAINER_URL || 'http://localhost:5000';

async function testGpuHealth() {
    console.log('\n🔍 Testing GPU Trainer Health...');
    try {
        const response = await fetch(`${GPU_TRAINER_URL}/health`);
        const data = await response.json();

        console.log(`   Status: ${data.status}`);
        console.log(`   GPU Available: ${data.gpu_available}`);
        console.log(`   GPU Count: ${data.gpu_count}`);
        console.log(`   TensorFlow: ${data.tensorflow_version}`);
        console.log(`   Auto-Training: ${data.auto_training}`);

        return data.status === 'healthy';
    } catch (error) {
        console.log(`   ❌ Error: ${error.message}`);
        return false;
    }
}

async function testGpuInfo() {
    console.log('\n🖥️ Testing GPU Info...');
    try {
        const response = await fetch(`${GPU_TRAINER_URL}/api/gpu/info`);
        const data = await response.json();

        console.log(`   Available: ${data.available}`);
        console.log(`   CUDA Built: ${data.cuda_available}`);
        if (data.devices) {
            data.devices.forEach((d, i) => {
                console.log(`   Device ${i}: ${d.name}`);
            });
        }

        return true;
    } catch (error) {
        console.log(`   ❌ Error: ${error.message}`);
        return false;
    }
}

async function testTrainingStart() {
    console.log('\n🚀 Testing Training Start...');
    try {
        const response = await fetch(`${GPU_TRAINER_URL}/api/train/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                job_id: 'test_job_' + Date.now(),
                category: 'security',
                iterations: 2
            })
        });
        const data = await response.json();

        console.log(`   Success: ${data.success}`);
        console.log(`   Job ID: ${data.job_id}`);

        return data.success;
    } catch (error) {
        console.log(`   ❌ Error: ${error.message}`);
        return false;
    }
}

async function testEmbeddings() {
    console.log('\n📊 Testing GPU Embeddings...');
    try {
        const response = await fetch(`${GPU_TRAINER_URL}/api/embeddings`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                texts: ['SQL injection vulnerability detected in login endpoint']
            })
        });
        const data = await response.json();

        console.log(`   Embeddings Generated: ${data.count}`);
        console.log(`   GPU Accelerated: ${data.gpu_accelerated}`);
        console.log(`   Dimension: ${data.embeddings?.[0]?.length || 'N/A'}`);

        return data.embeddings?.length > 0;
    } catch (error) {
        console.log(`   ❌ Error: ${error.message}`);
        return false;
    }
}

async function testVulnAnalysis() {
    console.log('\n🔒 Testing Vulnerability Analysis...');
    try {
        const response = await fetch(`${GPU_TRAINER_URL}/api/analyze/vulnerability`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                content: `
                    query = "SELECT * FROM users WHERE id = '" + user_input + "'";
                    db.execute(query);
                `,
                type: 'code'
            })
        });
        const data = await response.json();

        console.log(`   Risk Score: ${data.risk_score?.toFixed(2)}`);
        console.log(`   GPU Accelerated: ${data.gpu_accelerated}`);
        if (data.vulnerabilities?.length > 0) {
            data.vulnerabilities.forEach(v => {
                console.log(`   - ${v.type} (${v.severity}): ${v.confidence?.toFixed(2)}`);
            });
        }

        return true;
    } catch (error) {
        console.log(`   ❌ Error: ${error.message}`);
        return false;
    }
}

async function runAllTests() {
    console.log('='.repeat(50));
    console.log('  Th3 Thirty3 - GPU Training Test Suite');
    console.log('='.repeat(50));
    console.log(`  Target: ${GPU_TRAINER_URL}`);

    const results = {
        health: await testGpuHealth(),
        gpuInfo: await testGpuInfo(),
        training: await testTrainingStart(),
        embeddings: await testEmbeddings(),
        vulnAnalysis: await testVulnAnalysis()
    };

    console.log('\n' + '='.repeat(50));
    console.log('  TEST RESULTS');
    console.log('='.repeat(50));

    let passed = 0;
    let failed = 0;

    Object.entries(results).forEach(([name, result]) => {
        const status = result ? '✅ PASS' : '❌ FAIL';
        console.log(`  ${status} - ${name}`);
        if (result) passed++; else failed++;
    });

    console.log('\n' + '='.repeat(50));
    console.log(`  Total: ${passed} passed, ${failed} failed`);
    console.log('='.repeat(50));

    process.exit(failed > 0 ? 1 : 0);
}

// Run tests
runAllTests();
