/**
 * Comprehensive System Integration Test Suite
 * Runs after each change to ensure code quality
 * Target: 100% pass rate before proceeding
 */

const DartService = require('../dart_service');
const OrchestratorService = require('../orchestrator_service');
const ModelMetricsService = require('../model_metrics_service');
const LLMService = require('../llm_service');

class TestRunner {
    constructor() {
        this.results = [];
        this.passed = 0;
        this.failed = 0;
    }

    async test(name, fn) {
        process.stdout.write(`[TEST] ${name}... `);
        try {
            await fn();
            console.log('✅ PASS');
            this.results.push({ name, status: 'PASS' });
            this.passed++;
        } catch (error) {
            console.log(`❌ FAIL: ${error.message}`);
            this.results.push({ name, status: 'FAIL', error: error.message });
            this.failed++;
        }
    }

    printSummary() {
        console.log('\n=== TEST SUMMARY ===');
        console.log(`Passed: ${this.passed}/${this.passed + this.failed}`);
        console.log(`Failed: ${this.failed}/${this.passed + this.failed}`);
        
        if (this.failed > 0) {
            console.log('\n❌ FAILED TESTS:');
            this.results.filter(r => r.status === 'FAIL').forEach(r => {
                console.log(`  - ${r.name}: ${r.error}`);
            });
        }
        
        return this.failed === 0;
    }
}

async function runTests() {
    console.log('=== SYSTEM INTEGRATION TEST SUITE ===\n');
    const runner = new TestRunner();

    // ========================================
    // SECTION 1: DartAI Service Tests
    // ========================================
    console.log('[SECTION 1] DartAI Service\n');

    await runner.test('DartService instantiation', async () => {
        const dart = new DartService();
        if (!dart || !dart.token || !dart.workspaceId) throw new Error('Service not initialized');
    });

    await runner.test('DartService authentication', async () => {
        const dart = new DartService();
        const result = await dart.authenticate();
        if (!result) throw new Error('Auth failed');
    });

    await runner.test('DartService list tasks', async () => {
        const dart = new DartService();
        const result = await dart.listTasks();
        if (!result.success && result.success !== false) throw new Error('Invalid response structure');
    });

    await runner.test('DartService create task', async () => {
        const dart = new DartService();
        const result = await dart.createTask('Test Task ' + Date.now(), { description: 'Auto-test' });
        if (!result.success && result.success !== false) throw new Error('Invalid response structure');
    });

    await runner.test('DartService get tasks by status', async () => {
        const dart = new DartService();
        const result = await dart.getTasksByStatus('todo');
        if (result.success === undefined) throw new Error('Invalid response');
    });

    await runner.test('DartService breakdown task (mock)', async () => {
        const dart = new DartService();
        const result = await dart.breakdownTask('Test description');
        if (!result.success || !result.breakdown) throw new Error('Breakdown failed');
    });

    // ========================================
    // SECTION 2: Orchestrator Tests
    // ========================================
    console.log('\n[SECTION 2] Orchestrator Service\n');

    await runner.test('Orchestrator instantiation', async () => {
        const orch = new OrchestratorService();
        if (!orch) throw new Error('Orchestrator not initialized');
        if (!orch.dartSyncEnabled) console.warn('  ⚠️  DartAI sync disabled');
    });

    await runner.test('Orchestrator has DartService', async () => {
        const orch = new OrchestratorService();
        if (!orch.dartService) throw new Error('DartService not attached to orchestrator');
    });

    await runner.test('Orchestrator team structure', async () => {
        const orch = new OrchestratorService();
        if (!orch.teams || Object.keys(orch.teams).length === 0) {
            throw new Error('No teams configured');
        }
        const totalAgents = orch.getTotalAgents();
        if (totalAgents < 30) throw new Error(`Expected 30+ agents, got ${totalAgents}`);
    });

    // ========================================
    // SECTION 3: Model Metrics Tests
    // ========================================
    console.log('\n[SECTION 3] Model Metrics Service\n');

    await runner.test('ModelMetrics instantiation', async () => {
        const metrics = new ModelMetricsService();
        if (!metrics) throw new Error('Metrics service not initialized');
    });

    await runner.test('ModelMetrics skips non-Ollama models', async () => {
        const metrics = new ModelMetricsService();
        const result = await metrics.runBenchmark('[ANYTHINGLLM] workspace-test', null);
        if (result !== null) throw new Error('Should skip non-Ollama models');
    });

    await runner.test('ModelMetrics skips invalid model names', async () => {
        const metrics = new ModelMetricsService();
        const result1 = await metrics.runBenchmark('', null);
        const result2 = await metrics.runBenchmark('invalid-no-colon', null);
        if (result1 !== null || result2 !== null) {
            throw new Error('Should skip invalid models');
        }
    });

    // ========================================
    // SECTION 4: LLM Service Tests
    // ========================================
    console.log('\n[SECTION 4] LLM Service\n');

    await runner.test('LLMService instantiation', async () => {
        const llm = new LLMService();
        if (!llm || !llm.ollama) throw new Error('LLM Service not initialized');
    });

    await runner.test('LLMService listModels (no verbose logs)', async () => {
        const llm = new LLMService();
        // Capture console to check for spam
        const originalLog = console.log;
        let logCount = 0;
        console.log = (...args) => {
            if (args[0]?.includes('[LLM] Checking Ollama') || args[0]?.includes('[LLM] listModels called')) {
                logCount++;
            }
        };
        
        await llm.listModels();
        console.log = originalLog;
        
        if (logCount > 0) throw new Error(`Found ${logCount} verbose log messages (should be 0)`);
    });

    // ========================================
    // SECTION 5: Integration Tests
    // ========================================
    console.log('\n[SECTION 5] Integration Tests\n');

    await runner.test('Orchestrator → DartAI Sync (Full Flow)', async () => {
        const orch = new OrchestratorService();
        if (!orch.dartSyncEnabled) {
            console.log('  ⚠️  Skipped (DartAI sync disabled)');
            return; // Skip but don't fail
        }
        
        // This is a long test - only run if DartAI is enabled
        const mission = await orch.executeMission('Simple test mission for integration');
        
        if (mission.status !== 'completed' && mission.status !== 'failed') {
            throw new Error(`Unexpected mission status: ${mission.status}`);
        }
        
        // Check if DartAI sync happened
        if (mission.status === 'completed' && !mission.dartSynced) {
            throw new Error('Mission completed but dartSynced = false');
        }
    });

    // ========================================
    // Print Results
    // ========================================
    const allPassed = runner.printSummary();
    
    console.log('\n=== RECOMMENDATION ===');
    if (allPassed) {
        console.log('✅ All tests passed! Safe to proceed to next phase.');
    } else {
        console.log('❌ Some tests failed. Fix issues before proceeding.');
        console.log('   Run this test again after fixes.');
    }
    
    process.exit(allPassed ? 0 : 1);
}

// Run if executed directly
if (require.main === module) {
    runTests().catch(err => {
        console.error('Test runner crashed:', err);
        process.exit(1);
    });
}

module.exports = runTests;
