require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { getPatterns } = require('./fabric_service');
const PiecesService = require('./pieces_service');
const LLMService = require('./llm_service');
const settingsService = require('./settings_service');

async function runTests() {
    console.log("=== TH3 THIRTY3 SYSTEM DIAGNOSTIC ===");
    let errors = 0;

    // 1. Settings Check
    console.log("\n[1] Checking Settings...");
    try {
        const settings = settingsService.getSettings();
        // AnythingLLM is only required in cloud mode
        if (settings.computeMode === 'cloud' && !settings.apiKeys.anythingllm_key) {
            throw new Error("AnythingLLM Key missing (required for cloud mode)");
        }
        if (settings.apiKeys.anythingllm_url && settings.apiKeys.anythingllm_url.includes('|')) {
            throw new Error("AnythingLLM URL corrupted");
        }
        console.log(`✅ Settings loaded correctly. Mode: ${settings.computeMode || 'local'}`);
    } catch (e) {
        console.error("❌ Settings Error:", e.message);
        errors++;
    }

    // 2. Fabric Check
    console.log("\n[2] Checking Fabric Patterns...");
    try {
        const patterns = getPatterns();
        if (patterns.length === 0) throw new Error("No patterns found");
        console.log(`✅ Found ${patterns.length} patterns.`);
    } catch (e) {
        console.error("❌ Fabric Error:", e.message);
        errors++;
    }

    // 3. Pieces Check
    console.log("\n[3] Checking Pieces Service...");
    try {
        const pieces = new PiecesService();
        const piecesHealth = await pieces.healthCheck();
        if (piecesHealth) {
            console.log("✅ Pieces OS connected.");
        } else {
            console.warn("⚠️ Pieces OS not detected (Warning only).");
        }
    } catch (e) {
        console.error("❌ Pieces Error:", e.message);
        // Warning only
    }

    // 4. LLM Service Check
    console.log("\n[4] Checking LLM Service...");
    try {
        const llm = new LLMService();

        // Mock Env Vars for test
        const settings = settingsService.getSettings();
        process.env.ANYTHING_LLM_URL = settings.apiKeys.anythingllm_url;
        process.env.ANYTHING_LLM_KEY = settings.apiKeys.anythingllm_key;

        const models = await llm.listModels('cloud');
        console.log(`✅ Models listed. Local: ${models.local.length}, Cloud: ${models.cloud.length}`);

        const anythingAgent = models.cloud.find(m => m.provider === 'anythingllm');
        if (anythingAgent) {
            console.log("✅ AnythingLLM Agent found:", anythingAgent.name);
        } else {
            console.warn("⚠️ No AnythingLLM agents found (Check URL/Key).");
        }
    } catch (e) {
        console.error("❌ LLM Service Error:", e.message);
        errors++;
    }

    console.log("\n=== DIAGNOSTIC COMPLETE ===");
    if (errors === 0) {
        console.log("RESULT: PASS (System Healthy)");
        // Allow pending connections to close properly
        setTimeout(() => process.exit(0), 100);
    } else {
        console.log(`RESULT: FAIL (${errors} errors)`);
        setTimeout(() => process.exit(1), 100);
    }
}

runTests().catch(err => {
    console.error("Test runner error:", err);
    setTimeout(() => process.exit(1), 100);
});
