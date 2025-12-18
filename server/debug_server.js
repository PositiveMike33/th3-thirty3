require('dotenv').config();
const { getPatterns } = require('./fabric_service');
const LLMService = require('./llm_service');

async function debug() {
    console.log("--- DEBUGGING FABRIC ---");
    try {
        const patterns = getPatterns();
        console.log(`Patterns found: ${patterns.length}`);
        if (patterns.length > 0) {
            console.log("First 5 patterns:", patterns.slice(0, 5));
        } else {
            console.log("No patterns found. Checking paths...");
            const fs = require('fs');
            const path = require('path');
            const p1 = path.join(__dirname, 'fabric', 'patterns');
            const p2 = path.join(__dirname, 'fabric', 'data', 'patterns');
            console.log(`Path 1 (${p1}) exists: ${fs.existsSync(p1)}`);
            console.log(`Path 2 (${p2}) exists: ${fs.existsSync(p2)}`);
        }
    } catch (e) {
        console.error("Fabric Error:", e);
    }

    console.log("\n--- DEBUGGING LLM SERVICE ---");
    try {
        const llmService = new LLMService();
        console.log("Listing models...");
        const models = await llmService.listModels();
        console.log("Local Models:", models.local);
        console.log("Cloud Models:", models.cloud.length);
        if (models.cloud.length > 0) {
            console.log("First 3 Cloud Models:", models.cloud.slice(0, 3));
        }
    } catch (e) {
        console.error("LLM Service Error:", e);
    }
}

debug();
