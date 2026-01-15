
const LLMService = require('../llm_service');
const settingsService = require('../settings_service');
require('dotenv').config();

async function testHackerGPT() {
    console.log("-----------------------------------------");
    console.log("🧪 TESTING HACKERGPT with GEMINI 3");
    console.log("-----------------------------------------");

    const llm = new LLMService();
    // Mock socket service to avoid errors
    llm.setSocketService({
        emitAgentStatus: (msg) => console.log(`[SOCKET] ${msg}`),
        emitAgentStart: () => { },
        emitAgentEnd: () => { }
    });

    try {
        const prompt = "Analyze the risks of using default passwords on IoT devices. Be brief.";
        console.log(`Prompt: ${prompt}`);

        const response = await llm.generateHackerGPTResponse(prompt, 'gemini-3-flash-preview');

        console.log("\n✅ RESPONSE RECEIVED:");
        console.log("-----------------------------------------");
        console.log(response);
        console.log("-----------------------------------------");

        if (!response || response.trim().length === 0) {
            console.error("❌ FAILURE: Empty response received!");
            process.exit(1);
        } else {
            console.log("✅ SUCCESS: Non-empty response.");
            process.exit(0);
        }

    } catch (error) {
        console.error("\n❌ ERROR:", error);
        process.exit(1);
    }
}

testHackerGPT();
