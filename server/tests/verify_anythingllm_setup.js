
require('dotenv').config({ path: '../.env' });
const AnythingLLMWrapper = require('../anythingllm_wrapper');

async function testConnection() {
    console.log("--- STARTING ANYTHINGLLM CONNECTION TEST ---");
    console.log("URL:", process.env.ANYTHING_LLM_URL);
    console.log("KEY:", process.env.ANYTHING_LLM_KEY ? "Present" : "Missing");

    const wrapper = new AnythingLLMWrapper();

    try {
        console.log("1. Initializing wrapper (fetching workspaces)...");
        await wrapper.initialize();
        console.log("✅ Initialization successful!");
        console.log("   Workspace Slug:", wrapper.workspaceSlug);

        console.log("2. Sending Test Message...");
        const response = await wrapper.chat("Hello, are you online and ready for map analysis?", "chat");
        console.log("✅ Chat successful!");
        console.log("   Response:", response);

        if (response.includes("OFFLINE MODE")) {
            console.warn("⚠️ WARNING: System fell back to Offline Mode. AnythingLLM might be unreachable or embedding failed.");
        } else {
            console.log("🎉 SUCCESS: Fully connected to AnythingLLM!");
        }

    } catch (error) {
        console.error("❌ TEST FAILED:", error.message);
        if (error.cause) console.error("   Cause:", error.cause);
    }
    console.log("--- END TEST ---");
}

testConnection();
