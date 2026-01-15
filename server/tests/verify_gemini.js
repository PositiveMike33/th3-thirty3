require('dotenv').config();
const { GoogleGenerativeAI } = require('@google/generative-ai');
const settingsService = require('./settings_service');

async function verify() {
    console.log("--- Verifying Gemini API Keys ---");

    // 1. Check Settings Key
    const settings = settingsService.getSettings();
    const settingsKey = settings.apiKeys.gemini;
    console.log(`Settings Key ends with: ...${settingsKey ? settingsKey.slice(-4) : 'NONE'}`);
    await testKey(settingsKey, "Settings");

    // 2. Check Env Key
    const envKey = process.env.GEMINI_API_KEY;
    console.log(`Env Key ends with: ...${envKey ? envKey.slice(-4) : 'NONE'}`);
    if (envKey && envKey !== settingsKey) {
        await testKey(envKey, "Env");
    } else if (envKey === settingsKey) {
        console.log("Env Key is same as Settings Key.");
    }
}

async function testKey(key, source) {
    if (!key) {
        console.log(`[${source}] No key found.`);
        return;
    }
    try {
        const genAI = new GoogleGenerativeAI(key);
        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
        console.log(`[${source}] Testing gemini-1.5-flash...`);
        const result = await model.generateContent("Test");
        const response = await result.response;
        console.log(`[${source}] ✅ Success! Response: ${response.text()}`);
    } catch (error) {
        console.log(`[${source}] ❌ Failed: ${error.message}`);
    }
}

verify();
