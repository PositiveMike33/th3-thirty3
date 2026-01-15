/**
 * Test Gemini connection using the same flow as the server
 */
const settingsService = require('./settings_service');
const { GoogleGenerativeAI } = require('@google/generative-ai');

async function testGeminiFromSettings() {
    const settings = settingsService.getSettings();
    console.log("Settings loaded:", {
        hasGeminiKey: !!settings.apiKeys?.gemini,
        keyPrefix: settings.apiKeys?.gemini?.substring(0, 10) + "..."
    });

    const geminiKey = process.env.GEMINI_API_KEY || settings.apiKeys?.gemini;

    if (!geminiKey) {
        console.error("❌ No Gemini API key found!");
        return;
    }

    console.log("✅ Gemini API Key found");

    const models = [
        'gemini-3-pro-preview',
        'gemini-3-flash-preview',
        'gemini-3-pro-image-preview'
    ];

    for (const modelName of models) {
        console.log(`\n--- Testing ${modelName} ---`);
        try {
            const genAI = new GoogleGenerativeAI(geminiKey);
            const model = genAI.getGenerativeModel({ model: modelName });

            const result = await model.generateContent("Say 'Hello' in French");
            const response = result.response.text();
            console.log(`✅ ${modelName}: ${response.substring(0, 50)}...`);
        } catch (error) {
            console.error(`❌ ${modelName}: ${error.message}`);
        }
    }
}

testGeminiFromSettings();
