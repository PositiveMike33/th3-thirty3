const settingsService = require('./settings_service');
require('dotenv').config();

console.log("Checking API Keys Configuration...");
const settings = settingsService.getSettings();

console.log("\n[1] Environment Variables:");
console.log("GEMINI_API_KEY:", process.env.GEMINI_API_KEY ? "SET (Matches pattern)" : "NOT SET");

console.log("\n[2] Settings File (settings.json):");
if (settings.apiKeys) {
    console.log("settings.apiKeys.gemini:", settings.apiKeys.gemini ? "SET" : "MISSING");
    console.log("settings.apiKeys.google:", settings.apiKeys.google ? "SET" : "MISSING");
} else {
    console.log("settings.apiKeys is UNDEFINED");
}

console.log("\n[3] LLM Service Logic Simulation:");
const geminiKey = process.env.GEMINI_API_KEY || settings.apiKeys?.gemini;
if (geminiKey) {
    console.log("✅ Success: Gemini Key found. Models should be visible.");
} else {
    console.log("❌ FAILURE: No Gemini Key found in Env or Settings. Models will be hidden.");
}
