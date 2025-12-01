require('dotenv').config();
const { GoogleGenerativeAI } = require("@google/generative-ai");

async function listModels() {
    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    try {
        // Access the model listing via the API directly if SDK doesn't expose it easily,
        // OR just try a few known variants.

        // Actually, let's try to use the model listing if possible.
        // In newer SDKs:
        // const models = await genAI.listModels(); 
        // But let's try to just hit the endpoint via fetch if SDK fails, or try variants.

        console.log("Trying variants...");
        const variants = ["gemini-1.5-flash", "gemini-1.5-flash-001", "gemini-1.5-pro", "gemini-pro"];

        for (const m of variants) {
            try {
                console.log(`Testing ${m}...`);
                const model = genAI.getGenerativeModel({ model: m });
                const result = await model.generateContent("Hi");
                console.log(`SUCCESS: ${m}`);
                return; // Found one!
            } catch (e) {
                console.log(`FAILED: ${m} - ${e.message.split('\n')[0]}`);
            }
        }

    } catch (error) {
        console.error("Error:", error);
    }
}

listModels();
