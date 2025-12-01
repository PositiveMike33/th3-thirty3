require('dotenv').config();
const { GoogleGenerativeAI } = require('@google/generative-ai');

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

async function listModels() {
    try {
        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
        // There isn't a direct listModels on the client instance in some versions, 
        // but let's try to just generate content with a known model or catch the error.

        // Actually, for listing models we might need to use the API directly or check documentation.
        // But let's try a simple generation to see if it works at all.
        console.log("Testing generation with gemini-pro...");
        const result = await model.generateContent("Hello");
        const response = await result.response;
        console.log("Response:", response.text());
    } catch (error) {
        console.error("Error:", error);
    }
}

listModels();
