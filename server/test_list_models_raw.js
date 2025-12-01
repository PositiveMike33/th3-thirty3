const https = require('https');
require('dotenv').config();

const apiKey = process.env.GEMINI_API_KEY;
const url = `https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`;

https.get(url, (res) => {
    let data = '';
    res.on('data', (chunk) => {
        data += chunk;
    });
    res.on('end', () => {
        try {
            const json = JSON.parse(data);
            if (json.error) {
                console.error("API Error:", json.error);
            } else {
                console.log("Available Models:");
                if (json.models) {
                    const validModels = json.models.filter(m => m.supportedGenerationMethods.includes('generateContent'));
                    console.log(`Found ${validModels.length} models with generateContent:`);
                    validModels.forEach(m => {
                        console.log(`- ${m.name}`);
                    });
                } else {
                    console.log("No models found in response.");
                }
            }
        } catch (e) {
            console.error("Parse Error:", e);
            console.log("Raw Data:", data);
        }
    });
}).on('error', (err) => {
    console.error("Request Error:", err);
});
