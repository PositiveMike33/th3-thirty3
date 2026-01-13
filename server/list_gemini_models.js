const https = require('https');
const settingsService = require('./settings_service');

const apiKey = settingsService.getSettings().apiKeys.gemini;

https.get(`https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`, (res) => {
    let data = '';
    res.on('data', (chunk) => { data += chunk; });
    res.on('end', () => {
        try {
            const json = JSON.parse(data);
            if (json.models) {
                console.log("AVAILABLE MODELS:");
                json.models.forEach(m => {
                    if (m.supportedGenerationMethods && m.supportedGenerationMethods.includes('generateContent')) {
                        console.log(m.name.replace('models/', ''));
                    }
                });
            } else {
                console.log("No models found or error:", JSON.stringify(json, null, 2));
            }
        } catch (e) {
            console.error(e.message);
            console.log(data);
        }
    });
}).on('error', (e) => {
    console.error(e);
});
