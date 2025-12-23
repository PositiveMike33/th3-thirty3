// const fetch = require('node-fetch'); // Using native fetch

async function testAnythingLLM() {
    // Load settings to get keys
    const fs = require('fs');
    const path = require('path');
    const settingsPath = path.join(__dirname, 'data', 'settings.json');

    if (!fs.existsSync(settingsPath)) {
        console.error("Settings file not found!");
        return;
    }

    const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
    const { anythingllm_url, anythingllm_key } = settings.apiKeys || {};

    console.log("Testing AnythingLLM Connection...");
    console.log("URL:", anythingllm_url);
    console.log("Key:", anythingllm_key ? "Present" : "Missing");

    if (!anythingllm_url || !anythingllm_key) {
        console.error("Missing URL or Key in settings.");
        return;
    }

    try {
        const response = await fetch(`${anythingllm_url}/openai/models`, {
            headers: { 'Authorization': `Bearer ${anythingllm_key}` }
        });

        if (response.ok) {
            const data = await response.json();
            console.log("SUCCESS! Connection established.");
            console.log("Models found:", data.data.map(m => m.id));
        } else {
            console.error("FAILURE: Server responded with status", response.status);
            const text = await response.text();
            console.error("Response:", text);
        }
    } catch (error) {
        console.error("ERROR: Failed to connect.", error.message);
    }
}

testAnythingLLM();
