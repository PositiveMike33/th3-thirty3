const settingsService = require('./settings_service');

async function debug() {
    console.log("--- DEBUG ANYTHINGLLM CHAT ---");

    const settings = settingsService.getSettings();
    const baseUrl = settings.apiKeys.anythingllm_url;
    const key = settings.apiKeys.anythingllm_key;

    console.log("URL:", baseUrl);

    try {
        // 1. Get Slug
        console.log("Fetching workspaces...");
        const res = await fetch(`${baseUrl}/workspaces`, {
            headers: { 'Authorization': `Bearer ${key}` }
        });
        const data = await res.json();
        const slug = data.workspaces.find(w => w.slug.includes('thirty3'))?.slug || data.workspaces[0].slug;
        console.log("Slug:", slug);

        // 2. Send Chat
        const chatUrl = `${baseUrl}/workspace/${slug}/chat`;
        console.log(`Sending chat to ${chatUrl}...`);
        
        const chatRes = await fetch(chatUrl, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${key}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                message: "Hello from debug script",
                mode: 'chat'
            })
        });

        console.log("Status:", chatRes.status);
        if (!chatRes.ok) {
            console.log("Error Body:", await chatRes.text());
        } else {
            const chatData = await chatRes.json();
            console.log("Response:", chatData);
        }

    } catch (e) {
        console.log(`FETCH FAILED: ${e.message}`);
        if (e.cause) console.log("Cause:", e.cause);
    }
}

debug();
