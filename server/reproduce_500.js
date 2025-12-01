const settings = require('./data/settings.json');
const { anythingllm_url, anythingllm_key } = settings.apiKeys;

async function testChat() {
    console.log("Testing AnythingLLM Chat Generation...");
    console.log("URL:", anythingllm_url);

    const PERSONA = require('./persona');
    const largeContext = "Some large context ".repeat(100); // Simulate context injection

    const payload = {
        model: "th3-thirty3-workspace",
        messages: [
            { role: "system", content: PERSONA + "\n\n" + largeContext },
            { role: "user", content: "Hello, are you working with this large context?" }
        ]
    };

    try {
        const response = await fetch(`${anythingllm_url}/openai/chat/completions`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${anythingllm_key}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            const data = await response.json();
            console.log("SUCCESS:", data);
        } else {
            console.error("FAILURE:", response.status, response.statusText);
            const text = await response.text();
            console.error("Response Body:", text);
        }
    } catch (error) {
        console.error("ERROR:", error.message);
    }
}

testChat();
