const { Ollama } = require('ollama');

async function testEmbedding() {
    const ollama = new Ollama();
    console.log("Testing embedding generation with 'nomic-embed-text'...");
    try {
        const response = await ollama.embeddings({
            model: 'nomic-embed-text',
            prompt: 'This is a test sentence.',
        });
        console.log("Success! Embedding length:", response.embedding.length);
    } catch (error) {
        console.error("Error generating embedding:", error);

        // Try listing models to see what's available
        try {
            const list = await ollama.list();
            console.log("\nAvailable models:");
            list.models.forEach(m => console.log(`- ${m.name}`));
        } catch (e) {
            console.error("Could not list models:", e);
        }
    }
}

testEmbedding();
