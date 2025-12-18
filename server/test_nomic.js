
const { Ollama } = require('ollama');

async function testEmbedding() {
    console.log("Testing nomic-embed-text...");
    const ollama = new Ollama();
    try {
        const response = await ollama.embeddings({
            model: 'nomic-embed-text',
            prompt: "Why did the chicken cross the road?"
        });
        console.log("Success! Embedding length:", response.embedding.length);
    } catch (e) {
        console.error("Embedding failed:", e.message);
        process.exit(1);
    }
}

testEmbedding();
