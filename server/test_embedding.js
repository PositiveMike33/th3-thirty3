const { Ollama } = require('ollama');

async function testEmbedding() {
    const ollama = new Ollama();
    console.log("Testing Ollama Embeddings...");
    try {
        const response = await ollama.embeddings({
            model: 'nomic-embed-text',
            prompt: 'Hello world',
        });
        console.log("Success! Embedding length:", response.embedding.length);
    } catch (error) {
        console.error("Error:", error);
    }
}

testEmbedding();
