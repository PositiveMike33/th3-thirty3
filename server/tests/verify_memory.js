const { Ollama } = require('../node_modules/ollama');

async function verifyMemory() {
    console.log("[TEST] Verifying Memory Service Dependencies...");
    const ollama = new Ollama();

    // 1. Check Connection
    try {
        await ollama.list();
        console.log("[TEST] Ollama Connection: OK");
    } catch (e) {
        console.error("[TEST] Ollama Connection: FAILED - Is Ollama running?");
        process.exit(1);
    }

    // 2. Check Embedding Model
    try {
        console.log("[TEST] Generating Test Embedding...");
        const response = await ollama.embeddings({
            model: 'nomic-embed-text',
            prompt: 'verification',
        });
        if (response.embedding && response.embedding.length > 0) {
            console.log(`[TEST] Embedding Generation: OK (Length: ${response.embedding.length})`);
            process.exit(0);
        } else {
            console.error("[TEST] Embedding Generation: FAILED (Empty response)");
            process.exit(1);
        }
    } catch (e) {
        console.error(`[TEST] Embedding Generation: FAILED - ${e.message}`);
        if (e.message.includes('not found')) {
            console.error("[TEST] HINT: Run 'ollama pull nomic-embed-text'");
        }
        process.exit(1);
    }
}

verifyMemory();
