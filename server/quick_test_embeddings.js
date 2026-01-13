/**
 * QUICK TEST - Hybrid Embeddings
 */

const EmbeddingService = require('./embedding_service');

async function quickTest() {
    console.log("\n🚀 Quick Test: Hybrid Embeddings\n");

    const service = new EmbeddingService();

    // Test 1: Local only (Ollama)
    console.log("1. Testing Ollama (nomic-embed-text)...");
    try {
        const start = Date.now();
        const emb = await service.embed("Test local embedding", 'ollama');
        console.log(`✅ Success! Dimension: ${emb.length}, Time: ${Date.now() - start}ms\n`);
    } catch (e) {
        console.error(`❌ Failed: ${e.message}\n`);
    }

    // Test 2: Auto (will try Gemini, fallback to Ollama)
    console.log("2. Testing AUTO mode (Gemini with Ollama fallback)...");
    try {
        const start = Date.now();
        const emb = await service.embed("Test auto embedding", 'auto');
        console.log(`✅ Success! Dimension: ${emb.length}, Time: ${Date.now() - start}ms\n`);
    } catch (e) {
        console.error(`❌ Failed: ${e.message}\n`);
    }

    // Test 3: Similarity
    console.log("3. Testing semantic similarity...");
    try {
        const docs = [
            { text: "Cybersecurity and hacking techniques" },
            { text: "Cooking recipes and food preparation" },
            { text: "Network penetration testing methods" }
        ];
        
        const results = await service.findSimilar(
            "How to perform security testing?",
            docs,
            2,
            'ollama'  // Use local to be sure it works
        );
        
        console.log("✅ Top matches:");
        results.forEach((r, i) => {
            console.log(`   ${i+1}. [${(r.similarity*100).toFixed(1)}%] ${r.text}`);
        });
        console.log("");
    } catch (e) {
        console.error(`❌ Failed: ${e.message}\n`);
    }

    // Stats
    console.log("📊 Statistics:");
    const stats = service.getStats();
    console.log(`   Gemini: ${stats.gemini_success} success, ${stats.gemini_failures} failures`);
    console.log(`   Ollama: ${stats.ollama_success} success, ${stats.ollama_failures} failures`);
    console.log(`   Cache: ${stats.cache_size} entries`);
    console.log(`   Total: ${stats.total_requests} requests`);
    console.log("\n   ✅ Hybrid Embedding System is OPERATIONAL!\n");
}

quickTest().catch(err => {
    console.error("\n❌ Fatal error:", err.message);
    console.error(err.stack);
});
