/**
 * TEST HYBRID EMBEDDING SYSTEM
 * 
 * Tests both Gemini and nomic-embed-text embeddings with automatic fallback
 */

const EmbeddingService = require('./embedding_service');

async function testEmbeddings() {
    console.log("🧪 TESTING HYBRID EMBEDDING SYSTEM\n");
    console.log("=".repeat(60));

    const embeddingService = new EmbeddingService();

    // Test 1: Single text embedding with auto fallback
    console.log("\n1️⃣ Testing AUTO mode (tries Gemini, falls back to Ollama)");
    try {
        const start = Date.now();
        const embedding = await embeddingService.embed("Test cybersecurity analysis", 'auto');
        const duration = Date.now() - start;
        console.log(`✅ Embedded successfully (${duration}ms)`);
        console.log(`   Dimension: ${embedding.length}`);
        console.log(`   Sample values: [${embedding.slice(0, 5).map(v => v.toFixed(4)).join(', ')}...]`);
    } catch (e) {
        console.error(`❌ Failed: ${e.message}`);
    }

    // Test 2: Force Ollama (nomic-embed-text)
    console.log("\n2️⃣ Testing OLLAMA mode (local embeddings)");
    try {
        const start = Date.now();
        const embedding = await embeddingService.embed("Test with local nomic embeddings", 'ollama');
        const duration = Date.now() - start;
        console.log(`✅ Embedded successfully (${duration}ms)`);
        console.log(`   Dimension: ${embedding.length}`);
    } catch (e) {
        console.error(`❌ Failed: ${e.message}`);
    }

    // Test 3: Batch embeddings
    console.log("\n3️⃣ Testing batch embeddings (auto mode)");
    try {
        const texts = [
            "Phishing detection techniques",
            "Network traffic analysis",
            "Malware reverse engineering"
        ];
        const start = Date.now();
        const embeddings = await embeddingService.embed(texts, 'auto');
        const duration = Date.now() - start;
        console.log(`✅ Embedded ${embeddings.length} texts (${duration}ms)`);
        console.log(`   Avg time per text: ${(duration / embeddings.length).toFixed(2)}ms`);
    } catch (e) {
        console.error(`❌ Failed: ${e.message}`);
    }

    // Test 4: Similarity search
    console.log("\n4️⃣ Testing semantic search");
    try {
        const documents = [
            { text: "SQL injection is a code injection technique used to attack data-driven applications", metadata: { topic: "web-security" } },
            { text: "Cross-site scripting (XSS) enables attackers to inject client-side scripts into web pages", metadata: { topic: "web-security" } },
            { text: "Machine learning models can detect anomalies in network traffic patterns", metadata: { topic: "ml-security" } },
            { text: "Zero-day exploits target unknown vulnerabilities in software", metadata: { topic: "exploits" } },
            { text: "Encrypted communications protect data confidentiality during transmission", metadata: { topic: "encryption" } }
        ];

        const query = "How to prevent web application attacks?";
        const start = Date.now();
        const results = await embeddingService.findSimilar(query, documents, 3, 'auto');
        const duration = Date.now() - start;

        console.log(`✅ Search completed (${duration}ms)`);
        console.log(`\n   Query: "${query}"`);
        console.log(`   Top results:`);
        results.forEach((doc, idx) => {
            console.log(`   ${idx + 1}. [${(doc.similarity * 100).toFixed(1)}%] ${doc.text.substring(0, 60)}...`);
        });
    } catch (e) {
        console.error(`❌ Failed: ${e.message}`);
    }

    // Test 5: Cache performance
    console.log("\n5️⃣ Testing cache performance");
    try {
        const text = "Test cache performance with repeated queries";
        
        const start1 = Date.now();
        await embeddingService.embed(text, 'auto');
        const duration1 = Date.now() - start1;
        
        const start2 = Date.now();
        await embeddingService.embed(text, 'auto');
        const duration2 = Date.now() - start2;
        
        console.log(`✅ First call: ${duration1}ms`);
        console.log(`✅ Cached call: ${duration2}ms`);
        console.log(`   Speedup: ${(duration1 / duration2).toFixed(1)}x faster`);
    } catch (e) {
        console.error(`❌ Failed: ${e.message}`);
    }

    // Final Stats
    console.log("\n" + "=".repeat(60));
    console.log("SUMMARY");
    console.log("=".repeat(60));
    const stats = embeddingService.getStats();
    console.log(`Gemini Success: ${stats.gemini_success}`);
    console.log(`Gemini Failures: ${stats.gemini_failures}`);
    console.log(`Ollama Success: ${stats.ollama_success}`);
    console.log(`Ollama Failures: ${stats.ollama_failures}`);
    console.log(`Cache Size: ${stats.cache_size}`);
    console.log(`Total Requests: ${stats.total_requests}`);
    console.log(`Gemini Available: ${stats.gemini_available ? '✅' : '❌'}`);
    console.log(`Fallback Rate: ${(stats.fallback_rate * 100).toFixed(1)}%`);
    console.log("=".repeat(60));
}

testEmbeddings().catch(console.error);
