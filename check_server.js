/**
 * CHECK SERVER STATUS
 */

async function checkServer() {
    console.log("\n🔍 Checking Th3 Thirty3 Server Status...\n");

    try {
        // Check if server is running
        const response = await fetch('http://localhost:3000/health');
        
        if (response.ok) {
            console.log("✅ Server is RUNNING");
            console.log(`   Status: ${response.status}`);
            console.log(`   URL: http://localhost:3000`);
            console.log(`   Frontend: http://localhost:5173`);
        } else {
            console.log(`⚠️  Server responded with: ${response.status}`);
        }

        // Test embedding service if available
        try {
            const EmbeddingService = require('./server/embedding_service');
            const embSvc = new EmbeddingService();
            
            console.log("\n🧪 Testing Hybrid Embedding System...");
            const start = Date.now();
            await embSvc.embed("Quick server startup test", 'auto');
            const duration = Date.now() - start;
            
            console.log(`✅ Embeddings working! (${duration}ms)`);
            
            const stats = embSvc.getStats();
            console.log(`   Provider: ${stats.gemini_success > 0 ? 'Gemini ☁️' : 'Ollama 🏠'}`);
            
        } catch (e) {
            console.log(`⚠️  Embedding test skipped: ${e.message}`);
        }

        console.log("\n" + "=".repeat(50));
        console.log("🎉 Th3 Thirty3 is OPERATIONAL!");
        console.log("=".repeat(50));
        console.log("\n📱 Open http://localhost:5173 in your browser\n");

    } catch (error) {
        console.log("❌ Server is NOT running");
        console.log(`   Error: ${error.message}`);
        console.log("\n💡 Try running: .\\start_th3_thirty3.bat\n");
    }
}

checkServer();
