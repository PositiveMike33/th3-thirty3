/**
 * FIX ANYTHINGLLM EMBEDDINGS
 * 
 * This script fixes the "Gemini Failed to embed" error by:
 * 1. Verifying nomic-embed-text is installed in Ollama
 * 2. Updating AnythingLLM workspace to use local embeddings
 * 3. Testing the connection
 */

const settingsService = require('./settings_service');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

async function fixEmbeddings() {
    console.log("\n🔧 FIXING ANYTHINGLLM EMBEDDINGS\n");

    // Step 1: Check if nomic-embed-text is installed
    console.log("1️⃣ Checking Ollama models...");
    try {
        const { stdout } = await execAsync('ollama list');
        console.log(stdout);
        
        if (!stdout.includes('nomic-embed-text')) {
            console.log("❌ nomic-embed-text NOT found!");
            console.log("\n📥 Installing nomic-embed-text (this may take a few minutes)...");
            
            const pullProcess = exec('ollama pull nomic-embed-text');
            pullProcess.stdout.on('data', (data) => process.stdout.write(data));
            pullProcess.stderr.on('data', (data) => process.stderr.write(data));
            
            await new Promise((resolve, reject) => {
                pullProcess.on('close', (code) => {
                    if (code === 0) {
                        console.log("✅ nomic-embed-text installed successfully!");
                        resolve();
                    } else {
                        reject(new Error(`Pull failed with code ${code}`));
                    }
                });
            });
        } else {
            console.log("✅ nomic-embed-text is already installed");
        }
    } catch (e) {
        console.error("❌ Failed to check/install Ollama models:", e.message);
        console.log("\n⚠️ Please manually run: ollama pull nomic-embed-text");
        return;
    }

    // Step 2: Get AnythingLLM settings
    console.log("\n2️⃣ Connecting to AnythingLLM...");
    const settings = settingsService.getSettings();
    const baseUrl = settings.apiKeys.anythingllm_url;
    const key = settings.apiKeys.anythingllm_key;

    if (!baseUrl || !key) {
        console.error("❌ AnythingLLM URL or API Key not configured!");
        return;
    }

    console.log(`   URL: ${baseUrl}`);

    try {
        // Step 3: Get workspace
        const wsRes = await fetch(`${baseUrl}/workspaces`, {
            headers: { 'Authorization': `Bearer ${key}` }
        });
        
        if (!wsRes.ok) {
            throw new Error(`Failed to fetch workspaces: ${wsRes.status}`);
        }

        const wsData = await wsRes.json();
        const workspace = wsData.workspaces.find(w => w.slug.includes('thirty3')) || wsData.workspaces[0];
        
        console.log(`✅ Found workspace: ${workspace.name} (${workspace.slug})`);

        // Step 4: Update workspace to use Ollama embeddings
        console.log("\n3️⃣ Updating workspace embedding configuration...");
        
        const updateRes = await fetch(`${baseUrl}/workspace/${workspace.slug}/update-embeddings`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${key}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                embeddingProvider: 'ollama',
                embeddingModel: 'nomic-embed-text',
                embeddingBasePath: 'http://localhost:11434'
            })
        });

        if (!updateRes.ok) {
            const errorText = await updateRes.text();
            console.log(`⚠️ Update response: ${updateRes.status}`);
            console.log(`   Response: ${errorText}`);
            
            // Try alternative API endpoint
            console.log("\n   Trying alternative configuration method...");
            const altUpdateRes = await fetch(`${baseUrl}/workspace/${workspace.slug}`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${key}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    embeddingPreference: {
                        provider: 'ollama',
                        model: 'nomic-embed-text'
                    }
                })
            });
            
            if (altUpdateRes.ok) {
                console.log("✅ Workspace configuration updated (alternative method)");
            }
        } else {
            console.log("✅ Workspace embedding configuration updated");
        }

        // Step 5: Test the chat
        console.log("\n4️⃣ Testing chat with new configuration...");
        const chatRes = await fetch(`${baseUrl}/workspace/${workspace.slug}/chat`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${key}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                message: "System check: embedding test",
                mode: 'chat'
            })
        });

        if (!chatRes.ok) {
            const errorBody = await chatRes.text();
            console.log(`❌ Chat test failed: ${chatRes.status}`);
            console.log(`   Error: ${errorBody}`);
            
            if (errorBody.includes("Gemini Failed to embed")) {
                console.log("\n⚠️ MANUAL ACTION REQUIRED:");
                console.log("   The workspace is still configured to use Gemini embeddings.");
                console.log("   Please open AnythingLLM UI and:");
                console.log(`   1. Go to Workspace Settings for '${workspace.name}'`);
                console.log("   2. Under 'Embedding Preference', select 'Ollama'");
                console.log("   3. Model: 'nomic-embed-text'");
                console.log("   4. Base URL: 'http://localhost:11434'");
                console.log("   5. Save changes");
            }
        } else {
            const chatData = await chatRes.json();
            console.log("✅ Chat test successful!");
            console.log(`   Response: ${chatData.textResponse?.substring(0, 100)}...`);
        }

    } catch (e) {
        console.error("\n❌ Error:", e.message);
    }

    console.log("\n" + "=".repeat(60));
    console.log("SUMMARY:");
    console.log("=".repeat(60));
    console.log("If you still see 'Gemini Failed to embed' errors:");
    console.log("1. Open AnythingLLM Desktop app");
    console.log("2. Go to Settings → Embedding Preference");
    console.log("3. Select: Provider = 'Ollama', Model = 'nomic-embed-text'");
    console.log("4. Restart AnythingLLM");
    console.log("=".repeat(60) + "\n");
}

fixEmbeddings();
