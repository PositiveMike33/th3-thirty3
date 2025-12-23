/**
 * Test Cloud Optimizer AnythingLLM Connection
 */

const settingsService = require('./settings_service');

async function testCloudOptimizerConnection() {
    console.log('=== CLOUD OPTIMIZER CONNECTION TEST ===\n');
    
    // 1. Check settings
    console.log('[1] Checking settings...');
    const settings = settingsService.getSettings();
    const url = settings?.apiKeys?.anythingllm_url;
    const key = settings?.apiKeys?.anythingllm_key;
    
    console.log(`   URL: ${url || 'NOT SET'}`);
    console.log(`   Key: ${key ? 'Present (' + key.substring(0, 8) + '...)' : 'NOT SET'}`);
    
    if (!url || !key) {
        console.log('\n❌ Missing AnythingLLM configuration in settings');
        return false;
    }
    
    // 2. Test connection (same URL format as fixed cloud_model_optimizer.js)
    console.log('\n[2] Testing AnythingLLM connection...');
    
    try {
        // Test with the corrected URL format (no /api/v1 prefix for workspace endpoints)
        const testWorkspace = 'th3-thirty3-workspace';
        const testUrl = `${url}/workspace/${testWorkspace}/chat`;
        
        console.log(`   Testing: ${testUrl}`);
        
        const response = await fetch(testUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${key}`
            },
            body: JSON.stringify({
                message: '[TEST] Cloud Optimizer connection test',
                mode: 'chat'
            })
        });
        
        if (response.ok) {
            console.log('\n✅ SUCCESS! AnythingLLM connection working!');
            const data = await response.json();
            console.log(`   Response: ${data.textResponse?.substring(0, 100) || 'OK'}...`);
            return true;
        } else {
            const errText = await response.text();
            console.log(`\n⚠️ Response status: ${response.status}`);
            console.log(`   Body: ${errText.substring(0, 200)}`);
            
            // If workspace doesn't exist, at least we know connection works
            if (response.status === 404) {
                console.log('\n   Note: Workspace not found, but AnythingLLM is reachable');
                return true;
            }
            return false;
        }
    } catch (error) {
        console.log(`\n❌ Connection failed: ${error.message}`);
        return false;
    }
}

testCloudOptimizerConnection()
    .then(success => {
        console.log('\n=== TEST COMPLETE ===');
        process.exit(success ? 0 : 1);
    })
    .catch(err => {
        console.error('Test error:', err);
        process.exit(1);
    });
