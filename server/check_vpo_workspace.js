/**
 * Helper script to check AnythingLLM workspaces
 * Use this to verify workspace configuration for VPO module
 */

require('dotenv').config();

async function checkWorkspaces() {
    const baseUrl = process.env.ANYTHING_LLM_URL;
    const apiKey = process.env.ANYTHING_LLM_KEY;

    if (!baseUrl || !apiKey) {
        console.error('❌ ANYTHING_LLM_URL or ANYTHING_LLM_KEY not set in .env');
        process.exit(1);
    }

    console.log('🔍 Checking AnythingLLM workspaces...\n');
    console.log(`URL: ${baseUrl}`);
    console.log(`API Key: ${apiKey.substring(0, 10)}...\n`);

    try {
        const response = await fetch(`${baseUrl}/workspaces`, {
            headers: { 'Authorization': `Bearer ${apiKey}` }
        });

        if (!response.ok) {
            console.error(`❌ Failed to fetch workspaces: ${response.status}`);
            const text = await response.text();
            console.error(text);
            process.exit(1);
        }

        const data = await response.json();
        
        if (!data.workspaces || data.workspaces.length === 0) {
            console.log('⚠️  No workspaces found in AnythingLLM\n');
            console.log('📝 To create the VPO workspace:');
            console.log('1. Open AnythingLLM UI (http://localhost:3001)');
            console.log('2. Create a new workspace');
            console.log('3. Name: "Expert Technique Senior & Auditeur VPO (AB InBev)"');
            console.log('4. Configure a vision model (GPT-4 Vision or Claude 3)');
            console.log('5. Add VPO system prompt from server/config/prompts.js\n');
            process.exit(0);
        }

        console.log(`✅ Found ${data.workspaces.length} workspace(s):\n`);
        
        const vpoWorkspace = 'expert-technique-senior-auditeur-vpo-ab-inbev';
        let vpoFound = false;

        data.workspaces.forEach((ws, index) => {
            const isVPO = ws.slug === vpoWorkspace;
            const marker = isVPO ? '🎯' : '  ';
            
            console.log(`${marker} ${index + 1}. ${ws.name}`);
            console.log(`   Slug: ${ws.slug}`);
            console.log(`   ID: ${ws.id}`);
            
            if (isVPO) {
                console.log('   ✅ THIS IS THE VPO WORKSPACE');
                vpoFound = true;
            }
            console.log('');
        });

        if (!vpoFound) {
            console.log('⚠️  VPO workspace NOT found!\n');
            console.log('📝 Expected slug: expert-technique-senior-auditeur-vpo-ab-inbev\n');
            console.log('To create it:');
            console.log('1. Open AnythingLLM UI (http://localhost:3001)');
            console.log('2. Create a new workspace');
            console.log('3. Name: "Expert Technique Senior & Auditeur VPO (AB InBev)"');
            console.log('   (The slug will be generated automatically)');
            console.log('4. Configure a vision model (GPT-4 Vision or Claude 3)');
            console.log('5. Add VPO system prompt from server/config/prompts.js\n');
        } else {
            console.log('✅ VPO workspace is correctly configured!\n');
            console.log('You can now use the incident analysis module.');
        }

    } catch (error) {
        console.error('❌ Error:', error.message);
        process.exit(1);
    }
}

checkWorkspaces();
