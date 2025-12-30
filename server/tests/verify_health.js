const { exec } = require('child_process');

console.log("🏥 STARTING MORNING HEALTH CHECK...");

const runScript = (scriptName) => {
    return new Promise((resolve, reject) => {
        console.log(`\n--- Running ${scriptName} ---`);
        exec(`node ${scriptName}`, (error, stdout, stderr) => {
            if (error) {
                console.error(`❌ ${scriptName} FAILED:`, error.message);
                resolve(false);
            } else {
                console.log(stdout);
                if (stderr) console.error(stderr);
                console.log(`✅ ${scriptName} PASSED`);
                resolve(true);
            }
        });
    });
};

async function checkAll() {
    // 1. Verify Settings Persistence
    const settingsOk = await runScript('verify_settings.js');

    // 2. Verify AnythingLLM
    const anythingOk = await runScript('test_anythingllm.js');

    console.log("\n=================================");
    console.log("SUMMARY:");
    console.log(`Settings Persistence: ${settingsOk ? "✅ OK" : "❌ FAIL"}`);
    console.log(`AnythingLLM Connect:  ${anythingOk ? "✅ OK" : "❌ FAIL"}`);
    console.log("=================================");
}

checkAll();
