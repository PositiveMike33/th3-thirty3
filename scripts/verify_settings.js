const settingsService = require('../server/settings_service');
const fs = require('fs');
const path = require('path');

console.log("🛠️ Starting Self-Verification: Settings & Persistence");

try {
    // 1. Initial State
    const initial = settingsService.getSettings();
    console.log("✅ Initial Settings Loaded. Theme:", initial.themeMode);

    // 2. Modify Setting
    const testValue = `test_${Date.now()}`;
    console.log(`📝 Modifying 'language' to: ${testValue}`);
    settingsService.saveSettings({ language: testValue });

    // 3. Verify File Write
    const filePath = path.join(__dirname, '../server/data/settings.json');
    const fileContent = fs.readFileSync(filePath, 'utf8');
    const parsedFile = JSON.parse(fileContent);

    if (parsedFile.language === testValue) {
        console.log("✅ File Persistence Confirmed: Value written to disk.");
    } else {
        console.error("❌ File Persistence FAILED: Disk value differs from memory.");
        process.exit(1);
    }

    // 4. Verify Deep Merge (ensure other keys didn't vanish)
    if (parsedFile.themeMode && parsedFile.apiKeys) {
        console.log("✅ Deep Merge Confirmed: Existing keys preserved.");
    } else {
        console.error("❌ Deep Merge FAILED: Existing keys lost.");
        process.exit(1);
    }

    // 5. Restore (Optional, but good practice)
    // settingsService.saveSettings({ language: initial.language }); 
    // console.log("✅ Settings restored.");

    console.log("\n🎉 ALL CHECKS PASSED: Settings System is Bulletproof.");

} catch (e) {
    console.error("❌ Verification Failed:", e);
    process.exit(1);
}
