const fs = require('fs');
const path = require('path');

const settingsPath = path.join(__dirname, 'data', 'settings.json');

try {
    let settings = {};
    if (fs.existsSync(settingsPath)) {
        const raw = fs.readFileSync(settingsPath, 'utf8');
        try {
            settings = JSON.parse(raw);
        } catch (e) {
            console.error("Failed to parse existing settings:", e);
            // backup broken file?
        }
    }

    if (!settings.apiKeys) settings.apiKeys = {};

    // Set the key
    settings.apiKeys.gemini = "AIzaSyCSfTI0Fsc7O4z1251Ey6UeW-bykzDHAF8";
    settings.apiKeys.google = "AIzaSyCSfTI0Fsc7O4z1251Ey6UeW-bykzDHAF8"; // Redundancy just in case

    // Ensure data dir exists
    const dataDir = path.dirname(settingsPath);
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

    fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2));
    console.log("Successfully updated Gemini API Key in " + settingsPath);

} catch (error) {
    console.error("Error updating settings:", error);
    process.exit(1);
}
