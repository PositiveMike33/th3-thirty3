const fs = require('fs');
const path = require('path');

const SETTINGS_PATH = path.join(__dirname, 'data', 'settings.json');

// Default Settings
const DEFAULTS = {
    darkMode: true,
    autoCorrect: true,
    computeMode: 'cloud', // 'local' | 'cloud'
    reflectionMode: 'think', // 'rapide' | 'think' | 'ultra'
    socials: {
        facebook: false,
        instagram: false,
        x: false,
        telegram: false
    },
    apiKeys: {

        openai: "",
        anthropic: "",
        perplexity: "",
        gemini: "",
        anythingllm_url: "",
        anythingllm_key: "J7SYKN6-9P4M3SG-GY35K69-B8NVZ9M",
        extension_url: "http://localhost:63436/api",
        extension_key: "brx-AET5FA5-HYZM8FQ-KDTKC5V-MDG3WM8"
    }
};

class SettingsService {
    constructor() {
        this.ensureDataDir();
        if (!fs.existsSync(SETTINGS_PATH)) {
            console.log("[SETTINGS] Initializing default settings file.");
            this.saveSettings(DEFAULTS);
        }
    }

    ensureDataDir() {
        const dataDir = path.join(__dirname, 'data');
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
        }
    }

    getSettings() {
        try {
            if (!fs.existsSync(SETTINGS_PATH)) {
                return DEFAULTS;
            }
            const data = fs.readFileSync(SETTINGS_PATH, 'utf8');
            const parsed = JSON.parse(data);

            // Deep merge with defaults to ensure all fields exist
            return {
                ...DEFAULTS,
                ...parsed,
                socials: { ...DEFAULTS.socials, ...(parsed.socials || {}) },
                apiKeys: { ...DEFAULTS.apiKeys, ...(parsed.apiKeys || {}) }
            };
        } catch (error) {
            console.error("[SETTINGS] Error reading settings:", error);
            return DEFAULTS;
        }
    }

    saveSettings(newSettings) {
        try {
            const current = this.getSettings();

            // Merge carefully
            const updated = {
                ...current,
                ...newSettings,
                socials: { ...current.socials, ...(newSettings.socials || {}) },
                apiKeys: { ...current.apiKeys, ...(newSettings.apiKeys || {}) }
            };

            fs.writeFileSync(SETTINGS_PATH, JSON.stringify(updated, null, 2));
            console.log("[SETTINGS] Settings saved successfully.");
            return updated;
        } catch (error) {
            console.error("[SETTINGS] Error saving settings:", error);
            throw error;
        }
    }
}

module.exports = new SettingsService();
