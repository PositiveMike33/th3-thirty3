const fs = require('fs');
const path = require('path');

const SETTINGS_PATH = path.join(__dirname, 'data', 'settings.json');

// Default Settings
const DEFAULTS = {
    darkMode: true,
    autoCorrect: true,
    computeMode: 'local', // 'local' | 'cloud'
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
        anythingllm_url: "",
        anythingllm_key: ""
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
