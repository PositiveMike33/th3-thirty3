const fs = require('fs');
const path = require('path');

// 1. Définition des Chemins Absolus (Vital pour éviter les erreurs de path)
const DATA_DIR = path.join(__dirname, 'data');
const SETTINGS_PATH = path.join(DATA_DIR, 'settings.json');

// 2. Configuration par défaut (Fallback)
const DEFAULT_SETTINGS = {
    themeMode: 'dark',
    language: 'fr-CA',
    autoCorrection: true,
    apiKeys: {
        openai: '',
        anthropic: '',
        gemini: '',
        groq: '',
        anythingllm: '',
        anythingllmUrl: 'http://localhost:3001/api/v1'
    },
    system: {
        autoSaveInterval: 60000,
        logLevel: 'info'
    }
};

class SettingsService {
    constructor() {
        this.settingsPath = SETTINGS_PATH;
        this.initialize();
    }

    /**
     * Initialisation Robuste : Crée le dossier et le fichier si absents
     */
    initialize() {
        try {
            // Vérifier/Créer le dossier 'data'
            if (!fs.existsSync(DATA_DIR)) {
                console.log(`[SETTINGS] Dossier data introuvable. Création : ${DATA_DIR}`);
                fs.mkdirSync(DATA_DIR, { recursive: true });
            }

            // Vérifier si le fichier settings existe
            if (!fs.existsSync(this.settingsPath)) {
                console.log('[SETTINGS] Fichier introuvable. Création avec valeurs par défaut.');
                this.writeSettingsToDisk(DEFAULT_SETTINGS);
            } else {
                // Test de lecture pour vérifier la corruption
                try {
                    const content = fs.readFileSync(this.settingsPath, 'utf8');
                    JSON.parse(content); // Juste pour tester la validité
                    console.log(`[SETTINGS] Chargé avec succès depuis : ${this.settingsPath}`);
                } catch (parseError) {
                    console.error('[SETTINGS] ⚠️ Fichier corrompu détecté. Réinitialisation (Backup créé).');
                    fs.copyFileSync(this.settingsPath, `${this.settingsPath}.bak`); // Backup
                    this.writeSettingsToDisk(DEFAULT_SETTINGS);
                }
            }
        } catch (error) {
            console.error('[SETTINGS] Erreur critique initialisation:', error);
        }
    }

    /**
     * Lecture : Fusionne toujours avec les Defaults pour éviter les champs manquants
     */
    getSettings() {
        try {
            if (!fs.existsSync(this.settingsPath)) {
                return DEFAULT_SETTINGS;
            }
            const fileContent = fs.readFileSync(this.settingsPath, 'utf8');
            const userSettings = JSON.parse(fileContent);

            // Merge profond simple : Defaults <- UserSettings
            // Cela garantit que si tu ajoutes une nouvelle option dans le code, 
            // elle n'est pas "undefined" pour l'utilisateur existant.
            return { ...DEFAULT_SETTINGS, ...userSettings, apiKeys: { ...DEFAULT_SETTINGS.apiKeys, ...userSettings.apiKeys } };
        } catch (error) {
            console.error('[SETTINGS] Erreur lecture:', error);
            return DEFAULT_SETTINGS;
        }
    }

    /**
     * Sauvegarde : "Atomic Merge"
     * Ne remplace que ce qui est modifié, garde le reste.
     */
    saveSettings(newSettings) {
        try {
            const currentSettings = this.getSettings();

            // Fusion des données existantes avec les nouvelles
            const updatedSettings = {
                ...currentSettings,
                ...newSettings,
                // Gestion spécifique pour les objets imbriqués comme apiKeys
                apiKeys: {
                    ...(currentSettings.apiKeys || {}),
                    ...(newSettings.apiKeys || {})
                }
            };

            this.writeSettingsToDisk(updatedSettings);
            return updatedSettings;
        } catch (error) {
            console.error('[SETTINGS] Erreur sauvegarde:', error);
            throw new Error('Impossible de sauvegarder les paramètres');
        }
    }

    /**
     * Helper interne pour l'écriture disque
     */
    writeSettingsToDisk(data) {
        fs.writeFileSync(this.settingsPath, JSON.stringify(data, null, 2), 'utf8');
    }

    /**
     * Mise à jour d'une seule clé (utilitaire rapide)
     */
    updateKey(key, value) {
        const settings = this.getSettings();
        settings[key] = value;
        return this.saveSettings(settings);
    }
}

// Singleton pour éviter les conflits d'accès fichier
const settingsService = new SettingsService();
module.exports = settingsService;
