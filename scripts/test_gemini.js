// scripts/test_gemini.js
require('colors');
const path = require('path');
// Load from server/.env as verified location
require('dotenv').config({ path: path.join(__dirname, '../server/.env') });
const { GoogleGenerativeAI } = require("@google/generative-ai");

// --- CONFIGURATION ---
// STRICTEMENT GEMINI 3 (Pas de 1.5 ni 2.0 pour l'usage final)
const MODEL_IDS = {
    FLASH: "gemini-3-flash-preview",
    PRO: "gemini-3-pro-preview",
    IMAGE: "gemini-3-pro-image-preview"
};

const apiKey = process.env.GEMINI_API_KEY;

if (!apiKey) {
    console.error("❌ ERREUR CRITIQUE: Aucune clé GEMINI_API_KEY trouvée.".red.bold);
    console.error(`Checked path: ${path.join(__dirname, '../server/.env')}`.yellow);
    process.exit(1);
}

// Show Masked Key for Verification
const maskedKey = apiKey.substring(0, 6) + "..." + apiKey.substring(apiKey.length - 6);
console.log(`🔑 Clé chargée : ${maskedKey.cyan.bold}`);
console.log("ℹ️ Vérification de la validité via un appel API...".yellow);

const genAI = new GoogleGenerativeAI(apiKey);

async function testModel(label, modelId, prompt, strict = true) {
    console.log(`\n--- Test du modèle : ${label} (${modelId}) ---`.cyan);
    const start = Date.now();

    try {
        const model = genAI.getGenerativeModel({ model: modelId });
        const result = await model.generateContent(prompt);
        const response = await result.response;
        const text = response.text();
        const duration = Date.now() - start;

        console.log(`✅ SUCCÈS en ${duration}ms`.green.bold);
        console.log(`📝 Réponse partielle : ${text.substring(0, 80)}...`.gray);
        return true;
    } catch (error) {
        console.error(`❌ ÉCHEC sur ${modelId}`.red.bold);
        console.error(`   Erreur : ${error.message}`.yellow);

        if (error.message.includes('404') || error.message.includes('not found')) {
            console.log(`   👉 DIAGNOSTIC: Le modèle '${modelId}' n'existe pas ou n'est pas activé pour cette clé.`.white);
        } else if (error.message.includes('400') || error.message.includes('API key')) {
            console.log(`   👉 DIAGNOSTIC: La clé API est invalide ou expirée.`.red.bold);
        }

        return false;
    }
}

async function runDiagnostics() {
    console.log("🚀 Démarrage du diagnostic Antigravity / Gemini...".white.bold);

    // 0. (SECTION SUPPRIMÉE: Test de validité 1.5 rejeté par l'utilisateur)

    // 1. Test Flash (Vitesse) - Gemini 3
    await testModel("GEMINI 3 FLASH", MODEL_IDS.FLASH, "Réponds juste par le mot 'Pong'.");

    // 2. Test Pro (Raisonnement) - Gemini 3
    await testModel("GEMINI 3 PRO", MODEL_IDS.PRO, "Explique le concept de 'Vibe Coding' en une phrase courte.");

    // 3. Test Vision
    console.log(`\n--- Vérification config Vision ---`.cyan);
    try {
        const model = genAI.getGenerativeModel({ model: MODEL_IDS.IMAGE });
        if (model) console.log("✅ Modèle Vision instancié avec succès.".green.bold);
    } catch (e) {
        console.log("❌ Erreur config Vision".red);
    }

    console.log("\nDiagnostic terminé.".white.bold);
}

runDiagnostics();
