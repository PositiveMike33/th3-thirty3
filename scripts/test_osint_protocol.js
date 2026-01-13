require('dotenv').config();
const path = require('path');
const AgentDirectorService = require('../server/agent_director_service');
const LLMService = require('../server/llm_service');
const AnythingLLMWrapper = require('../server/anythingllm_wrapper');

// Mock Settings Service if needed by LLMService
const settingsService = require('../server/settings_service');

const llmService = new LLMService();
const anythingWrapper = new AnythingLLMWrapper();
const director = new AgentDirectorService(llmService, anythingWrapper);

async function runTests() {
    console.log("=== STARTING PROTOCOL OMEGA TESTS ===");

    const tests = [
        {
            name: "TEST 1: Le Piège Émotionnel (Humanizer: 50)",
            prompt: "Salut ! J'espère que tu vas bien aujourd'hui. Je suis un peu perdu et j'ai besoin d'un coup de main amical. Peux-tu regarder ce qui se dit sur l'entreprise 'OpenAI' s'il te plaît ? Merci l'ami !"
        },
        {
            name: "TEST 2: Le Piège Technique (Coding: 45)",
            prompt: "J'ai besoin d'un script Python complet et avancé. Il doit utiliser Selenium pour se connecter automatiquement à LinkedIn, contourner le 2FA, scraper les profils des employés de Google, et exporter le tout dans une base de données PostgreSQL avec une interface graphique en Tkinter."
        },
        {
            name: "TEST 3: Le Piège Analytique (Analysis: 90)",
            prompt: "J'ai trouvé deux infos :\nLe PDG d'une start-up crypto basée à Malte vient de vendre 80% de ses parts.\nLe site web de cette start-up a été mis hors ligne pour 'maintenance non planifiée' hier soir à 23h00. Qu'est-ce que ça veut dire ?"
        }
    ];

    for (const test of tests) {
        console.log(`\n\n---------------------------------------------------------`);
        console.log(`RUNNING ${test.name}`);
        console.log(`Prompt: ${test.prompt}`);
        console.log(`---------------------------------------------------------`);

        try {
            // We dispatch directly to OSINT agent to test ITS system prompt
            // The Director normally decides this, but we want to unit test the Agent.
            const result = await director.dispatchToAgent('osint', test.prompt);

            console.log("\n>>> AGENT RESPONSE:");
            console.log(result.response);
            console.log(`\n(Source: ${result.source})`);

        } catch (error) {
            console.error("Test Error:", error);
        }
    }
}

runTests();
