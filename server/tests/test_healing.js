const OrchestratorService = require('../orchestrator_service');

async function testHealing() {
    console.log("🛠️ TEST: Starting Self-Healing Verification...");
    const orchestrator = new OrchestratorService();

    // Mock the consultAgent to return bad result first, then good result
    orchestrator.consultAgent = async (team, agentId, objective) => {
        console.log(`[MOCK AGENT] Received: ${objective}`);
        if (objective.includes("CORRECTION")) {
            return { response: "Voici la liste CORRECTE: ['Fraise', 'Framboise', 'Cerise', 'Groseille', 'Mûre']" };
        }
        return { response: "Voici une liste incomplète: ['Fraise', 'Framboise']" }; // Will fail verification
    };

    // Mock Monitor/LLM calls will rely on real LLM or we can mock verifyResult too if we want pure logic test.
    // For this e2e, we let it use real attributes but mocked agent response.

    try {
        const mission = await orchestrator.executeMission("Obtenir une liste de 5 fruits rouges", { mocked: true });
        console.log("\n✅ MISSION COMPLETE");
        console.log("Phases:", JSON.stringify(mission.phases, null, 2));
    } catch (e) {
        console.error("❌ MISSION FAILED:", e);
    }
}

testHealing();
