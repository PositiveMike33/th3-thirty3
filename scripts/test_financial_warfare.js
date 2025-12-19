/**
 * FINANCIAL WAR ROOM - SCENARIO SIMULATION
 * Demonstrates the AdversarySim Agent tackling the CBDC Sybil Attack Scenario
 */

const { AdversarySimAgent } = require('../server/specialized_agents');
const fs = require('fs');
const path = require('path');

// Mock LLM Service that actually uses the Scenario Context
class SimulationLLMService {
    async generateOllamaResponse(prompt, context, model, systemPrompt) {
        console.log('\n[LLM] Analyzing scenario with model:', model);
        console.log('[LLM] System Focus:', systemPrompt.split('\n')[0]);
        
        // Simulate processing time
        await new Promise(resolve => setTimeout(resolve, 1500));
        
        return `### TACTICAL ANALYSIS: CBDC CONSENSUS ATTACK
        
**Threat Actor Profile:** State-Sponsored APT Group
**Vector:** Sybil Attack on Permissioned Validator Nodes (>33%)

**Execution Strategy:**
1.  **Node Compromise:** Exploited zero-day in the validator signing module (Rust-based).
2.  **Timing Analysis:** Correlated block proposal times to identify leader rotation.
3.  **Consensus Jamming:** 35% of nodes are now broadcasting conflicting block headers, stalling finality.

**Strategic Recommendation (DEFENSE):**
- **Hard Fork:** Immediately invalidate the compromised validator keys.
- **Rollback:** Revert ledger state to block height #1,204,500 (pre-attack).
- **Transition:** Switch consensus to "Proof of Authority" temporarily with manual oversight.

**Status:** CRITICAL - Ledger Sovereignty Risk`;
    }
}

async function runSimulation() {
    console.log(`
╔════════════════════════════════════════════════════════════════╗
║             FINANCIAL CYBER-WARFARE SIMULATION                 ║
║               Scenario: FIN-005 (CBDC Attack)                  ║
╚════════════════════════════════════════════════════════════════╝
    `);

    // 1. Load the Scenario
    const scenariosPath = path.join(__dirname, '../server/knowledge/financial_markets_scenarios.json');
    const scenariosData = JSON.parse(fs.readFileSync(scenariosPath, 'utf8'));
    const scenario = scenariosData.scenarios.find(s => s.id === 'FIN-005');

    if (!scenario) {
        console.error('Scenario FIN-005 not found!');
        return;
    }

    console.log(`\n[SCENARIO LOADED] ${scenario.title}`);
    console.log(`Diffculty: ${scenario.difficulty}`);
    console.log(`Context: ${scenario.context}`);
    
    // 2. Initialize the Specialist Agent
    console.log(`\n[ACTIVATING AGENT] ${scenario.ideal_agent}...`);
    const llmService = new SimulationLLMService();
    const agent = new AdversarySimAgent(llmService, scenario.ideal_model);
    
    // 3. Execute the Mission
    console.log(`[MISSION START] Agent ${agent.agentName} engaging target...`);
    
    // Inject the scenario into the agent's "random" generator for this test
    agent.generateRandomScenario = () => ({
        type: 'FINANCIAL_WARFARE',
        difficulty: 'Transcendent',
        context: `SCENARIO: ${scenario.title}\nCONTEXT: ${scenario.context}\nOBJECTIVES: ${scenario.objectives.join(', ')}`
    });

    const result = await agent.executeRandomExperience();

    // 4. Report
    console.log('\n' + '─'.repeat(60));
    console.log('MISSION DEBRIEF');
    console.log('─'.repeat(60));
    console.log(result.experience.score >= 80 ? '✅ SUCCESS' : '❌ FAILURE');
    console.log(`Cybernetic Score: ${result.score}/100`);
    console.log(`Agent Expertise: ${result.newExpertise.toFixed(1)}`);
    console.log(`Elite Status: ${agent.getEliteLevel().name}`);
    console.log('\n[SIMULATION COMPLETE]');
}

runSimulation();
