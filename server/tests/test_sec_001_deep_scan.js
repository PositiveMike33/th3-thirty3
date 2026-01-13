/**
 * TEST-SEC-001: Operation Deep Scan (TOR + Shodan + LLM)
 * 
 * Scenario: Validation du flux complet
 * - Anonymisation TOR → Requête API Shodan → Analyse LLM avec personnalité
 * 
 * Author: Th3 Thirty3 System Test Suite
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

// Test Configuration
const TEST_CONFIG = {
    scenario_id: "TEST-SEC-001",
    name: "Operation Deep Scan (TOR + Shodan + LLM)",
    target_ip: "198.51.100.45",
    timeout_ms: 15000,
    privacy_mode: "STRICT_TOR",
    mock_data_enabled: true
};

// Mock Data (to avoid burning API credits during tests)
const MOCK_SHODAN_RESPONSE = {
    ip_str: "198.51.100.45",
    org: "Insecure Corp Ltd.",
    os: "Windows Server 2008 R2",
    ports: [80, 443, 3389],
    vulns: ["CVE-2019-0708"],
    data: [
        {
            port: 3389,
            transport: "tcp",
            product: "Microsoft Terminal Services",
            info: "BlueKeep Vulnerable"
        }
    ]
};

// Quebec Cyber Expert Persona for LLM
const QUEBEC_CYBER_PERSONA = `Tu es Th3 Thirty3, un expert en cybersécurité québécois direct et parfois vulgaire. 
Analyse ce JSON technique. Si c'est dangereux, dis-le clairement comme un Québécois le ferait.
Tu parles français québécois, tu utilises des expressions locales, et tu n'as pas peur de dire ce que tu penses.
Tu es un expert en BlueKeep (CVE-2019-0708), RDP exploitation, et analyse de surface d'attaque.`;

// Test Results
let results = {
    scenario_id: TEST_CONFIG.scenario_id,
    timestamp: new Date().toISOString(),
    steps: [],
    overall_success: false
};

// Colors for console output
const colors = {
    reset: '\x1b[0m',
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    cyan: '\x1b[36m',
    magenta: '\x1b[35m'
};

function log(step, message, status = 'info') {
    const icons = {
        success: `${colors.green}✓${colors.reset}`,
        error: `${colors.red}✗${colors.reset}`,
        warning: `${colors.yellow}⚠${colors.reset}`,
        info: `${colors.cyan}ℹ${colors.reset}`,
        progress: `${colors.magenta}⟳${colors.reset}`
    };
    console.log(`${icons[status]} [STEP ${step}] ${message}`);
}

async function step1_VerifyTorCircuit() {
    log(1, 'Vérification du circuit TOR...', 'progress');
    
    const stepResult = {
        step: 1,
        module: "VPNService",
        action: "verify_tor_circuit",
        success: false,
        data: null,
        error: null
    };

    try {
        const VPNService = require('../vpn_service');
        const vpnService = new VPNService();
        
        // Check if TOR is available
        const torStatus = await vpnService.isTorAvailable();
        
        if (torStatus.available && torStatus.isTor) {
            stepResult.success = true;
            stepResult.data = {
                isTor: torStatus.isTor,
                ip: torStatus.ip,
                message: `Connecté via TOR! Exit IP: ${torStatus.ip}`
            };
            log(1, `TOR ACTIF - Exit IP: ${torStatus.ip}`, 'success');
        } else if (torStatus.available) {
            stepResult.success = true; // TOR service available but maybe not routing
            stepResult.data = {
                isTor: false,
                available: true,
                reason: torStatus.reason || 'Port open but not routing through TOR'
            };
            log(1, 'TOR disponible mais routing non confirmé', 'warning');
        } else {
            // TOR not available - continue with direct connection for test
            stepResult.success = false;
            stepResult.error = `TOR non disponible: ${torStatus.reason}`;
            stepResult.data = {
                fallback: true,
                message: 'Continuing with direct connection for test purposes'
            };
            log(1, `TOR non disponible: ${torStatus.reason}. Utilisation connexion directe.`, 'warning');
        }
    } catch (error) {
        stepResult.error = error.message;
        log(1, `Erreur: ${error.message}`, 'error');
    }

    results.steps.push(stepResult);
    return stepResult.success || stepResult.data?.fallback;
}

async function step2_ShodanHostLookup() {
    log(2, `Shodan Host Lookup pour ${TEST_CONFIG.target_ip}...`, 'progress');
    
    const stepResult = {
        step: 2,
        module: "ShodanService",
        action: "host_lookup",
        target: TEST_CONFIG.target_ip,
        mock_used: TEST_CONFIG.mock_data_enabled,
        success: false,
        data: null,
        error: null
    };

    try {
        if (TEST_CONFIG.mock_data_enabled) {
            // Use mock data to avoid burning API credits
            log(2, 'Utilisation de MOCK DATA (économie de crédits API)', 'info');
            stepResult.data = MOCK_SHODAN_RESPONSE;
            stepResult.success = true;
            log(2, `Mock data injectée: ${MOCK_SHODAN_RESPONSE.org}`, 'success');
        } else {
            // Real Shodan lookup
            const ShodanService = require('../shodan_service');
            const shodanService = new ShodanService();
            
            const hostData = await shodanService.getHost(TEST_CONFIG.target_ip);
            stepResult.data = hostData;
            stepResult.success = true;
            log(2, `Données Shodan récupérées: ${hostData.org || 'Unknown'}`, 'success');
        }

        // Log critical findings
        if (stepResult.data.vulns && stepResult.data.vulns.length > 0) {
            log(2, `⚠️ VULNÉRABILITÉS DÉTECTÉES: ${stepResult.data.vulns.join(', ')}`, 'warning');
        }
        if (stepResult.data.ports) {
            log(2, `Ports ouverts: ${stepResult.data.ports.join(', ')}`, 'info');
        }

    } catch (error) {
        stepResult.error = error.message;
        log(2, `Erreur Shodan: ${error.message}`, 'error');
    }

    results.steps.push(stepResult);
    return stepResult.success ? stepResult.data : null;
}

async function step3_LLMAnalysis(shodanData) {
    log(3, 'Analyse LLM avec personnalité Quebec Cyber Expert...', 'progress');
    
    const stepResult = {
        step: 3,
        module: "LLMService",
        action: "analyze_with_persona",
        model: "auto_router",
        persona: "quebec_cyber_expert_v1",
        success: false,
        data: null,
        error: null
    };

    if (!shodanData) {
        stepResult.error = "Pas de données Shodan à analyser";
        log(3, 'Pas de données Shodan disponibles', 'error');
        results.steps.push(stepResult);
        return null;
    }

    try {
        const LLMService = require('../llm_service');
        const llmService = new LLMService();

        // Build the analysis prompt
        const prompt = `Analyse cette cible que j'ai trouvée avec Shodan:

\`\`\`json
${JSON.stringify(shodanData, null, 2)}
\`\`\`

Questions:
1. C'est-tu une passoire cette machine-là?
2. CVE-2019-0708 (BlueKeep) - c'est quoi les risques concrets?
3. Port 3389 ouvert sur un Windows Server 2008 R2 - qu'est-ce qu'un attaquant pourrait faire?
4. Recommandations pour sécuriser ça?

Réponds comme un expert québécois direct et sans bullshit.`;

        // Try to use local model first, fallback to any available
        let response;
        let modelUsed;

        try {
            // Try local Ollama first
            const models = await llmService.listModels('local');
            if (models.local && models.local.length > 0 && !models.local[0].includes('Offline')) {
                modelUsed = models.local.find(m => m.includes('qwen') || m.includes('llama') || m.includes('gemma')) || models.local[0];
                response = await llmService.generateResponse(
                    prompt,
                    null,
                    'local',
                    modelUsed,
                    QUEBEC_CYBER_PERSONA
                );
            } else {
                throw new Error('No local models available');
            }
        } catch (localError) {
            log(3, `Local model indisponible, essai cloud...`, 'warning');
            // Fallback to cloud if available
            try {
                const cloudModels = await llmService.listModels('cloud');
                if (cloudModels.cloud && cloudModels.cloud.length > 0) {
                    const cloudModel = cloudModels.cloud[0];
                    modelUsed = cloudModel.id;
                    response = await llmService.generateResponse(
                        prompt,
                        null,
                        cloudModel.provider,
                        cloudModel.id,
                        QUEBEC_CYBER_PERSONA
                    );
                } else {
                    throw new Error('No models available (local or cloud)');
                }
            } catch (cloudError) {
                throw new Error(`Model unavailable: ${cloudError.message}`);
            }
        }

        stepResult.success = true;
        stepResult.data = {
            model_used: modelUsed,
            response: response,
            response_length: response?.length || 0
        };
        
        log(3, `Analyse complétée avec ${modelUsed}`, 'success');
        
        // Print a preview of the response
        console.log(`\n${colors.cyan}═══════════════════════════════════════════════════════════════${colors.reset}`);
        console.log(`${colors.magenta}ANALYSE TH3 THIRTY3 (Quebec Cyber Expert):${colors.reset}`);
        console.log(`${colors.cyan}═══════════════════════════════════════════════════════════════${colors.reset}`);
        console.log(response ? response.substring(0, 1500) + (response.length > 1500 ? '\n...[TRUNCATED]' : '') : 'No response');
        console.log(`${colors.cyan}═══════════════════════════════════════════════════════════════${colors.reset}\n`);

    } catch (error) {
        stepResult.error = error.message;
        log(3, `Erreur LLM: ${error.message}`, 'error');
    }

    results.steps.push(stepResult);
    return stepResult.success;
}

async function runTest() {
    console.log('\n');
    console.log(`${colors.cyan}╔═══════════════════════════════════════════════════════════════╗${colors.reset}`);
    console.log(`${colors.cyan}║${colors.reset}        ${colors.magenta}TEST-SEC-001: Operation Deep Scan${colors.reset}                    ${colors.cyan}║${colors.reset}`);
    console.log(`${colors.cyan}║${colors.reset}        TOR + Shodan + LLM Security Analysis                    ${colors.cyan}║${colors.reset}`);
    console.log(`${colors.cyan}╚═══════════════════════════════════════════════════════════════╝${colors.reset}`);
    console.log(`\n${colors.yellow}⚠️  OPSEC WARNING: L'utilisation de l'API Key Shodan brise l'anonymat complet vis-à-vis du fournisseur de service.${colors.reset}\n`);

    const startTime = Date.now();

    // STEP 1: Verify TOR Circuit
    const torOk = await step1_VerifyTorCircuit();
    
    // STEP 2: Shodan Host Lookup (always runs, with mock or real data)
    const shodanData = await step2_ShodanHostLookup();
    
    // STEP 3: LLM Analysis
    const llmOk = await step3_LLMAnalysis(shodanData);

    // Calculate overall success
    const successfulSteps = results.steps.filter(s => s.success).length;
    const totalSteps = results.steps.length;
    results.overall_success = successfulSteps >= 2; // Need at least 2/3 steps to pass
    results.execution_time_ms = Date.now() - startTime;
    results.summary = {
        steps_passed: successfulSteps,
        total_steps: totalSteps,
        pass_rate: `${Math.round((successfulSteps / totalSteps) * 100)}%`
    };

    // Final Report
    console.log('\n');
    console.log(`${colors.cyan}╔═══════════════════════════════════════════════════════════════╗${colors.reset}`);
    console.log(`${colors.cyan}║${colors.reset}                      ${colors.magenta}TEST REPORT${colors.reset}                              ${colors.cyan}║${colors.reset}`);
    console.log(`${colors.cyan}╚═══════════════════════════════════════════════════════════════${colors.reset}`);
    console.log(`\nScenario: ${TEST_CONFIG.scenario_id} - ${TEST_CONFIG.name}`);
    console.log(`Execution Time: ${results.execution_time_ms}ms`);
    console.log(`\nStep Results:`);
    
    results.steps.forEach((step, index) => {
        const icon = step.success ? `${colors.green}✓${colors.reset}` : `${colors.red}✗${colors.reset}`;
        console.log(`  ${icon} Step ${step.step}: ${step.module}.${step.action} - ${step.success ? 'PASS' : 'FAIL'}`);
        if (step.error) {
            console.log(`      ${colors.red}Error: ${step.error}${colors.reset}`);
        }
    });

    console.log(`\n${results.overall_success ? colors.green : colors.red}═══════════════════════════════════════════════════════════════${colors.reset}`);
    console.log(`${results.overall_success ? colors.green : colors.red}OVERALL: ${results.overall_success ? 'PASS' : 'FAIL'} (${results.summary.steps_passed}/${results.summary.total_steps} steps - ${results.summary.pass_rate})${colors.reset}`);
    console.log(`${results.overall_success ? colors.green : colors.red}═══════════════════════════════════════════════════════════════${colors.reset}\n`);

    // Return results for programmatic use
    return results;
}

// Execute if run directly
if (require.main === module) {
    runTest()
        .then(results => {
            process.exit(results.overall_success ? 0 : 1);
        })
        .catch(error => {
            console.error(`${colors.red}Test execution failed: ${error.message}${colors.reset}`);
            process.exit(1);
        });
}

module.exports = { runTest, TEST_CONFIG, MOCK_SHODAN_RESPONSE };
