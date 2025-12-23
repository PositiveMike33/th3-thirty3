/**
 * GRANITE CLEANUP SCRIPT
 * Replace all granite3.1-moe:1b references with dolphin-uncensored
 */

const fs = require('fs');
const path = require('path');

const OLD_MODEL = 'granite3.1-moe:1b';
const NEW_MODEL = 'uandinotai/dolphin-uncensored:latest';

// Also clean granite-flash references
const REPLACEMENTS = [
    { from: 'granite3.1-moe:1b', to: 'uandinotai/dolphin-uncensored:latest' },
    { from: 'granite3.1-moe', to: 'uandinotai/dolphin-uncensored' },
    { from: 'granite3.1-flash:latest', to: 'uandinotai/dolphin-uncensored:latest' },
    { from: 'granite-flash:latest', to: 'uandinotai/dolphin-uncensored:latest' },
    { from: "'granite'", to: "'dolphin'" },
];

const filesToClean = [
    'server/agent_director_service.js',
    'server/anythingllm_wrapper.js',
    'server/cyber_training_service.js',
    'server/expert_agents_service.js',
    'server/expert_model_service.js',
    'server/hacking_expert_agents_service.js',
    'server/index.js',
    'server/network_failover_service.js',
    'server/model_router.js',
    'server/osint_team_anythingllm.js',
    'server/osint_expert_agents_service.js',
    'server/plugins/osint_plugin.js',
    'server/report_extraction_service.js',
    'server/shodan_routes.js',
    'server/orchestrator_service.js',
    'server/offline_mode_service.js',
    'server/verify_training.js',
    'interface/src/ChatInterface.jsx',
    'interface/src/GlobalChat.jsx',
    'interface/src/FineTuningDashboard.jsx',
    'interface/src/components/ModelIntelligenceDashboard.jsx',
    'interface/src/components/ModelProgressChart.jsx',
    'scripts/global_check.js',
    'scripts/auto_train_agents.js',
    'scripts/auto_train.js',
    'server/scripts/cleanup_models.js',
    'server/scripts/osint_pipeline.py',
    'server/tests/test_all_models.js',
    'server/tests/test_model_evolution.js',
    'server/test_saas_tiers.js',
    'server/knowledge/expert_model_assignments.json',
    'server/knowledge/financial_markets_scenarios.json',
    'restart_with_checks.bat',
    'start_th3_thirty3.bat'
];

let totalReplacements = 0;

filesToClean.forEach(relPath => {
    const fullPath = path.join(__dirname, '..', relPath);
    
    if (!fs.existsSync(fullPath)) {
        console.log(`⚠️  File not found: ${relPath}`);
        return;
    }
    
    let content = fs.readFileSync(fullPath, 'utf-8');
    let modified = false;
    let fileReplacements = 0;
    
    REPLACEMENTS.forEach(({ from, to }) => {
        const regex = new RegExp(from.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
        const matches = content.match(regex);
        if (matches) {
            content = content.replace(regex, to);
            fileReplacements += matches.length;
            modified = true;
        }
    });
    
    if (modified) {
        fs.writeFileSync(fullPath, content);
        console.log(`✅ ${relPath}: ${fileReplacements} replacements`);
        totalReplacements += fileReplacements;
    }
});

console.log(`\n📊 Total: ${totalReplacements} replacements across ${filesToClean.length} files`);
console.log(`\n🎯 Replaced: ${OLD_MODEL} → ${NEW_MODEL}`);
