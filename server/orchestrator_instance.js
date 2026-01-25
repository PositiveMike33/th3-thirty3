/**
 * Orchestrator Instance (Singleton)
 * 
 * Assures that all routes share the same Orchestrator state (missions, agents)
 */

const OrchestratorService = require('./orchestrator_service');

let instance = null;

function getOrchestrator() {
    if (!instance) {
        instance = new OrchestratorService();
        console.log('[SYSTEM] Orchestrator Singleton Initialized');
    }
    return instance;
}

module.exports = getOrchestrator();
