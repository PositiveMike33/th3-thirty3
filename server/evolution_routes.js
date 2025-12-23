/**
 * Evolution Dashboard Routes
 * 
 * API endpoints for the Agent Evolution Dashboard and Team Chat
 */

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');

// Import services (lazy loading to avoid errors if not available)
let evolutionSystem = null;
let kbTraining = null;
let hackergpt = null;

// Training log buffer
const trainingLogs = [];
const MAX_LOGS = 100;

// Add log entry
function addLog(message, type = 'info') {
    trainingLogs.unshift({
        timestamp: new Date().toISOString(),
        message,
        type
    });
    if (trainingLogs.length > MAX_LOGS) {
        trainingLogs.pop();
    }
}

// Initialize services lazily
function getEvolutionSystem() {
    if (!evolutionSystem) {
        try {
            const ContinuousEvolutionSystem = require('./continuous_evolution_system');
            const HackerGPTTrainingService = require('./hackergpt_training_service');
            
            // Mock LLM service
            const mockLLM = {
                async generateOllamaResponse(prompt, img, model, sys) {
                    const { Ollama } = require('ollama');
                    const ollama = new Ollama({ host: process.env.OLLAMA_URL || 'http://localhost:11434' });
                    const response = await ollama.chat({
                        model,
                        messages: [{ role: 'system', content: sys }, { role: 'user', content: prompt }]
                    });
                    return response.message.content;
                }
            };
            
            hackergpt = new HackerGPTTrainingService(mockLLM, null);
            evolutionSystem = new ContinuousEvolutionSystem(hackergpt, mockLLM);
            
            console.log('[EVOLUTION-ROUTES] Services initialized');
        } catch (error) {
            console.error('[EVOLUTION-ROUTES] Failed to init services:', error.message);
        }
    }
    return evolutionSystem;
}

function getKBTraining() {
    if (!kbTraining) {
        try {
            const KnowledgeIntegratedTraining = require('./knowledge_integrated_training');
            const mockLLM = {
                async generateOllamaResponse(prompt, img, model, sys) {
                    const { Ollama } = require('ollama');
                    const ollama = new Ollama({ host: process.env.OLLAMA_URL || 'http://localhost:11434' });
                    const response = await ollama.chat({
                        model,
                        messages: [{ role: 'system', content: sys }, { role: 'user', content: prompt }]
                    });
                    return response.message.content;
                }
            };
            kbTraining = new KnowledgeIntegratedTraining(mockLLM);
        } catch (error) {
            console.error('[EVOLUTION-ROUTES] Failed to init KB training:', error.message);
        }
    }
    return kbTraining;
}

/**
 * GET /evolution-status
 * Get current evolution status for all models
 */
router.get('/evolution-status', (req, res) => {
    try {
        const evolution = getEvolutionSystem();
        
        if (!evolution) {
            // Return mock data if services not available
            return res.json({
                models: [
                    {
                        name: 'Sadiq',
                        fullName: 'sadiq-bd/llama3.2-3b-uncensored',
                        evolutionLevel: 2,
                        levelName: 'Junior Pentester',
                        prodigyScore: null,
                        stats: { sessions: 5, passed: 3, failed: 2, xp: 250, fatigue: 20, momentum: 1.1 },
                        domainExpertise: { osint: 45, pentesting: 30, social_engineering: 50, wireless: 25 }
                    },
                    {
                        name: 'Dolphin',
                        fullName: 'uandinotai/dolphin-uncensored',
                        evolutionLevel: 2,
                        levelName: 'Junior Pentester',
                        prodigyScore: null,
                        stats: { sessions: 4, passed: 2, failed: 2, xp: 180, fatigue: 15, momentum: 0.95 },
                        domainExpertise: { pentesting: 55, exploit_dev: 35, red_team: 30, network: 20 }
                    },
                    {
                        name: 'Nidum',
                        fullName: 'nidumai/nidum-llama-3.2-3b-uncensored',
                        evolutionLevel: 1,
                        levelName: 'Script Kiddie',
                        prodigyScore: null,
                        stats: { sessions: 3, passed: 1, failed: 2, xp: 120, fatigue: 10, momentum: 0.9 },
                        domainExpertise: { exploit_dev: 40, cryptography: 25, forensics: 20, malware: 15 }
                    }
                ],
                isActive: false,
                levels: evolution?.constructor?.EVOLUTION_LEVELS || {}
            });
        }
        
        const status = evolution.getEvolutionStatus();
        res.json(status);
        
    } catch (error) {
        console.error('[EVOLUTION-ROUTES] Error:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /training-log
 * Get recent training logs
 */
router.get('/training-log', (req, res) => {
    res.json({
        logs: trainingLogs,
        isTraining: false
    });
});

/**
 * POST /train
 * Start a training session for a model
 */
router.post('/train', async (req, res) => {
    const { modelName, domain, useRAG = true } = req.body;
    
    if (!modelName || !domain) {
        return res.status(400).json({ error: 'modelName and domain required' });
    }
    
    addLog(`Starting training: ${modelName} on ${domain}`, 'info');
    
    try {
        const kb = getKBTraining();
        
        if (!kb) {
            addLog('KB Training service not available', 'error');
            return res.status(500).json({ error: 'Training service not available' });
        }
        
        const result = await kb.runKnowledgeExam(modelName, domain, useRAG);
        
        addLog(`Training complete: ${result.averageScore}% ${result.passed ? '✅' : '❌'}`, result.passed ? 'success' : 'warning');
        
        res.json({
            success: true,
            result
        });
        
    } catch (error) {
        addLog(`Training failed: ${error.message}`, 'error');
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /knowledge-summary
 * Get knowledge base summary
 */
router.get('/knowledge-summary', (req, res) => {
    try {
        const kb = getKBTraining();
        
        if (!kb) {
            return res.json({
                totalKnowledgeBases: 20,
                domains: {
                    osint: { sources: ['osint_shodan'], questionCount: 5 },
                    pentesting: { sources: ['pentestgpt_methodology'], questionCount: 36 },
                    wireless: { sources: ['wifi_security'], questionCount: 20 }
                }
            });
        }
        
        const summary = kb.getKnowledgeSummary();
        res.json(summary);
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /team-chat
 * Get team chat response from multiple agents
 */
router.post('/team-chat', async (req, res) => {
    const { message, agents = ['sadiq', 'dolphin', 'nidum'] } = req.body;
    
    if (!message) {
        return res.status(400).json({ error: 'message required' });
    }
    
    const modelMap = {
        'sadiq': 'sadiq-bd/llama3.2-3b-uncensored',
        'dolphin': 'uandinotai/dolphin-uncensored',
        'nidum': 'nidumai/nidum-llama-3.2-3b-uncensored'
    };
    
    const responses = [];
    
    for (const agentId of agents) {
        try {
            const { Ollama } = require('ollama');
            const ollama = new Ollama({ host: process.env.OLLAMA_URL || 'http://localhost:11434' });
            
            const response = await ollama.chat({
                model: modelMap[agentId],
                messages: [
                    { role: 'system', content: `Tu es ${agentId}, un agent AI collaboratif. Réponds brièvement.` },
                    { role: 'user', content: message }
                ]
            });
            
            responses.push({
                agent: agentId,
                content: response.message.content
            });
            
        } catch (error) {
            responses.push({
                agent: agentId,
                content: 'Agent indisponible',
                error: true
            });
        }
    }
    
    res.json({ responses });
});

/**
 * GET /model-state/:modelName
 * Get detailed state for a specific model
 */
router.get('/model-state/:modelName', (req, res) => {
    const { modelName } = req.params;
    
    try {
        const evolution = getEvolutionSystem();
        
        if (!evolution) {
            return res.status(500).json({ error: 'Evolution system not available' });
        }
        
        const state = evolution.getModelState(decodeURIComponent(modelName));
        res.json(state);
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// AUTONOMOUS LEARNING LOOP
// Continuous agent dialogue and evolution
// ============================================

let learningLoop = null;

function getLearningLoop() {
    if (!learningLoop) {
        try {
            const AutonomousLearningLoop = require('./autonomous_learning_loop');
            learningLoop = new AutonomousLearningLoop(null);
            
            // Add event listeners for logging
            learningLoop.on('task_started', (task) => {
                addLog(`🎯 Task #${task.id}: ${task.type} (${task.level})`, 'info');
            });
            
            learningLoop.on('agent_responded', (data) => {
                addLog(`${data.icon} ${data.agentName}: ${data.response.substring(0, 80)}...`, 'success');
            });
            
            learningLoop.on('cycle_completed', (conv) => {
                addLog(`✅ Cycle complete: ${conv.responses.length} responses`, 'success');
            });
            
            console.log('[EVOLUTION-ROUTES] Autonomous Learning Loop initialized');
        } catch (error) {
            console.error('[EVOLUTION-ROUTES] Failed to init learning loop:', error.message);
        }
    }
    return learningLoop;
}

/**
 * GET /learning-loop/status
 * Get learning loop status
 */
router.get('/learning-loop/status', (req, res) => {
    try {
        const loop = getLearningLoop();
        if (!loop) {
            return res.json({ isRunning: false, error: 'Loop not available' });
        }
        res.json(loop.getStatus());
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /learning-loop/start
 * Start the autonomous learning loop
 */
router.post('/learning-loop/start', async (req, res) => {
    const { intervalMinutes = 5 } = req.body;
    
    try {
        const loop = getLearningLoop();
        if (!loop) {
            return res.status(500).json({ error: 'Loop not available' });
        }
        
        const result = await loop.start(intervalMinutes);
        addLog(`🚀 Learning loop started (interval: ${intervalMinutes}min)`, 'info');
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /learning-loop/stop
 * Stop the learning loop
 */
router.post('/learning-loop/stop', (req, res) => {
    try {
        const loop = getLearningLoop();
        if (!loop) {
            return res.status(500).json({ error: 'Loop not available' });
        }
        
        const result = loop.stop();
        addLog('🛑 Learning loop stopped', 'warning');
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /learning-loop/trigger
 * Trigger a manual discussion
 */
router.post('/learning-loop/trigger', async (req, res) => {
    const { topic, type = 'discuss' } = req.body;
    
    if (!topic) {
        return res.status(400).json({ error: 'topic required' });
    }
    
    try {
        const loop = getLearningLoop();
        if (!loop) {
            return res.status(500).json({ error: 'Loop not available' });
        }
        
        addLog(`💬 Manual discussion: ${topic}`, 'info');
        const result = await loop.triggerDiscussion(topic, type);
        res.json({ success: true, conversation: result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /learning-loop/history
 * Get conversation history
 */
router.get('/learning-loop/history', (req, res) => {
    const limit = parseInt(req.query.limit) || 50;
    
    try {
        const loop = getLearningLoop();
        if (!loop) {
            return res.json({ history: [] });
        }
        
        res.json({ history: loop.getHistory(limit) });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;

