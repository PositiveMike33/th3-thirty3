/**
 * Routes Integration for Th3 Thirty3
 * 
 * Add these lines to your index.js after other route mounts
 * (Around line 1600, after VPN routes)
 * 
 * COPY AND PASTE THE FOLLOWING INTO index.js:
 */

// ============================================
// RUNPOD GPU CLOUD ROUTES (NEW)
// ============================================
// const runpodRoutes = require('./runpod_routes');
// app.use('/api/runpod', runpodRoutes);
// console.log('[SYSTEM] RunPod GPU Cloud routes mounted at /api/runpod');

// ============================================
// HACKERGPT TRAINING SYSTEM ROUTES (NEW)
// ============================================
// const HackerGPTTrainingService = require('./hackergpt_training_service');
// const hackergptRoutes = require('./hackergpt_routes');
// 
// // Initialize HackerGPT with LLM service
// const hackergptService = new HackerGPTTrainingService(llmService, modelMetricsService);
// hackergptRoutes.init(hackergptService);
// 
// app.use('/api/hackergpt', hackergptRoutes);
// console.log('[HACKERGPT] Training System mounted at /api/hackergpt');
// console.log('[HACKERGPT] Available tracks: OSINT, Pentesting, Exploit Dev, Web Security, Social Engineering');

// ============================================
// FULL INTEGRATION SNIPPET (READY TO PASTE)
// ============================================

/*

// RunPod GPU Cloud Service
const runpodRoutes = require('./runpod_routes');
app.use('/api/runpod', runpodRoutes);
console.log('[SYSTEM] RunPod GPU Cloud routes mounted at /api/runpod');

// HackerGPT Training System - Elite Hacker Training for Models
const HackerGPTTrainingService = require('./hackergpt_training_service');
const hackergptRoutes = require('./hackergpt_routes');
const hackergptService = new HackerGPTTrainingService(llmService, modelMetricsService);
hackergptRoutes.init(hackergptService);
app.use('/api/hackergpt', hackergptRoutes);
console.log('[HACKERGPT] Training System initialized - Elite Hacker Training');
console.log('[HACKERGPT] Routes mounted at /api/hackergpt');

*/

// ============================================
// ENV CONFIGURATION - Add to .env file
// ============================================
// 
// # RunPod GPU Cloud
// RUNPOD_API_KEY=your_runpod_api_key_here
// RUNPOD_LLAMA70B_ENDPOINT=your_serverless_endpoint_id
// RUNPOD_VLLM_ENDPOINT=your_vllm_endpoint_id
// RUNPOD_OPENAI_ENDPOINT=https://your-pod-id-11434.proxy.runpod.net
//
