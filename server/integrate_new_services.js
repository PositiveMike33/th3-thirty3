/**
 * Integration Script for RunPod and HackerGPT
 * 
 * Run this script to add the new routes to index.js
 * Usage: node integrate_new_services.js
 */

const fs = require('fs');
const path = require('path');

const indexPath = path.join(__dirname, 'index.js');

// New routes to add
const newRoutesCode = `
// ============================================
// RUNPOD GPU CLOUD SERVICE
// ============================================
const runpodRoutes = require('./runpod_routes');
app.use('/api/runpod', runpodRoutes);
console.log('[SYSTEM] RunPod GPU Cloud routes mounted at /api/runpod');

// ============================================
// HACKERGPT TRAINING SYSTEM
// Elite Hacker Training for Local Models
// ============================================
const HackerGPTTrainingService = require('./hackergpt_training_service');
const hackergptRoutes = require('./hackergpt_routes');
const hackergptService = new HackerGPTTrainingService(llmService, modelMetricsService);
hackergptRoutes.init(hackergptService);
app.use('/api/hackergpt', hackergptRoutes);
console.log('[HACKERGPT] Training System initialized - Elite Hacker Training');
console.log('[HACKERGPT] Routes mounted at /api/hackergpt');
console.log('[HACKERGPT] Tracks: OSINT, Pentesting, Exploit Dev, Web Security, Social Engineering');

`;

function integrate() {
    console.log('Reading index.js...');
    let content = fs.readFileSync(indexPath, 'utf8');
    
    // Check if already integrated
    if (content.includes('hackergpt_training_service')) {
        console.log('HackerGPT already integrated!');
        return;
    }
    
    if (content.includes('runpod_routes')) {
        console.log('RunPod already integrated!');
        return;
    }
    
    // Find the insertion point (before "// Start Server")
    const insertionMarker = '// Start Server';
    const insertionIndex = content.indexOf(insertionMarker);
    
    if (insertionIndex === -1) {
        console.error('Could not find insertion point "// Start Server"');
        return;
    }
    
    // Insert new routes
    const newContent = content.slice(0, insertionIndex) + newRoutesCode + content.slice(insertionIndex);
    
    // Backup original
    const backupPath = indexPath + '.backup_' + Date.now();
    fs.writeFileSync(backupPath, content);
    console.log(`Backup created: ${backupPath}`);
    
    // Write updated content
    fs.writeFileSync(indexPath, newContent);
    console.log('Integration complete!');
    console.log('New routes added:');
    console.log('  - /api/runpod (GPU Cloud)');
    console.log('  - /api/hackergpt (Training System)');
}

integrate();
