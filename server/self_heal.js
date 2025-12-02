const { execSync } = require('child_process');
const path = require('path');

// Helper to run commands from the project root
const run = (cmd) => {
    try {
        // Execute in the project root (one level up from server/)
        execSync(cmd, { stdio: 'inherit', cwd: path.join(__dirname, '..') });
        return true;
    } catch (e) {
        return false;
    }
};

console.log("\n[SELF-HEAL] Initiating System Integrity Check...");

// 1. Memory Service (Ollama)
console.log("[SELF-HEAL] Checking Memory Service...");
if (!run('node tests/verify_memory.js')) {
    console.warn("[SELF-HEAL] Memory check failed. Attempting auto-fix (Pulling Model)...");
    if (run('ollama pull nomic-embed-text')) {
        console.log("[SELF-HEAL] Model pulled. Retrying check...");
        if (run('node tests/verify_memory.js')) {
            console.log("[SELF-HEAL] Memory Service Restored.");
        } else {
            console.error("[SELF-HEAL] CRITICAL: Memory Service still failing after fix.");
            process.exit(1);
        }
    } else {
        console.error("[SELF-HEAL] CRITICAL: Failed to pull Ollama model.");
        process.exit(1);
    }
} else {
    console.log("[SELF-HEAL] Memory Service: OK");
}

// 2. Pieces Integration
console.log("[SELF-HEAL] Checking Pieces Integration...");
if (!run('node tests/verify_pieces.js')) {
    console.error("[SELF-HEAL] CRITICAL: Pieces Integration failed. Please ensure Pieces OS is running.");
    // Future: Could try to launch Pieces OS here if path is known
    process.exit(1);
} else {
    console.log("[SELF-HEAL] Pieces Integration: OK");
}

// 3. Fabric Patterns
console.log("[SELF-HEAL] Checking Fabric Patterns...");
if (!run('node tests/verify_fabric.js')) {
    console.error("[SELF-HEAL] CRITICAL: Fabric Patterns missing or inaccessible.");
    process.exit(1);
} else {
    console.log("[SELF-HEAL] Fabric Patterns: OK");
}

console.log("[SELF-HEAL] All Systems Nominal. Safe to Launch.\n");
process.exit(0);
