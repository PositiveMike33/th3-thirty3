const fs = require('fs');
const path = require('path');

const FABRIC_PATH = path.join(__dirname, '../server/fabric/data/patterns');

console.log("[TEST] Verifying Fabric Patterns...");
console.log(`[TEST] Path: ${FABRIC_PATH}`);

if (fs.existsSync(FABRIC_PATH)) {
    console.log("[TEST] Fabric Directory: FOUND");

    try {
        const patterns = fs.readdirSync(FABRIC_PATH).filter(file => {
            return fs.statSync(path.join(FABRIC_PATH, file)).isDirectory();
        });

        console.log(`[TEST] Patterns Found: ${patterns.length}`);

        if (patterns.length > 0) {
            // Check a specific pattern (e.g., 'extract_wisdom' or just the first one)
            const testPattern = patterns[0];
            const systemFile = path.join(FABRIC_PATH, testPattern, 'system.md');

            if (fs.existsSync(systemFile)) {
                console.log(`[TEST] Verified content for '${testPattern}': OK`);
                process.exit(0);
            } else {
                console.error(`[TEST] Pattern '${testPattern}' is missing system.md`);
                process.exit(1);
            }
        } else {
            console.warn("[TEST] No patterns found in directory.");
            process.exit(1);
        }
    } catch (e) {
        console.error(`[TEST] Error reading directory: ${e.message}`);
        process.exit(1);
    }
} else {
    console.error("[TEST] Fabric Directory: NOT FOUND");
    process.exit(1);
}
