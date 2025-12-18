const fs = require('fs');
const path = require('path');

// Correct path: server/fabric/data/patterns (relative to this file in server/)
const FABRIC_PATH_PRIMARY = path.join(__dirname, 'fabric', 'data', 'patterns');
const FABRIC_PATH_FALLBACK_1 = path.join(__dirname, '..', 'fabric', 'data', 'patterns');
const FABRIC_PATH_FALLBACK_2 = path.join(__dirname, 'fabric-official', 'data', 'patterns');

const getPatternsDir = () => {
    // Check primary path first (server/fabric/data/patterns)
    if (fs.existsSync(FABRIC_PATH_PRIMARY)) return FABRIC_PATH_PRIMARY;
    if (fs.existsSync(FABRIC_PATH_FALLBACK_1)) return FABRIC_PATH_FALLBACK_1;
    if (fs.existsSync(FABRIC_PATH_FALLBACK_2)) return FABRIC_PATH_FALLBACK_2;
    return null;
};

const getPatterns = () => {
    const patternsDir = getPatternsDir();
    if (!patternsDir) {
        console.error("Fabric patterns directory not found.");
        return [];
    }
    try {
        const items = fs.readdirSync(patternsDir);
        // Filter only directories
        return items.filter(item => {
            const fullPath = path.join(patternsDir, item);
            return fs.statSync(fullPath).isDirectory();
        });
    } catch (error) {
        console.error("Error reading Fabric patterns:", error);
        return [];
    }
};

const getPatternContent = (patternName) => {
    const patternsDir = getPatternsDir();
    if (!patternsDir) return null;

    const patternPath = path.join(patternsDir, patternName, 'system.md');
    if (fs.existsSync(patternPath)) {
        return fs.readFileSync(patternPath, 'utf8');
    }
    return null;
};

module.exports = {
    getPatterns,
    getPatternContent
};
