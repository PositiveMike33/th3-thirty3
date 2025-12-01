const fs = require('fs');
const path = require('path');

const FABRIC_PATH_1 = path.join(__dirname, 'fabric', 'patterns');
const FABRIC_PATH_2 = path.join(__dirname, 'fabric', 'data', 'patterns'); // Some versions might have it here?
const FABRIC_PATH_3 = path.join(__dirname, 'fabric', 'server', 'patterns'); // Just in case

const getPatternsDir = () => {
    // Check data/patterns first as that seems to be the correct location in this clone
    if (fs.existsSync(FABRIC_PATH_2)) return FABRIC_PATH_2;
    if (fs.existsSync(FABRIC_PATH_1)) return FABRIC_PATH_1;
    if (fs.existsSync(FABRIC_PATH_3)) return FABRIC_PATH_3;
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
