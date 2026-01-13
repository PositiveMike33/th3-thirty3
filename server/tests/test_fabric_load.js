const { getPatterns, getPatternContent } = require('./fabric_service');

console.log("Testing Fabric Service...");

const patterns = getPatterns();
console.log(`Found ${patterns.length} patterns.`);

if (patterns.length > 0) {
    const firstPattern = patterns[0];
    console.log(`First pattern: ${firstPattern}`);
    const content = getPatternContent(firstPattern);
    console.log(`Content length: ${content ? content.length : 'null'}`);
    if (content) {
        console.log("Sample content:", content.substring(0, 50) + "...");
    }
} else {
    console.error("No patterns found!");
    process.exit(1);
}

console.log("Fabric Service Test Passed.");
