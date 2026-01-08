const { getPatterns, getPatternContent } = require('./server/fabric_service');

console.log("Testing Fabric Service...");
const patterns = getPatterns();
console.log(`Found ${patterns.length} patterns.`);
if (patterns.length > 0) {
    console.log("First 5 patterns:", patterns.slice(0, 5));
    const firstPattern = patterns[0];
    const content = getPatternContent(firstPattern);
    console.log(`Content for ${firstPattern} length:`, content ? content.length : 'NULL');
} else {
    console.error("No patterns found!");
}
