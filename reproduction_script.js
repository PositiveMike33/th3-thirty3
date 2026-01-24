const { getPatterns, getPatternContent } = require('./server/fabric_service');
const fs = require('fs');
const path = require('path');

// Mock getPatternsDir to verify internal logic if needed, but getPatterns uses it internally.
// We'll trust getPatterns() finds the right dir as it worked before.

console.log("Analyzing patterns...");
const patterns = getPatterns();
console.log(`Found ${patterns.length} patterns.`);

const report = {
    missing_system: [],
    has_user: [],
    large_files: [],
    suspicious_names: [],
    all_names: patterns
};

patterns.forEach(p => {
    // Check name
    if (!/^[a-zA-Z0-9_-]+$/.test(p)) {
        report.suspicious_names.push(p);
    }

    // Check content via service
    const content = getPatternContent(p);
    if (!content) {
        report.missing_system.push(p);
    } else {
        // content is now { system, user }
        if (content.system && content.system.length > 50000) {
            report.large_files.push({ name: p, size: content.system.length, type: 'system' });
        }
        if (content.user) {
            report.has_user.push(p);
        }
    }

    // Check manual path for user.md (since service doesn't support it yet)
    // We need to know WHERE the patterns are.
    // Hack: use the same logic as service to find dir
    // We already know getPatterns worked, so let's rely on finding one pattern to guess the root.
    // Wait, I can't easily guess the root without exporting getPatternsDir.
    // But I can try the paths manually.
});

console.log("Analysis Complete.");
console.log("Suspicious Names:", report.suspicious_names);
console.log("Missing System:", report.missing_system.length);
console.log("Large Files (>50KB):", report.large_files);

fs.writeFileSync('patterns_report.json', JSON.stringify(report, null, 2));
console.log("Report saved to patterns_report.json");
