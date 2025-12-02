const webSearch = require('./tools/web_search');

async function testSearch() {
    console.log("Testing Web Search Tool directly...");
    try {
        const result = await webSearch.handler({ query: "current price of bitcoin", max_results: 3 });
        console.log("Result Type:", typeof result);
        console.log("Result Length:", result.length);
        console.log("Raw Result Preview:", result.substring(0, 100) + "...");

        try {
            const parsed = JSON.parse(result);
            console.log("\nParsed Results:");
            if (Array.isArray(parsed)) {
                parsed.forEach((r, i) => {
                    console.log(`[${i + 1}] ${r.title}`);
                    console.log(`    ${r.href}`);
                });
            } else {
                console.log("Parsed result is not an array:", parsed);
            }
        } catch (e) {
            console.error("JSON Parse Error:", e.message);
            console.log("Full Raw Result:", result);
        }
    } catch (error) {
        console.error("Test Failed:", error);
    }
}

testSearch();
