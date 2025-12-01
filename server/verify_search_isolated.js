const webSearch = require('./tools/web_search');

async function testSearch() {
    console.log("Testing Web Search Tool directly...");
    try {
        const result = await webSearch.handler({ query: "current price of bitcoin", max_results: 3 });
        console.log("Raw Result:", result);

        try {
            const parsed = JSON.parse(result);
            console.log("\nParsed Results:");
            parsed.forEach((r, i) => {
                console.log(`[${i + 1}] ${r.title}\n    ${r.href}`);
            });
        } catch (e) {
            console.log("Result is not JSON (might be error message):", result);
        }
    } catch (error) {
        console.error("Test Failed:", error);
    }
}

testSearch();
