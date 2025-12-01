const webSearch = require('./tools/web_search');

async function findDartUrl() {
    console.log("Searching for Dart Project Management URL...");
    try {
        const result = await webSearch.handler({ query: "ItsDart API documentation developer", max_results: 3 });
        console.log("Results:", result);
    } catch (error) {
        console.error("Search Failed:", error);
    }
}

findDartUrl();
