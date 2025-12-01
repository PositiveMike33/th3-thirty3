const pythonRunner = require('./python_runner');

const webSearch = {
    name: 'web_search',
    description: 'Searches the web for a query using DuckDuckGo. Returns a list of results with titles and URLs.',
    inputSchema: {
        type: 'object',
        properties: {
            query: {
                type: 'string',
                description: 'The search query.'
            },
            max_results: {
                type: 'integer',
                description: 'Number of results to return (default 5).',
                default: 5
            }
        },
        required: ['query']
    },
    handler: async ({ query, max_results = 5 }) => {
        const pythonCode = `
from duckduckgo_search import DDGS
import json

try:
    results = DDGS().text("${query.replace(/"/g, '\\"')}", max_results=${max_results})
    print(json.dumps(results))
except Exception as e:
    print(json.dumps({"error": str(e)}))
`;
        const result = await pythonRunner.handler({ code: pythonCode });
        return result;
    }
};

module.exports = webSearch;
