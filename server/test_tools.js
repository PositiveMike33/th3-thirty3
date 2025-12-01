const LLMService = require('./llm_service');
const MCPService = require('./mcp_service');
const pythonRunner = require('./tools/python_runner');
const webSearch = require('./tools/web_search');
require('dotenv').config();

async function testTools() {
    console.log("Testing Agentic Tools...");

    // Setup Services
    const mcpService = new MCPService();
    mcpService.registerLocalTool(pythonRunner, pythonRunner.handler);
    mcpService.registerLocalTool(webSearch, webSearch.handler);

    const llmService = new LLMService();
    llmService.setMCPService(mcpService);

    // Test 1: Python Calculation
    console.log("\n--- TEST 1: Python Calculation ---");
    const prompt1 = "Calculate the 10th Fibonacci number using Python.";
    const response1 = await llmService.generateResponse(prompt1, null, 'gemini', 'gemini-1.5-flash', "You are a helpful assistant.");
    console.log("Response:", response1);

    // Test 2: Web Search
    console.log("\n--- TEST 2: Web Search ---");
    const prompt2 = "Search for 'current price of Bitcoin' and tell me the result.";
    const response2 = await llmService.generateResponse(prompt2, null, 'gemini', 'gemini-1.5-flash', "You are a helpful assistant.");
    console.log("Response:", response2);
}

testTools();
