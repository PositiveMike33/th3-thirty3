const http = require('http');
const crypto = require('crypto');

const PIECES_URL = 'http://localhost:39300/model_context_protocol/2024-11-05/sse';
const SESSION_ID = crypto.randomUUID();
const FULL_URL = `${PIECES_URL}?sessionId=${SESSION_ID}`;

console.log(`[TEST] Verifying Pieces MCP Connection...`);
console.log(`[TEST] URL: ${FULL_URL}`);

const req = http.get(FULL_URL, (res) => {
    console.log(`[TEST] Response Status: ${res.statusCode}`);

    if (res.statusCode === 200) {
        console.log("[TEST] Connection Successful (200 OK)");

        res.on('data', (chunk) => {
            const text = chunk.toString();
            if (text.includes('endpoint')) {
                console.log("[TEST] Received 'endpoint' event. Protocol valid.");
                process.exit(0);
            } else if (text.includes('message') && text.includes('http')) {
                console.log("[TEST] Received 'message' event with URL. Protocol valid (Pieces Custom).");
                process.exit(0);
            }
        });

        // Timeout if no data received
        setTimeout(() => {
            console.error("[TEST] Timeout waiting for initial event.");
            process.exit(1);
        }, 5000);

    } else {
        console.error(`[TEST] Failed with status ${res.statusCode}`);
        process.exit(1);
    }
});

req.on('error', (e) => {
    console.error(`[TEST] Connection Error: ${e.message}`);
    process.exit(1);
});
