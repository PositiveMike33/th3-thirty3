const http = require('http');
const { Client } = require("@modelcontextprotocol/sdk/client/index.js");
const { StdioClientTransport } = require("@modelcontextprotocol/sdk/client/stdio.js");
const { SSEClientTransport } = require("@modelcontextprotocol/sdk/client/sse.js");
const path = require('path');

// Custom Transport for Pieces
class PiecesClientTransport {
    constructor(url) {
        this.url = url;
        this.req = null;
        this.endpoint = null;
        this.onmessage = null;
        this.onclose = null;
        this.onerror = null;
    }

    async start() {
        return new Promise((resolve, reject) => {
            console.log(`[PiecesTransport] Starting connection to ${this.url}`);

            this.req = http.get(this.url, (res) => {
                console.log(`[PiecesTransport] Response status: ${res.statusCode}`);

                if (res.statusCode !== 200) {
                    reject(new Error(`Failed to connect: ${res.statusCode} ${res.statusMessage}`));
                    res.resume(); // Consume response to free memory
                    return;
                }

                console.log("[PiecesTransport] SSE Connected via http");

                res.on('data', (chunk) => {
                    const text = chunk.toString();
                    // console.log("[PiecesTransport] Chunk:", text);

                    const lines = text.split('\n');
                    for (const line of lines) {
                        if (line.startsWith('data: ')) {
                            const data = line.slice(6).trim();
                            this.handleData(data, resolve);
                        }
                    }
                });

                res.on('end', () => {
                    console.log("[PiecesTransport] Stream ended");
                    this.close();
                });

                res.on('error', (err) => {
                    console.error("[PiecesTransport] Stream error:", err);
                    if (this.onerror) this.onerror(err);
                });
            });

            this.req.on('error', (err) => {
                console.error("[PiecesTransport] Request error:", err);
                if (!this.endpoint) reject(err);
                if (this.onerror) this.onerror(err);
            });
        });
    }

    handleData(data, resolve) {
        // console.log("[PiecesTransport] Received data:", data);

        // Check if it's the endpoint (first message usually)
        if (!this.endpoint && (data.startsWith('/') || data.startsWith('http'))) {
            console.log("[PiecesTransport] Found endpoint:", data);
            this.endpoint = data;
            resolve();
            return;
        }

        // Otherwise it's a message
        if (this.onmessage) {
            try {
                const message = JSON.parse(data);
                this.onmessage(message);
            } catch (e) {
                // Ignore non-JSON messages
            }
        }
    }

    async send(message) {
        if (!this.endpoint) throw new Error("Not connected");

        const baseUrl = new URL(this.url);
        const postUrl = new URL(this.endpoint, baseUrl).toString();

        console.log(`[PiecesTransport] Sending message to ${postUrl}`);

        const response = await fetch(postUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(message)
        });

        if (response.ok) {
            const text = await response.text();
            // console.log("[PiecesTransport] POST Response:", text);
            if (text && text.trim().length > 0) {
                try {
                    const json = JSON.parse(text);
                    if (this.onmessage) {
                        // console.log("[PiecesTransport] Emitting POST response as message");
                        this.onmessage(json);
                    }
                } catch (e) {
                    // Ignore
                }
            }
        } else {
            console.error("[PiecesTransport] POST Failed:", response.status, response.statusText);
        }
    }

    async close() {
        if (this.req) {
            this.req.destroy();
        }
        if (this.onclose) this.onclose();
    }
}

class MCPService {
    constructor() {
        this.clients = new Map(); // Map<serverName, Client>
        this.transports = new Map(); // Map<serverName, Transport>
        this.localTools = new Map(); // Map<toolName, { definition, handler }>
    }

    /**
     * Register a local tool (JavaScript function)
     * @param {object} definition - Tool definition (name, description, inputSchema)
     * @param {function} handler - Function to execute
     */
    registerLocalTool(definition, handler) {
        this.localTools.set(definition.name, { definition, handler });
        console.log(`[MCP] Registered local tool: ${definition.name}`);
    }

    /**
     * Connect to a remote MCP server via SSE
     * @param {string} name - Unique name for this connection
     * @param {string} url - SSE Endpoint URL
     */
    async connectSSE(name, url, sessionId = null) {
        try {
            let finalUrl = url;
            if (sessionId) {
                const separator = url.includes('?') ? '&' : '?';
                finalUrl = `${url}${separator}sessionId=${sessionId}`;
            }

            console.log(`[MCP] Connecting to ${name} via SSE (${finalUrl})...`);

            // Use custom transport for Pieces
            let transport;
            if (name === 'pieces') {
                transport = new PiecesClientTransport(finalUrl);
            } else {
                // Ensure global.EventSource is set for standard SDK transport
                if (!global.EventSource) global.EventSource = require('eventsource').EventSource;
                transport = new SSEClientTransport({
                    url: new URL(finalUrl)
                });
            }

            const client = new Client({
                name: "Thirty3_Client",
                version: "1.0.0",
            }, {
                capabilities: {
                    prompts: {},
                    resources: {},
                    tools: {},
                },
            });

            await client.connect(transport);

            this.clients.set(name, client);
            this.transports.set(name, transport);

            console.log(`[MCP] Connected to ${name} successfully.`);
            return true;
        } catch (error) {
            console.error(`[MCP] Failed to connect to ${name}:`, error);
            return false;
        }
    }

    /**
     * Connect to a local MCP server via Stdio
     * @param {string} name - Unique name for this connection (e.g., "obsidian")
     * @param {string} command - Executable command (e.g., "npx", "python")
     * @param {string[]} args - Arguments for the command
     * @param {object} env - Environment variables
     */
    async connectStdio(name, command, args = [], env = {}) {
        try {
            console.log(`[MCP] Connecting to ${name} via stdio...`);

            const transport = new StdioClientTransport({
                command: command,
                args: args,
                env: { ...process.env, ...env }
            });

            const client = new Client({
                name: "Thirty3_Client",
                version: "1.0.0",
            }, {
                capabilities: {
                    prompts: {},
                    resources: {},
                    tools: {},
                },
            });

            await client.connect(transport);

            this.clients.set(name, client);
            this.transports.set(name, transport);

            console.log(`[MCP] Connected to ${name} successfully.`);
            return true;
        } catch (error) {
            console.error(`[MCP] Failed to connect to ${name}:`, error);
            return false;
        }
    }

    /**
     * List all available tools from all connected servers AND local tools
     * @returns {Promise<Array>} List of tools with server prefix
     */
    async listTools() {
        const allTools = [];

        // 1. Local Tools
        for (const [name, tool] of this.localTools.entries()) {
            allTools.push({
                ...tool.definition,
                server: 'local',
                originalName: name,
                name: `local__${name}`
            });
        }

        // 2. Remote MCP Tools
        for (const [name, client] of this.clients.entries()) {
            try {
                const result = await client.listTools();
                if (result && result.tools) {
                    // Prefix tool names with server name to avoid collisions
                    const tools = result.tools.map(tool => ({
                        ...tool,
                        server: name,
                        originalName: tool.name,
                        name: `${name}__${tool.name}` // e.g., obsidian__search_notes
                    }));
                    allTools.push(...tools);
                }
            } catch (error) {
                console.error(`[MCP] Error listing tools for ${name}:`, error);
            }
        }

        return allTools;
    }

    /**
     * Call a specific tool on a specific server
     * @param {string} serverName 
     * @param {string} toolName 
     * @param {object} args 
     */
    async callTool(serverName, toolName, args) {
        // Handle Local Tools
        if (serverName === 'local') {
            const tool = this.localTools.get(toolName);
            if (!tool) {
                throw new Error(`Local tool '${toolName}' not found.`);
            }
            try {
                return await tool.handler(args);
            } catch (error) {
                console.error(`[MCP] Error executing local tool ${toolName}:`, error);
                throw error;
            }
        }

        // Handle Remote MCP Tools
        const client = this.clients.get(serverName);
        if (!client) {
            throw new Error(`MCP Server '${serverName}' not found.`);
        }

        try {
            const result = await client.callTool({
                name: toolName,
                arguments: args
            });
            return result;
        } catch (error) {
            console.error(`[MCP] Error calling tool ${toolName} on ${serverName}:`, error);
            throw error;
        }
    }

    async disconnectAll() {
        for (const [name, client] of this.clients.entries()) {
            try {
                await client.close();
                console.log(`[MCP] Disconnected from ${name}`);
            } catch (e) {
                console.error(`[MCP] Error disconnecting ${name}:`, e);
            }
        }
        this.clients.clear();
        this.transports.clear();
    }
}

module.exports = MCPService;
