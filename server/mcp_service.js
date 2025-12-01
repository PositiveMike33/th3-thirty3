const { Client } = require("@modelcontextprotocol/sdk/client/index.js");
const { StdioClientTransport } = require("@modelcontextprotocol/sdk/client/stdio.js");
const path = require('path');

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
