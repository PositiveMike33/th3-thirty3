const fs = require('fs');
const path = require('path');
const pdf = require('pdf-parse');
const mammoth = require('mammoth');

class ContextService {
    constructor(memoryService, mcpService) {
        this.memoryService = memoryService;
        this.mcpService = mcpService;
    }

    // Helper: Recursive file search in Vault
    findFileInVault(dir, filename) {
        const files = fs.readdirSync(dir);
        for (const file of files) {
            const fullPath = path.join(dir, file);
            const stat = fs.statSync(fullPath);
            if (stat.isDirectory()) {
                const found = this.findFileInVault(fullPath, filename);
                if (found) return found;
            } else if (file.toLowerCase() === filename.toLowerCase() || file.toLowerCase() === filename.toLowerCase() + '.md') {
                return fullPath;
            }
        }
        return null;
    }

    async injectContext(message) {
        let enrichedMessage = message;
        const vaultPath = process.env.OBSIDIAN_VAULT_PATH;

        // 0. Vector Memory Search (Semantic Recall)
        if (message.length > 10) { // Only search for substantial queries
            const searchResults = await this.memoryService.search(message, 3); // Top 3 results
            if (searchResults.length > 0) {
                enrichedMessage += `\n\n[MÉMOIRE LONGUE DURÉE (Vector DB)]\n`;
                searchResults.forEach((result, index) => {
                    const dateInfo = result.created ? ` [Date: ${new Date(result.created).toLocaleDateString()}]` : '';
                    enrichedMessage += `--- SOUVENIR ${index + 1} (Source: ${result.source}${dateInfo}) ---\n${result.text}\n`;
                });
                console.log(`[MEMORY] ${searchResults.length} souvenirs retrouvés.`);
            }
        }

        // 0.5 Pieces Memory (MCP)
        if (this.mcpService && message.length > 5) {
            try {
                // Try to find a relevant tool for searching pieces
                const tools = await this.mcpService.listTools();
                const piecesSearchTool = tools.find(t => t.server === 'pieces' && (t.name.includes('search') || t.name.includes('query')));

                if (piecesSearchTool) {
                    console.log(`[MEMORY] Querying Pieces via ${piecesSearchTool.name}...`);
                    const result = await this.mcpService.callTool('pieces', piecesSearchTool.originalName, { query: message });
                    if (result && result.content && result.content.length > 0) {
                        const piecesContext = result.content.map(c => c.text).join('\n');
                        enrichedMessage += `\n\n[MÉMOIRE PIECES]\n${piecesContext}\n`;
                    }
                }
            } catch (e) {
                console.error("[MEMORY] Pieces query failed:", e.message);
            }
        }

        // 1. Obsidian [[WikiLinks]] Detection
        const wikiLinkRegex = /\[\[(.*?)\]\]/g;
        let match;
        while ((match = wikiLinkRegex.exec(message)) !== null) {
            const noteName = match[1];
            if (vaultPath && fs.existsSync(vaultPath)) {
                try {
                    const notePath = this.findFileInVault(vaultPath, noteName);
                    if (notePath) {
                        const content = fs.readFileSync(notePath, 'utf8');
                        const truncated = content.length > 20000 ? content.substring(0, 20000) + "\n...[TRUNCATED]" : content;
                        enrichedMessage += `\n\n[CONTEXTE OBSIDIAN: ${noteName}]\n\`\`\`markdown\n${truncated}\n\`\`\``;
                        console.log(`[MEMORY] Note Obsidian chargée : ${noteName}`);
                    } else {
                        console.log(`[MEMORY] Note introuvable : ${noteName}`);
                    }
                } catch (e) {
                    console.error("Erreur lecture Obsidian:", e);
                }
            }
        }

        // 2. Standard File Paths
        const words = message.split(/\s+/);
        for (const word of words) {
            const cleanWord = word.replace(/[?.,!;:]+$/, '');
            if ((cleanWord.includes('/') || cleanWord.includes('\\') || cleanWord.includes('.')) && !cleanWord.startsWith('http') && !cleanWord.includes('[')) {
                // We need to resolve paths relative to where the server is running or absolute paths
                // In index.js we used __dirname/.. as projectRoot. 
                // Since this file is in server/, __dirname is server/. 
                // So projectRoot is still path.join(__dirname, '..') if we assume relative to server dir.
                // However, usually users provide absolute paths or paths relative to CWD.

                // Let's try to resolve against CWD and Project Root
                const projectRoot = path.join(__dirname, '..');

                let possiblePaths = [
                    path.resolve(projectRoot, cleanWord),
                    path.resolve(__dirname, cleanWord),
                    path.resolve(cleanWord) // Absolute path or relative to CWD
                ];

                for (const p of possiblePaths) {
                    if (fs.existsSync(p) && fs.lstatSync(p).isFile()) {
                        try {
                            let content = "";
                            const ext = path.extname(p).toLowerCase();

                            if (ext === '.pdf') {
                                const dataBuffer = fs.readFileSync(p);
                                const data = await pdf(dataBuffer);
                                content = data.text;
                            } else if (ext === '.docx') {
                                const result = await mammoth.extractRawText({ path: p });
                                content = result.value;
                            } else {
                                // Default to text/code
                                content = fs.readFileSync(p, 'utf8');
                            }

                            const truncatedContent = content.length > 20000 ? content.substring(0, 20000) + "\n...[TRUNCATED]" : content;
                            enrichedMessage += `\n\n[CONTEXTE FICHIER LOCAL: ${cleanWord}]\n\`\`\`\n${truncatedContent}\n\`\`\``;
                            break;
                        } catch (e) {
                            console.error(`Error reading file ${p}:`, e);
                        }
                    }
                }
            }
        }
        return enrichedMessage;
    }
}

module.exports = ContextService;
