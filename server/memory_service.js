const lancedb = require('vectordb');
const { Ollama } = require('ollama');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class MemoryService {
    constructor() {
        this.ollama = new Ollama(); // Default host: http://127.0.0.1:11434
        this.db = null;
        this.table = null;
        this.tableName = 'memory_store';
        this.embedModel = 'nomic-embed-text';
    }

    async initialize() {
        try {
            // Initialize DB in a local folder
            const dbPath = path.join(__dirname, 'data', 'lancedb');
            if (!fs.existsSync(dbPath)) {
                fs.mkdirSync(dbPath, { recursive: true });
            }

            this.db = await lancedb.connect(dbPath);

            // Check if table exists
            try {
                this.table = await this.db.openTable(this.tableName);
                console.log(`[MEMORY] Table '${this.tableName}' opened.`);
            } catch (e) {
                console.log(`[MEMORY] Table '${this.tableName}' not found. It will be created on first ingestion.`);
            }
        } catch (error) {
            console.error("[MEMORY] Initialization failed:", error);
        }
    }

    async getEmbedding(text) {
        try {
            const response = await this.ollama.embeddings({
                model: this.embedModel,
                prompt: text,
            });
            return response.embedding;
        } catch (error) {
            console.error("[MEMORY] Embedding generation failed:", error);
            return null;
        }
    }

    async addDocument(text, metadata = {}) {
        const embedding = await this.getEmbedding(text);
        if (!embedding) return false;

        const record = {
            id: crypto.randomUUID(),
            vector: embedding,
            text: text,
            source: metadata.source || 'unknown',
            timestamp: Date.now(),
            ...metadata
        };

        if (!this.table) {
            // Create table with the first record
            this.table = await this.db.createTable(this.tableName, [record]);
            console.log(`[MEMORY] Table '${this.tableName}' created.`);
        } else {
            await this.table.add([record]);
        }
        return true;
    }

    async addCorrection(originalQuery, wrongResponse, correction) {
        const text = `[CORRECTION UTILISATEUR]\nQuestion: "${originalQuery}"\nMauvaise réponse: "${wrongResponse}"\nCORRECTION: "${correction}"\n[FIN CORRECTION]`;
        return await this.addDocument(text, {
            source: 'user_feedback',
            type: 'correction',
            created: new Date().toISOString(),
            modified: new Date().toISOString()
        });
    }

    async addChatExchange(userMsg, agentMsg) {
        // Format for retrieval: "User asked: ... Agent replied: ..."
        // This helps the LLM understand the flow when retrieved later.
        const text = `[HISTORIQUE CHAT]\nUser: ${userMsg}\nAgent: ${agentMsg}`;
        return await this.addDocument(text, {
            source: 'chat_history',
            type: 'conversation',
            created: new Date().toISOString(),
            modified: new Date().toISOString()
        });
    }

    async search(query, limit = 5) {
        if (!this.table) {
            console.warn("[MEMORY] No memory table found. Search skipped.");
            return [];
        }

        const queryEmbedding = await this.getEmbedding(query);
        if (!queryEmbedding) return [];

        try {
            const results = await this.table.search(queryEmbedding)
                .limit(limit)
                .execute();

            return results.map(r => ({
                text: r.text,
                source: r.source,
                created: r.created,
                modified: r.modified,
                score: r._distance // LanceDB returns distance (lower is better)
            }));
        } catch (error) {
            console.error("[MEMORY] Search failed:", error);
            return [];
        }
    }

    // Smart Chunking: Split by headers and paragraphs
    chunkText(text, maxChunkSize = 1000) {
        const chunks = [];
        // Split by H1 or H2 headers
        const sections = text.split(/^#+\s/gm);

        for (const section of sections) {
            if (!section.trim()) continue;

            if (section.length > maxChunkSize) {
                // If section is too big, split by paragraphs
                const paragraphs = section.split(/\n\n+/);
                let currentChunk = "";

                for (const para of paragraphs) {
                    if ((currentChunk.length + para.length) > maxChunkSize) {
                        if (currentChunk) chunks.push(currentChunk.trim());
                        currentChunk = para;
                    } else {
                        currentChunk += "\n\n" + para;
                    }
                }
                if (currentChunk) chunks.push(currentChunk.trim());
            } else {
                chunks.push(section.trim());
            }
        }
        return chunks;
    }

    async ingestVault(vaultPath) {
        console.log(`[MEMORY] Starting ingestion of vault: ${vaultPath}`);
        let count = 0;
        const fsPromises = require('fs').promises;

        const processFile = async (filePath) => {
            try {
                const content = await fsPromises.readFile(filePath, 'utf8');
                // Skip small files
                if (content.length < 50) return;

                const relativePath = path.relative(vaultPath, filePath);
                const stat = await fsPromises.stat(filePath);

                // Deduplication: Remove old chunks for this file
                if (this.table) {
                    // Future implementation: Delete old chunks before adding new ones
                    // await this.table.delete(`source = '${relativePath}'`); 
                }

                const chunks = this.chunkText(content);

                for (const chunk of chunks) {
                    await this.addDocument(chunk, {
                        source: relativePath,
                        type: 'obsidian_note',
                        created: stat.birthtime.toISOString(),
                        modified: stat.mtime.toISOString()
                    });
                }
                process.stdout.write('.');
                count++;
            } catch (err) {
                console.error(`[MEMORY] Error processing file ${filePath}:`, err.message);
            }
        };

        const walkDir = async (dir) => {
            const files = await fsPromises.readdir(dir);
            for (const file of files) {
                const fullPath = path.join(dir, file);
                const stat = await fsPromises.stat(fullPath);
                if (stat.isDirectory()) {
                    if (file.startsWith('.')) continue; // Skip hidden dirs
                    await walkDir(fullPath);
                } else if (file.endsWith('.md')) {
                    await processFile(fullPath);
                }
            }
        };

        if (fs.existsSync(vaultPath)) {
            await walkDir(vaultPath);
            console.log(`\n[MEMORY] Ingestion complete. Processed ${count} files.`);
            return count;
        } else {
            console.error(`[MEMORY] Vault path not found: ${vaultPath}`);
            return 0;
        }
    }
}

module.exports = MemoryService;
