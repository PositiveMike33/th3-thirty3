const http = require('http');

class PiecesService {
    constructor() {
        this.baseUrl = 'http://localhost:39300'; // Default Pieces OS port
        this.isConnected = false;
    }

    setHost(host) {
        this.baseUrl = host || 'http://localhost:39300';
    }

    async healthCheck() {
        try {
            const response = await fetch(`${this.baseUrl}/health`);
            if (response.ok) {
                this.isConnected = true;
                console.log("[PIECES] Connected to Pieces OS.");
                return true;
            }
        } catch (error) {
            console.warn("[PIECES] Connection failed:", error.message);
        }
        this.isConnected = false;
        return false;
    }

    async search(query) {
        if (!this.isConnected) return [];

        try {
            // Pieces /search/assets endpoint
            // Note: The API might vary, using a generic search approach for now
            // We'll try to find relevant assets based on the query.
            
            // First, we need to ensure we are connected.
            // For now, we will simulate a search or use a known endpoint if available.
            // Pieces usually exposes /assets/search or similar.
            
            // Let's try a simple asset list and filter for now as a fallback, 
            // but ideally we use the search endpoint.
            
            const url = `${this.baseUrl}/assets/search?query=${encodeURIComponent(query)}`;
            // Note: If the specific search endpoint differs, we might need to adjust.
            // Checking Pieces OS documentation (simulated): /search/assets is common.
            
            // Alternative: POST /search
            const response = await fetch(`${this.baseUrl}/search`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    query: query,
                    mode: 'snippet' 
                })
            });

            if (!response.ok) return [];

            const results = await response.json();
            // Map results to a simplified format
            // Assuming results.iterable is the list
            const items = results.iterable || [];
            
            return items.slice(0, 3).map(item => ({
                id: item.id,
                name: item.name,
                content: item.original?.reference?.fragment?.string?.raw || "No content"
            }));

        } catch (error) {
            console.error("[PIECES] Search error:", error.message);
            return [];
        }
    }

    async getAsset(assetId) {
        if (!this.isConnected) return null;
        try {
            const response = await fetch(`${this.baseUrl}/asset/${assetId}`);
            if (!response.ok) return null;
            return await response.json();
        } catch (error) {
            console.error("[PIECES] Get Asset error:", error.message);
            return null;
        }
    }
}

module.exports = PiecesService;
