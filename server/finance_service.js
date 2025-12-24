// LAZY LOAD: ccxt is 50MB - only load when needed
let ccxt = null;

class FinanceService {
    constructor() {
        this.kraken = null;
        this.initialize();
    }

    initialize() {
        if (process.env.KRAKEN_API_KEY && process.env.KRAKEN_PRIVATE_KEY) {
            try {
                // Lazy load ccxt only when credentials exist
                if (!ccxt) {
                    ccxt = require('ccxt');
                    console.log("[FINANCE] ccxt loaded (50MB)");
                }
                this.kraken = new ccxt.kraken({
                    apiKey: process.env.KRAKEN_API_KEY,
                    secret: process.env.KRAKEN_PRIVATE_KEY,
                });
                console.log("[FINANCE] Kraken initialized.");
            } catch (error) {
                console.error("[FINANCE] Failed to initialize Kraken:", error.message);
            }
        } else {
            console.log("[FINANCE] Kraken skipped (no credentials) - 50MB saved");
        }
    }


    async getPortfolio() {
        if (!this.kraken) return "Kraken non configuré.";

        try {
            const balance = await this.kraken.fetchBalance();
            let summary = "";

            // Filter for non-zero balances
            for (const [currency, data] of Object.entries(balance.total)) {
                if (data > 0.0001) { // Ignore dust
                    summary += `- ${currency}: ${data.toFixed(4)}\n`;
                }
            }

            if (summary === "") return "Portefeuille Kraken vide.";
            return summary;
        } catch (error) {
            console.error("[FINANCE] Error fetching portfolio:", error.message);
            return "Erreur lors de la récupération du solde Kraken.";
        }
    }

    // Raw Data for Dashboard
    async getPortfolioData() {
        if (!this.kraken) return { error: "Kraken not initialized" };
        try {
            const balance = await this.kraken.fetchBalance();
            const assets = [];
            for (const [currency, data] of Object.entries(balance.total)) {
                if (data > 0.0001) {
                    assets.push({ name: currency, value: data });
                }
            }
            return assets;
        } catch (error) {
            console.error("[FINANCE] Error fetching portfolio data:", error.message);
            return { error: error.message };
        }
    }

    async getNews() {
        try {
            const response = await fetch('https://min-api.cryptocompare.com/data/v2/news/?lang=EN');
            const data = await response.json();
            if (data.Message === 'News list successfully returned') {
                return data.Data.slice(0, 10).map(item => ({
                    id: item.id,
                    title: item.title,
                    url: item.url,
                    image: item.imageurl,
                    source: item.source_info.name,
                    published_on: item.published_on
                }));
            }
            return [];
        } catch (error) {
            console.error("[FINANCE] Error fetching news:", error);
            return { error: "Failed to fetch news" };
        }
    }

    async getTicker(symbol = 'BTC/USD') {
        if (!this.kraken) return "Kraken non configuré.";

        try {
            const ticker = await this.kraken.fetchTicker(symbol);
            return `Prix ${symbol}: ${ticker.last} (Vol: ${ticker.baseVolume.toFixed(2)})`;
        } catch (error) {
            console.error(`[FINANCE] Error fetching ticker for ${symbol}:`, error.message);
            return `Erreur prix pour ${symbol}.`;
        }
    }

    // Raw Data for Dashboard
    async getTickerData(symbol = 'BTC/USD') {
        if (!this.kraken) return null;
        try {
            const ticker = await this.kraken.fetchTicker(symbol);
            return ticker;
        } catch (error) {
            console.error(`[FINANCE] Error fetching ticker data for ${symbol}:`, error.message);
            return null;
        }
    }
}

module.exports = FinanceService;
