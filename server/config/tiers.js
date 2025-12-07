const TIERS = {
    initiate: {
        rank: 1,
        name: "Initiate",
        models: ['local'], // Only Ollama
        tools: ['web_search'],
        features: [],
        rate_limit: 50 // requests per hour
    },
    netrunner: {
        rank: 2,
        name: "Netrunner",
        models: ['local', 'cloud_standard'], // + Gemini Flash, GPT-4o-mini
        tools: ['web_search', 'fabric_basic', 'google_personal'],
        features: ['rag_memory'],
        rate_limit: 200
    },
    operator: {
        rank: 3,
        name: "Operator",
        models: ['local', 'cloud_standard', 'cloud_elite', 'agents'], // + Pro, GPT-4o, Claude, AnythingLLM
        tools: ['web_search', 'fabric_expert', 'google_personal', 'osint_basic', 'finance_dashboard'],
        features: ['rag_memory', 'priority_support'],
        rate_limit: 1000
    },
    shadow: {
        rank: 4,
        name: "Shadow",
        models: ['all'],
        tools: ['all', 'osint_full'], // + SpiderFoot, Maltego
        features: ['rag_memory', 'priority_support', 'dedicated_server'],
        rate_limit: 5000
    },
    architect: {
        rank: 99,
        name: "Architect",
        models: ['all'],
        tools: ['all'],
        features: ['all', 'debug_mode', 'admin_panel'],
        rate_limit: Infinity
    }
};

module.exports = TIERS;
