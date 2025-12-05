const fs = require('fs');
const path = require('path');
const TIERS = require('./config/tiers');

const USERS_FILE = path.join(__dirname, 'data', 'users.json');

class UserService {
    constructor() {
        this.users = [];
        this.loadUsers();
    }

    loadUsers() {
        try {
            if (fs.existsSync(USERS_FILE)) {
                const data = fs.readFileSync(USERS_FILE, 'utf8');
                this.users = JSON.parse(data).users;
                console.log(`[USER] Loaded ${this.users.length} users.`);
            } else {
                console.warn("[USER] users.json not found. Creating default.");
                this.users = [];
                // Create file logic could go here, but we assume it exists from setup
            }
        } catch (error) {
            console.error("[USER] Failed to load users:", error);
        }
    }

    validateKey(apiKey) {
        const user = this.users.find(u => u.key === apiKey);
        if (!user) return null;

        const tierConfig = TIERS[user.tier];
        if (!tierConfig) {
            console.error(`[USER] Unknown tier '${user.tier}' for user ${user.username}`);
            return null;
        }

        return {
            ...user,
            tierConfig
        };
    }

    canUseModel(user, provider, modelName) {
        const allowedModels = user.tierConfig.models;

        if (allowedModels.includes('all')) return true;

        // Local
        if (provider === 'local' || provider === 'lmstudio') {
            return allowedModels.includes('local');
        }

        // Cloud Standard (GPT-4o-mini)
        if (modelName.includes('flash') || modelName.includes('mini')) {
            return allowedModels.includes('cloud_standard');
        }

        // Cloud Elite (Pro, GPT-4o, Claude)
        if (modelName.includes('pro') || modelName.includes('gpt-4o') || modelName.includes('sonnet')) {
            return allowedModels.includes('cloud_elite');
        }

        // Agents (AnythingLLM)
        if (provider === 'anythingllm') {
            return allowedModels.includes('agents');
        }

        return false;
    }

    canUseTool(user, toolName) {
        const allowedTools = user.tierConfig.tools;
        if (allowedTools.includes('all')) return true;

        // Check exact match or category match
        // e.g. 'osint_sherlock' might be covered by 'osint_basic' or 'osint_full'

        if (toolName.startsWith('osint')) {
            if (allowedTools.includes('osint_full')) return true;
            if (allowedTools.includes('osint_basic') && (toolName.includes('sherlock') || toolName.includes('check'))) return true;
            return false;
        }

        if (toolName.startsWith('finance')) {
            return allowedTools.includes('finance_dashboard');
        }

        if (toolName.startsWith('fabric')) {
            if (allowedTools.includes('fabric_expert')) return true;
            if (allowedTools.includes('fabric_basic') && !toolName.includes('create')) return true; // Basic can't create
            return false;
        }

        return allowedTools.includes(toolName);
    }
}

module.exports = new UserService();
