const fs = require('fs');

class StyleService {
    constructor() {
        this.commonWords = new Map();
        this.avgSentenceLength = 0;
        this.capitalizationRatio = 0;
        this.punctuationProfile = {};
    }

    /**
     * Analyzes the chat history to extract user style metrics.
     * @param {Array} history - The chat history array.
     * @returns {Object} The calculated style profile.
     */
    analyzeHistory(history) {
        // Filter for user messages only
        const userMessages = history
            .filter(msg => msg.role === 'user')
            .map(msg => msg.content || (msg.parts && msg.parts[0].text) || "")
            .filter(text => text.length > 0);

        if (userMessages.length === 0) return null;

        let totalWords = 0;
        let totalSentences = 0;
        let totalCaps = 0;
        let totalChars = 0;
        const wordCounts = {};

        userMessages.forEach(text => {
            // 1. Vocabulary Analysis
            const words = text.toLowerCase().match(/\b[\w']+\b/g) || [];
            words.forEach(w => {
                if (w.length > 3) { // Ignore small words
                    wordCounts[w] = (wordCounts[w] || 0) + 1;
                }
            });
            totalWords += words.length;

            // 2. Sentence Structure
            const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);
            totalSentences += sentences.length;

            // 3. Capitalization (Start of sentence vs lowercase)
            // Simple heuristic: check first char of message
            if (text[0] === text[0].toUpperCase() && text[0] !== text[0].toLowerCase()) {
                totalCaps++;
            }
            totalChars += text.length;
        });

        // Sort common words
        const sortedWords = Object.entries(wordCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(entry => entry[0]);

        this.avgSentenceLength = totalSentences > 0 ? Math.round(totalWords / totalSentences) : 0;
        this.capitalizationRatio = userMessages.length > 0 ? totalCaps / userMessages.length : 0;

        return {
            topWords: sortedWords,
            avgLength: this.avgSentenceLength,
            isCasual: this.capitalizationRatio < 0.5, // If < 50% start with caps, likely casual
            sampleSize: userMessages.length
        };
    }

    /**
     * Generates a system prompt instruction based on the profile.
     * @param {Object} profile - The style profile from analyzeHistory.
     * @returns {String} The system prompt fragment.
     */
    generateStylePrompt(profile) {
        if (!profile) return "";

        let prompt = `\n[MIMICRY PROTOCOL ACTIVE]\n`;
        prompt += `ANALYSE DU STYLE UTILISATEUR (${profile.sampleSize} messages):\n`;

        // Tone
        if (profile.isCasual) {
            prompt += `- TON: Décontracté, lowercase, rapide. Ne fais pas trop d'efforts sur la majuscule.\n`;
        } else {
            prompt += `- TON: Standard, structuré.\n`;
        }

        // Length
        prompt += `- LONGUEUR MOYENNE: ${profile.avgLength} mots par phrase. Essaie de matcher ce rythme.\n`;

        // Vocabulary
        if (profile.topWords.length > 0) {
            prompt += `- VOCABULAIRE FRÉQUENT: Utilise ces mots si le contexte s'y prête: ${profile.topWords.join(', ')}.\n`;
        }

        prompt += `INSTRUCTION: Imite ce style. Ne sois pas un robot. Sois le reflet de l'utilisateur.\n`;

        return prompt;
    }
}

module.exports = StyleService;
