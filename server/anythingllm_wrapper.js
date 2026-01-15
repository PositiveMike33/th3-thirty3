const { GoogleGenerativeAI } = require("@google/generative-ai");

// Initialize Gemini
// Ensure process.env.GEMINI_API_KEY is available (loaded by index.js or dotenv)
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// Model Configuration - STRICTLY GEMINI 3 AS REQUESTED
const MODELS = {
    fast: "gemini-3-flash-preview",
    complex: "gemini-3-pro-preview",
    image: "gemini-3-pro-image-preview", // or gemini-3-pro-preview if multimodal
    // Fallbacks (User requested ONLY Gemini 3, but keeping structural fallback to same version just in case)
    fallback_fast: "gemini-3-flash-preview",
    fallback_complex: "gemini-3-pro-preview"
};

class AnythingLLMWrapper {
    constructor() {
        if (!process.env.GEMINI_API_KEY) {
            console.error("❌ GEMINI_API_KEY is missing in environment variables!");
        }
        this.models = MODELS;
    }

    /**
     * Generate text response
     * @param {string} prompt - User input
     * @param {string} type - 'fast' | 'complex' | 'image'
     * @returns {Promise<string>}
     */
    async generateResponse(prompt, type = 'fast') {
        const modelName = this.models[type] || this.models.fast;
        try {
            const model = genAI.getGenerativeModel({ model: modelName });

            const result = await model.generateContent(prompt);
            const response = await result.response;
            return response.text();

        } catch (error) {
            console.error(`❌ Gemini Error (${modelName}):`, error.message);

            // Limit fallback logic to "not found" or "404"
            if (error.message && (error.message.includes('not found') || error.message.includes('404'))) {
                console.log("⚠️ Retrying with fallback model...");
                const fallbackName = type === 'complex' ? this.models.fallback_complex : this.models.fallback_fast;
                try {
                    const fallbackModel = genAI.getGenerativeModel({ model: fallbackName });
                    const result = await fallbackModel.generateContent(prompt);
                    return result.response.text();
                } catch (retryError) {
                    throw new Error(`Fallback failed: ${retryError.message}`);
                }
            }
            throw error;
        }
    }

    /**
     * Generate response with image input (Vision)
     * @param {string} prompt - Text prompt
     * @param {string} imageData - Base64 string
     * @param {string} mimeType - e.g. 'image/jpeg'
     */
    async generateVisionResponse(prompt, imageData, mimeType = 'image/jpeg') {
        const model = genAI.getGenerativeModel({ model: this.models.image });

        try {
            const imagePart = {
                inlineData: {
                    data: imageData,
                    mimeType: mimeType
                }
            };

            const result = await model.generateContent([prompt, imagePart]);
            return result.response.text();
        } catch (error) {
            console.error("❌ Gemini Vision Error:", error.message);
            throw error;
        }
    }

    // Health check
    async ping() {
        try {
            await this.generateResponse("Hello", "fast");
            return true;
        } catch (e) {
            return false;
        }
    }

    /**
     * Chat method for compatibility
     * @param {Array} messages - [{role, content}]
     * @param {string} type - 'fast' | 'complex'
     */
    async chat(messages, type = 'fast') {
        // Convert 'system' role to part of prompt or use systemInstruction if verified supported
        // For simplicity in wrapper, we'll concatenate for now or use chatSession if possible.
        // But the prompt pattern is simpler.
        // Let's use startChat for better context if messages > 1.

        const modelName = this.models[type] || this.models.fast;
        const model = genAI.getGenerativeModel({ model: modelName });

        // Transform messages for Gemini (user/model roles)
        // Gemini uses 'user' and 'model'. OpenAssistant/Ollama uses 'user', 'assistant', 'system'.

        let systemPrompt = '';
        const history = [];
        let lastUserMsg = '';

        for (const msg of messages) {
            if (msg.role === 'system') {
                systemPrompt += msg.content + '\n';
            } else if (msg.role === 'user') {
                if (lastUserMsg) { // If multiple user msgs in a row (rare but possible)
                    history.push({ role: 'user', parts: [{ text: lastUserMsg }] });
                }
                lastUserMsg = msg.content;
            } else if (msg.role === 'assistant') {
                if (lastUserMsg) {
                    history.push({ role: 'user', parts: [{ text: lastUserMsg }] });
                    lastUserMsg = '';
                }
                history.push({ role: 'model', parts: [{ text: msg.content }] });
            }
        }

        // If system prompt exists, pre-pend it or strict it.
        // Experimental models support systemInstruction.

        try {
            const chat = model.startChat({
                history: history,
                systemInstruction: systemPrompt ? { role: 'system', parts: [{ text: systemPrompt }] } : undefined
            });

            const result = await chat.sendMessage(lastUserMsg);
            return result.response.text();
        } catch (e) {
            // Fallback to simple generation if chat fails
            return this.generateResponse((systemPrompt ? `System: ${systemPrompt}\n\n` : '') + messages.map(m => `${m.role}: ${m.content}`).join('\n'), type);
        }
    }
}

module.exports = new AnythingLLMWrapper();
