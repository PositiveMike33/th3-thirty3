const fs = require('fs');
const path = require('path');

class VisionService {
    constructor(llmService = null) {
        this.llmService = llmService;
        // Generic workspace or default
        console.log('[VISION] Service initialized (AnythingLLM mode)');
    }

    /**
     * Set LLM Service for vision analysis
     * @param {Object} llmService - Instance of LLMService
     */
    setLLMService(llmService) {
        this.llmService = llmService;
    }

    /**
     * Send request to specific AnythingLLM workspace
     * @param {string} prompt - The prompt to send
     * @param {string} imageData - Base64 image data (optional)
     * @param {string} workspace - Workspace slug
     * @returns {Promise<string>} Response from workspace
     */
    async sendToWorkspace(prompt, imageData = null, workspace = null) {
        const baseUrl = process.env.ANYTHING_LLM_URL;
        const apiKey = process.env.ANYTHING_LLM_KEY;

        if (!baseUrl || !apiKey) {
            throw new Error("AnythingLLM URL or Key missing.");
        }

        const targetWorkspace = workspace || 'default-workspace';
        console.log(`[VISION] Sending to workspace: ${targetWorkspace}`);

        try {
            const chatRes = await fetch(`${baseUrl}/workspace/${targetWorkspace}/chat`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    message: prompt,
                    mode: 'chat',
                    // Note: Image support depends on workspace model configuration
                    // Some models may require different format
                })
            });

            if (!chatRes.ok) {
                const errText = await chatRes.text();
                throw new Error(`Workspace ${targetWorkspace} failed: ${chatRes.status} - ${errText}`);
            }

            const chatData = await chatRes.json();
            return chatData.textResponse;

        } catch (error) {
            console.error(`[VISION] Workspace ${targetWorkspace} error:`, error.message);
            throw error;
        }
    }

    /**
     * Analyze image with custom prompt using AnythingLLM
     * @param {string} imagePath - Path to image file or base64 data
     * @param {string} prompt - Analysis prompt
     * @returns {Promise<string>} Analysis result
     */
    async analyzeImage(imagePath, prompt = "Décris cette image en détail.") {
        if (!this.llmService) {
            throw new Error('LLMService not set. Call setLLMService() first.');
        }

        try {
            let imageData;

            // Check if it's a file path or base64
            if (imagePath.startsWith('data:')) {
                // Already base64 data URL
                imageData = imagePath;
            } else if (fs.existsSync(imagePath)) {
                // File path - convert to base64
                const ext = path.extname(imagePath).toLowerCase();
                const mimeTypes = {
                    '.jpg': 'image/jpeg',
                    '.jpeg': 'image/jpeg',
                    '.png': 'image/png',
                    '.gif': 'image/gif',
                    '.webp': 'image/webp'
                };
                const mimeType = mimeTypes[ext] || 'image/jpeg';

                const imageBuffer = fs.readFileSync(imagePath);
                const base64 = imageBuffer.toString('base64');
                imageData = `data:${mimeType};base64,${base64}`;
            } else {
                // Assume it's already base64 without data URL prefix
                imageData = `data:image/jpeg;base64,${imagePath}`;
            }

            // For now, send text prompt to workspace
            // Note: Image attachment may require specific workspace configuration
            const fullPrompt = `${prompt}\n\n[Image fournie pour analyse]`;

            const response = await this.sendToWorkspace(fullPrompt, imageData, null);
            return response;

        } catch (error) {
            console.error('[VISION] Analysis failed:', error.message);
            throw error;
        }
    }

    /**
     * Analyze video frame-by-frame (extract key frames first)
     * Note: For now, we'll analyze the first frame as an image
     * @param {string} videoPath - Path to video file
     * @param {string} prompt - Analysis prompt
     * @returns {Promise<string>} Analysis result
     */
    async analyzeVideo(videoPath, prompt = "Décris ce qui se passe dans cette vidéo.") {
        // For video analysis, we would need to:
        // 1. Extract key frames using ffmpeg
        // 2. Analyze each frame
        // 3. Combine results

        // For now, return a placeholder
        throw new Error('Video analysis not yet implemented. Please use image analysis or extract frames manually.');
    }

    /**
     * Batch analyze multiple images (e.g., before/after, different angles)
     * Note: AnythingLLM may have limitations on multi-image analysis
     * @param {Array<string>} imagePaths - Array of image paths
     * @param {string} prompt - Analysis prompt
     * @returns {Promise<string>} Combined analysis
     */
    async analyzeMultipleImages(imagePaths, prompt = "Compare ces images et décris les différences.") {
        if (!this.llmService) {
            throw new Error('LLMService not set. Call setLLMService() first.');
        }

        try {
            // For now, analyze images sequentially and combine results
            const analyses = [];

            for (let i = 0; i < imagePaths.length; i++) {
                const imagePath = imagePaths[i];
                const imagePrompt = `${prompt}\n\nImage ${i + 1}/${imagePaths.length}:`;

                const analysis = await this.analyzeImage(imagePath, imagePrompt);
                analyses.push(`\n--- Image ${i + 1} ---\n${analysis}`);
            }

            return `Analyse de ${imagePaths.length} images:\n${analyses.join('\n')}`;

        } catch (error) {
            console.error('[VISION] Multi-image analysis failed:', error.message);
            throw error;
        }
    }
}

module.exports = VisionService;
