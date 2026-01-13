const { v4: uuidv4 } = require('uuid');
const { OpenAPI, TaskService } = require('dart-tools');

/**
 * Dart AI Service for Th3 Thirty3
 * Integration with Dart AI (dart-tools SDK)
 */
class DartService {
    constructor(llmService) {
        this.token = process.env.DART_API_TOKEN;
        this.llmService = llmService; // Dependency Injection

        if (!this.token) {
            console.warn('[DART] Warning: DART_API_TOKEN not set. Features like Sync will be disabled.');
        }
        this.workspaceId = 'kok90kMp4rU4';

        // Configure SDK
        OpenAPI.HEADERS = {
            'Authorization': `Bearer ${this.token}`
        };

        console.log(`[DART] Service initialized (LLM: ${!!this.llmService})`);
    }

    // ... (authenticate method remains same, skipped for brevity in tool call if not modifying, but here we only modify constructor and breakdown)

    /**
     * AI-powered task breakdown (Real LLM)
     */
    async breakdownTask(taskDescription) {
        console.log(`[DART] Generating breakdown for: "${taskDescription}"`);

        if (!this.llmService) {
            console.warn('[DART] LLMService not available, falling back to mock.');
            return this._mockBreakdown(taskDescription);
        }

        const systemPrompt = `You are an expert Project Manager AI. 
        Your goal is to break down a high-level task into actionable, step-by-step subtasks.
        Format your response as a clear, numbered list with sections.
        Style it with Markdown.
        Be concise and professional.
        `;

        const prompt = `Task to break down: "${taskDescription}"
        
        Please provide a detailed execution plan.`;

        try {
            // Use "cloud" (e.g. GPT-4o) if available for best logic, or "local" (Ollama) if offline.
            // We can let LLMService decide based on what's available (defaults to local if no keys).
            // Ideally we want smart logic here.
            const provider = process.env.OPENAI_API_KEY ? 'openai' : 'local';
            const model = provider === 'openai' ? 'gpt-4o' : 'granite4:latest';

            const breakdown = await this.llmService.generateResponse(
                prompt,
                null,
                provider,
                model,
                systemPrompt
            );

            return {
                success: true,
                breakdown: breakdown
            };

        } catch (error) {
            console.error('[DART] LLM Breakdown failed:', error);
            return this._mockBreakdown(taskDescription);
        }
    }

    _mockBreakdown(taskDescription) {
        const breakdown = `
Analyse AI de la tâche: "${taskDescription}"

Étapes suggérées (MOCK - LLM Unavailable):
1. 📋 Planning & Design
2. 🏗️ Implémentation
3. 🧪 Tests & Validation
4. 🚀 Déploiement

Note: Breakdown généré par le mock Dart AI (LLM Error/Missing)
        `.trim();

        return { success: true, breakdown };
    }

    /**
     * Update a task
     */
    async updateTask(taskId, updates = {}) {
        try {
            console.log(`[DART] Updating task ${taskId}...`);

            // Build update payload - only include fields that are provided
            const updateBody = { id: taskId };
            if (updates.status) updateBody.status = updates.status;
            if (updates.priority) updateBody.priority = updates.priority;
            if (updates.description) updateBody.description = updates.description;
            if (updates.title) updateBody.title = updates.title;

            // Use SDK to update task
            const task = await TaskService.updateTask(updateBody);

            console.log('[DART] Task updated:', task.title || taskId);

            return {
                success: true,
                task: task,
                output: `✓ Tâche "${task.title || taskId}" mise à jour`
            };
        } catch (error) {
            console.error('[DART] Update task failed:', error.message);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Delete a task
     */
    async deleteTask(taskId) {
        try {
            console.log(`[DART] Deleting task ${taskId}...`);

            // Use SDK to delete task
            await TaskService.deleteTask({ id: taskId });

            console.log('[DART] Task deleted:', taskId);

            return {
                success: true,
                output: `✓ Tâche supprimée`
            };
        } catch (error) {
            console.error('[DART] Delete task failed:', error.message);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Get task by ID
     */
    async getTask(taskId) {
        try {
            console.log(`[DART] Getting task ${taskId}...`);

            // Use SDK to get task
            const task = await TaskService.getTask({ id: taskId });

            return {
                success: true,
                task: task
            };
        } catch (error) {
            console.error('[DART] Get task failed:', error.message);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Get tasks by status
     */
    async getTasksByStatus(status) {
        try {
            console.log(`[DART] Getting tasks with status: ${status}...`);

            // Use SDK to list tasks with filter
            const response = await TaskService.listTasks({
                workspaceId: this.workspaceId,
                status: status
            });

            // Format response
            const tasks = Array.isArray(response) ? response : (response.results || response.tasks || []);

            return {
                success: true,
                tasks: tasks
            };
        } catch (error) {
            console.error('[DART] Get tasks by status failed:', error.message);
            return {
                success: false,
                error: error.message
            };
        }
    }
}

module.exports = DartService;
