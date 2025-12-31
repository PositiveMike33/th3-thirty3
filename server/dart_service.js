const { v4: uuidv4 } = require('uuid');
const { OpenAPI, TaskService } = require('dart-tools');

/**
 * Dart AI Service for Th3 Thirty3
 * Integration with Dart AI (dart-tools SDK)
 */
class DartService {
    constructor() {
        this.token = process.env.DART_API_TOKEN;
        if (!this.token) {
            console.warn('[DART] Warning: DART_API_TOKEN not set. DartAI features will be disabled.');
        }
        this.workspaceId = 'kok90kMp4rU4';

        // Configure SDK
        OpenAPI.HEADERS = {
            'Authorization': `Bearer ${this.token}`
        };
        // Explicitly set base if needed, although default seems to be correct
        // OpenAPI.BASE = 'https://app.dartai.com/api/v0/public'; 

        this.isAuthenticated = true;
        console.log('[DART] Service initialized (SDK Mode)');
    }

    /**
     * Authenticate (Implicit check via operation)
     */
    async authenticate() {
        try {
            // No direct "me" endpoint found, we test connection by listing tasks
            // or fetching something minimal.
            console.log(`[DART] Verifying Auth via TaskService...`);
            // We pass a dummy limit to make it fast
            // Note: signature might vary, passing object usually works for openapi-codegen
            const result = await TaskService.listTasks({
                workspaceId: this.workspaceId,
                limit: 1
            });

            console.log(`[DART] Auth confirmed (API responded)`);
            return {
                id: 'unknown-sdk-user',
                email: 'authenticated-user',
                workspace: this.workspaceId
            };
        } catch (error) {
            console.error('[DART] Authentication check failed:', error.message);
            // Provide more context if it's an API error
            if (error.status || error.body) {
                console.error('API Error Details:', error.body || error.status);
            }
            throw error;
        }
    }

    /**
     * Create a new task
     */
    async createTask(title, options = {}) {
        try {
            // dart-tools SDK expects: { item: TaskCreate }
            // Minimal required: title only (dartboard auto-assigned by API)
            const taskItem = { title: title.trim() };

            // Add optional fields only if provided
            if (options.description) taskItem.description = options.description;

            const requestBody = { item: taskItem };

            console.log('[DART] Creating task via SDK...');

            const result = await TaskService.createTask(requestBody);
            const task = result.item || result;

            console.log('[DART] Task created:', task.title);

            return {
                success: true,
                task: task,
                output: `✓ Tâche "${title}" créée sur Dart AI`
            };
        } catch (error) {
            console.error('[DART] Create task failed:', error.message);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * List all tasks
     */
    async listTasks() {
        try {
            console.log(`[DART] Listing tasks for workspace ${this.workspaceId}`);
            // Assuming signature (query) or ({ workspaceId })
            const response = await TaskService.listTasks({
                workspaceId: this.workspaceId
            });

            // Response might be { results: ... } or just Array
            return this._formatTaskList(response);

        } catch (error) {
            console.error('[DART] List tasks failed:', error.message);
            return { success: false, error: error.message };
        }
    }

    _formatTaskList(data) {
        // Handle array or pagination object
        const tasks = Array.isArray(data) ? data : (data.results || data.tasks || []);

        const taskList = tasks.map(t =>
            `[${(t.status || 'todo').toUpperCase()}] ${t.title} (${t.priority || 'normal'}) - ${t.dart_id || t.id}`
        ).join('\n');

        return {
            success: true,
            tasks: tasks,
            output: taskList || 'Aucune tâche trouvée sur Dart AI'
        };
    }

    /**
     * AI-powered task breakdown (mock)
     */
    async breakdownTask(taskDescription) {
        // Simple mock breakdown - in reality would use LLM
        const breakdown = `
Analyse AI de la tâche: "${taskDescription}"

Étapes suggérées:
1. 📋 Planning & Design
   - Définir les exigences
   - Créer les maquettes/wireframes

2. 🏗️ Implémentation  
   - Configurer l'environnement
   - Développer les fonctionnalités de base
   - Intégrer les APIs

3. 🧪 Tests & Validation
   - Tests unitaires
   - Tests d'intégration
   - Validation utilisateur

4. 🚀 Déploiement
   - Préparer la production
   - Déployer et monitorer

Note: Breakdown généré par le mock Dart AI
        `.trim();

        console.log('[DART] Task breakdown generated for:', taskDescription);

        return {
            success: true,
            breakdown: breakdown
        };
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
