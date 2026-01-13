const express = require('express');
const router = express.Router();
const DartService = require('../dart_service');

module.exports = (dartService) => {
    // Check if service was provided
    if (!dartService) {
        throw new Error('DartService must be provided to Dart Routes');
    }

    /**
     * POST /api/dart/tasks/create
     * Create a new task in Dart AI
     */
    router.post('/tasks/create', async (req, res) => {
        try {
            const { title, description, priority, dueDate, assignee } = req.body;

            if (!title) {
                return res.status(400).json({
                    success: false,
                    error: 'Task title is required'
                });
            }

            const result = await dartService.createTask(title, {
                description,
                priority,
                dueDate,
                assignee
            });

            res.json(result);
        } catch (error) {
            console.error('[DART API] Task creation error:', error);
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    });

    /**
     * GET /api/dart/tasks
     * List all tasks from Dart AI
     */
    router.get('/tasks', async (req, res) => {
        try {
            const result = await dartService.listTasks();
            res.json(result);
        } catch (error) {
            console.error('[DART API] Task listing error:', error);
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    });

    /**
     * POST /api/dart/tasks/breakdown
     * Use AI to break down a complex task into subtasks
     */
    router.post('/tasks/breakdown', async (req, res) => {
        try {
            const { taskDescription } = req.body;

            if (!taskDescription) {
                return res.status(400).json({
                    success: false,
                    error: 'Task description is required'
                });
            }

            const result = await dartService.breakdownTask(taskDescription);
            res.json(result);
        } catch (error) {
            console.error('[DART API] Task breakdown error:', error);
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    });

    /**
     * PUT /api/dart/tasks/:taskId
     * Update an existing task
     */
    router.put('/tasks/:taskId', async (req, res) => {
        try {
            const { taskId } = req.params;
            const { status, priority, description } = req.body;

            const result = await dartService.updateTask(taskId, {
                status,
                priority,
                description
            });

            res.json(result);
        } catch (error) {
            console.error('[DART API] Task update error:', error);
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    });

    /**
     * POST /api/dart/auth/test
     * Test Dart AI authentication
     */
    router.post('/auth/test', async (req, res) => {
        try {
            await dartService.authenticate();
            res.json({
                success: true,
                message: 'Dart AI authentication successful'
            });
        } catch (error) {
            console.error('[DART API] Authentication error:', error);
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    });


    /**
     * GET /api/dart/status
     * Get current Dart AI connection status
     */
    router.get('/status', async (req, res) => {
        try {
            const authResult = await dartService.authenticate();
            res.json({
                success: true,
                connected: true,
                user: authResult,
                message: 'Dart AI connected and operational'
            });
        } catch (error) {
            res.json({
                success: false,
                connected: false,
                error: error.message
            });
        }
    });

    return router;
};

