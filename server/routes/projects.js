const express = require('express');
const router = express.Router();
const ProjectService = require('../project_service');
const projectService = new ProjectService();
const { authMiddleware } = require('../middleware/auth');

// GET /api/projects
router.get('/', authMiddleware, async (req, res) => {
    try {
        const projects = await projectService.getProjects();
        res.json(projects);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST /api/projects
router.post('/', authMiddleware, async (req, res) => {
    try {
        const { title, description } = req.body;
        if (!title) return res.status(400).json({ error: "Title is required" });

        const project = await projectService.createProject(title, description, req.user ? req.user._id : null);
        res.json(project);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// GET /api/projects/:id
router.get('/:id', authMiddleware, async (req, res) => {
    try {
        const project = await projectService.getProject(req.params.id);
        if (!project) return res.status(404).json({ error: "Project not found" });
        res.json(project);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// POST /api/projects/:id/tasks
router.post('/:id/tasks', authMiddleware, async (req, res) => {
    try {
        const { content, status } = req.body;
        if (!content) return res.status(400).json({ error: "Content is required" });

        const task = await projectService.addTask(req.params.id, content, status);
        if (!task) return res.status(404).json({ error: "Project not found" });

        res.json(task);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
