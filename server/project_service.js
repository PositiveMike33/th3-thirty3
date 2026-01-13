const Project = require('./models/Project');
const Task = require('./models/Task');

class ProjectService {
    constructor(socketService) {
        this.socketService = socketService;
        console.log('[PROJECT] Service initialized (MongoDB Mode)');
    }

    // --- Project Management ---

    async getProjects() {
        try {
            // Populate tasks for backward compatibility if needed, 
            // but usually fetching projects list suffices.
            return await Project.find().sort({ createdAt: -1 });
        } catch (error) {
            console.error("[PROJECT] Error fetching projects:", error);
            return [];
        }
    }

    async createProject(name, description, ownerId = null) {
        try {
            const projectData = {
                title: name,
                description
            };
            if (ownerId) projectData.ownerId = ownerId;
            const project = new Project(projectData);
            await project.save();
            if (this.socketService) this.socketService.emitProjectUpdate('create', project);
            return project;
        } catch (error) {
            console.error("[PROJECT] Error creating project:", error);
            throw error;
        }
    }

    async getProject(id) {
        try {
            const project = await Project.findById(id);
            if (!project) return null;

            // Fetch tasks separately
            const tasks = await Task.find({ projectId: id }).sort({ createdAt: 1 });
            return { ...project.toObject(), tasks };
        } catch (error) {
            console.error("[PROJECT] Error getting project:", error);
            return null;
        }
    }

    async updateProject(id, updates) {
        try {
            const project = await Project.findByIdAndUpdate(id, updates, { new: true });
            return project;
        } catch (error) {
            console.error("[PROJECT] Error updating project:", error);
            return null;
        }
    }

    async deleteProject(id) {
        try {
            await Project.findByIdAndDelete(id);
            await Task.deleteMany({ projectId: id });
            return true;
        } catch (error) {
            console.error("[PROJECT] Error deleting project:", error);
            return false;
        }
    }

    // --- Task Management ---

    async addTask(projectId, content, status = 'todo') {
        try {
            const task = new Task({
                projectId,
                content,
                status
            });
            await task.save();
            if (this.socketService) this.socketService.emitTaskUpdate('create', task);
            return task;
        } catch (error) {
            console.error("[PROJECT] Error adding task:", error);
            return null;
        }
    }

    async updateTask(projectId, taskId, updates) {
        try {
            // projectId param ignored in mongoose update usually, but good for validation if strict
            const task = await Task.findOneAndUpdate(
                { _id: taskId, projectId },
                updates,
                { new: true }
            );
            return task;
        } catch (error) {
            console.error("[PROJECT] Error updating task:", error);
            return null;
        }
    }

    async deleteTask(projectId, taskId) {
        try {
            const result = await Task.findOneAndDelete({ _id: taskId, projectId });
            return !!result;
        } catch (error) {
            console.error("[PROJECT] Error deleting task:", error);
            return false;
        }
    }
}

module.exports = ProjectService;
