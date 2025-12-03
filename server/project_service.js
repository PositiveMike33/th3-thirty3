const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const DATA_DIR = path.join(__dirname, 'data');
const PROJECTS_FILE = path.join(DATA_DIR, 'projects.json');

class ProjectService {
    constructor() {
        this.ensureDataDir();
    }

    ensureDataDir() {
        if (!fs.existsSync(DATA_DIR)) {
            fs.mkdirSync(DATA_DIR, { recursive: true });
        }
        if (!fs.existsSync(PROJECTS_FILE)) {
            fs.writeFileSync(PROJECTS_FILE, JSON.stringify([], null, 2));
        }
    }

    getProjects() {
        try {
            const data = fs.readFileSync(PROJECTS_FILE, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            console.error("Error reading projects:", error);
            return [];
        }
    }

    saveProjects(projects) {
        try {
            fs.writeFileSync(PROJECTS_FILE, JSON.stringify(projects, null, 2));
            return true;
        } catch (error) {
            console.error("Error saving projects:", error);
            return false;
        }
    }

    createProject(name, description) {
        const projects = this.getProjects();
        const newProject = {
            id: uuidv4(),
            name,
            description,
            status: 'active', // active, archived
            createdAt: new Date().toISOString(),
            tasks: []
        };
        projects.push(newProject);
        this.saveProjects(projects);
        return newProject;
    }

    getProject(id) {
        const projects = this.getProjects();
        return projects.find(p => p.id === id);
    }

    updateProject(id, updates) {
        const projects = this.getProjects();
        const index = projects.findIndex(p => p.id === id);
        if (index !== -1) {
            projects[index] = { ...projects[index], ...updates };
            this.saveProjects(projects);
            return projects[index];
        }
        return null;
    }

    deleteProject(id) {
        let projects = this.getProjects();
        const initialLength = projects.length;
        projects = projects.filter(p => p.id !== id);
        if (projects.length < initialLength) {
            this.saveProjects(projects);
            return true;
        }
        return false;
    }

    // --- Task Management ---

    addTask(projectId, content, status = 'todo') {
        const projects = this.getProjects();
        const project = projects.find(p => p.id === projectId);
        if (project) {
            const newTask = {
                id: uuidv4(),
                content,
                status, // todo, in-progress, done
                createdAt: new Date().toISOString()
            };
            project.tasks.push(newTask);
            this.saveProjects(projects);
            return newTask;
        }
        return null;
    }

    updateTask(projectId, taskId, updates) {
        const projects = this.getProjects();
        const project = projects.find(p => p.id === projectId);
        if (project) {
            const taskIndex = project.tasks.findIndex(t => t.id === taskId);
            if (taskIndex !== -1) {
                project.tasks[taskIndex] = { ...project.tasks[taskIndex], ...updates };
                this.saveProjects(projects);
                return project.tasks[taskIndex];
            }
        }
        return null;
    }

    deleteTask(projectId, taskId) {
        const projects = this.getProjects();
        const project = projects.find(p => p.id === projectId);
        if (project) {
            const initialLength = project.tasks.length;
            project.tasks = project.tasks.filter(t => t.id !== taskId);
            if (project.tasks.length < initialLength) {
                this.saveProjects(projects);
                return true;
            }
        }
        return false;
    }
}

module.exports = ProjectService;
