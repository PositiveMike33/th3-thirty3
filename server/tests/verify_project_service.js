require('dotenv').config();
const mongoose = require('mongoose');
const ProjectService = require('./project_service');

const runTest = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('✅ DB Connected');

        const service = new ProjectService();
        const timestamp = Date.now();

        // 1. Create Project
        const project = await service.createProject(`Test Project ${timestamp}`, 'Automated Test');
        if (!project || !project._id) throw new Error('Project creation failed');
        console.log(`✅ Project Created: ${project._id}`);

        // 2. Add Task
        const task = await service.addTask(project._id, 'Test Task', 'todo');
        if (!task || !task._id) throw new Error('Task creation failed');
        console.log(`✅ Task Added: ${task._id}`);

        // 3. Verify Persistence
        const fetched = await service.getProject(project._id);
        if (!fetched || fetched.tasks.length !== 1) throw new Error('Fetch verification failed');
        console.log('✅ Verification Passed');

        // Cleanup
        await service.deleteProject(project._id);
        console.log('✅ Cleanup Done');

        process.exit(0);
    } catch (error) {
        console.error('❌ Test Failed:', error.message || error);
        if (error.reason) console.error('Reason:', error.reason);
        process.exit(1);
    }
};

runTest();
