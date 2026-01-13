const mongoose = require('mongoose');

const ProjectSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String },
    status: { type: String, enum: ['active', 'archived', 'completed'], default: 'active' },
    ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    metrics: {
        progress: { type: Number, default: 0 },
        cost: { type: Number, default: 0 },
        deadline: Date
    },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Project', ProjectSchema);
