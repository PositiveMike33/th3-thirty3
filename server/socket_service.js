const { Server } = require('socket.io');

class SocketService {
    constructor() {
        this.io = null;
    }

    initialize(server) {
        this.io = new Server(server, {
            cors: {
                origin: "*", // Allow all origins for now (dev mode)
                methods: ["GET", "POST"]
            }
        });

        this.io.on('connection', (socket) => {
            console.log(`[SOCKET] Client connected: ${socket.id}`);

            socket.on('disconnect', () => {
                console.log(`[SOCKET] Client disconnected: ${socket.id}`);
            });
        });

        console.log("[SOCKET] Service initialized");
    }

    // --- AGENT EVENTS ---

    emitAgentStart(data) {
        if (this.io) this.io.emit('agent:start', data);
    }

    emitAgentThought(thought) {
        if (this.io) this.io.emit('agent:thought', { thought, timestamp: new Date() });
    }

    emitAgentTool(toolName, args) {
        if (this.io) this.io.emit('agent:tool', { toolName, args, timestamp: new Date() });
    }

    emitAgentEnd(response) {
        if (this.io) this.io.emit('agent:end', { response, timestamp: new Date() });
    }

    emitAgentStatus(status) {
        if (this.io) this.io.emit('agent:status', { status, timestamp: new Date() });
    }

    // --- TRAINING EVENTS ---

    emitTrainingCommentary(data) {
        if (this.io) {
            this.io.emit('training:commentary', {
                model: data.model,
                score: data.score,
                commentary: data.commentary,
                timestamp: new Date()
            });
            console.log(`[SOCKET] Training commentary emitted for ${data.model}`);
        }
    }

    emitBenchmarkComplete(data) {
        if (this.io) {
            this.io.emit('training:benchmark', {
                model: data.model,
                score: data.score,
                category: data.category,
                timestamp: new Date()
            });
            console.log(`[SOCKET] Benchmark complete emitted for ${data.model}`);
        }
    }

    emitMetricsUpdate(data) {
        if (this.io) {
            this.io.emit('metrics:update', {
                model: data.model,
                category: data.category,
                improvement: data.improvement,
                timestamp: new Date()
            });
        }
    }

    // Generic log emission
    emitLog(type, message) {
        if (this.io) {
            this.io.emit('log', { type, message, timestamp: new Date() });
        }
    }

    // --- PROJECT EVENTS ---
    emitProjectUpdate(action, project) {
        if (this.io) this.io.emit('project:update', { action, project, timestamp: new Date() });
    }

    emitTaskUpdate(action, task) {
        if (this.io) this.io.emit('task:update', { action, task, timestamp: new Date() });
    }

    // --- PAYMENT EVENTS ---
    emitTransaction(transaction) {
        if (this.io) this.io.emit('payment:transaction', { transaction, timestamp: new Date() });
    }
}

module.exports = SocketService;
