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
}

module.exports = SocketService;
